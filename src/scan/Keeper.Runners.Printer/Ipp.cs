using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Runners.Printer;

/// <summary>
/// The one IPP operation Keeper uses: Get-Printer-Attributes, which only asks a printer about itself. There is no
/// way to build a request that prints, creates, changes or cancels anything. A response that is cut off, too large,
/// too deeply nested or whose lengths overrun it is a format error, never a half-read answer.
/// </summary>
public static class Ipp
{
    public const int MaxBytes = 1_000_000;
    private const int MaxAttributes = 500;
    private const int MaxValues = 200;
    private const int MaxDepth = 16;

    private const byte EndOfAttributes = 0x03;
    private const byte PrinterAttributesGroup = 0x04;

    public sealed record Response(int StatusCode, IReadOnlyDictionary<string, JsonNode?> Attributes)
    {
        /// <summary>successful-ok and its two "ok, but" variants.</summary>
        public bool Successful => StatusCode < 0x0100;
    }

    public static byte[] GetPrinterAttributesRequest(string printerUri)
    {
        var bytes = new List<byte> { 0x01, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x01 };
        Attribute(bytes, 0x47, "attributes-charset", "utf-8");
        Attribute(bytes, 0x48, "attributes-natural-language", "en");
        Attribute(bytes, 0x45, "printer-uri", printerUri);
        Attribute(bytes, 0x44, "requested-attributes", "all");
        bytes.Add(EndOfAttributes);
        return [.. bytes];
    }

    private static void Attribute(List<byte> bytes, byte tag, string name, string value)
    {
        bytes.Add(tag);
        bytes.AddRange(Length(Encoding.UTF8.GetByteCount(name)));
        bytes.AddRange(Encoding.UTF8.GetBytes(name));
        bytes.AddRange(Length(Encoding.UTF8.GetByteCount(value)));
        bytes.AddRange(Encoding.UTF8.GetBytes(value));
    }

    private static byte[] Length(int length) => [(byte)(length >> 8), (byte)length];

    public static Response Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxBytes)
            throw new FormatException("the IPP answer is larger than it should be");
        if (data.Length < 8)
            throw new FormatException("the IPP answer is too short");
        var status = BinaryPrimitives.ReadUInt16BigEndian(data[2..4]);
        var position = 8;
        var attributes = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        var inPrinterGroup = false;
        var seenPrinterGroup = false;
        string? current = null;

        while (true)
        {
            if (position >= data.Length)
                throw new FormatException("the IPP answer ends before its end-of-attributes tag");
            var tag = data[position++];
            if (tag == EndOfAttributes)
                break;
            if (tag <= 0x05)
            {
                inPrinterGroup = tag == PrinterAttributesGroup && !seenPrinterGroup;
                seenPrinterGroup |= tag == PrinterAttributesGroup;
                current = null;
                continue;
            }

            var name = Encoding.UTF8.GetString(Take(data, ref position, ReadLength(data, ref position)));
            var value = Take(data, ref position, ReadLength(data, ref position));
            if (tag == 0x34)
            {
                SkipCollection(data, ref position);
                value = "<collection>"u8;
            }

            if (!inPrinterGroup)
                continue;
            if (name.Length > 0)
            {
                if (attributes.Count >= MaxAttributes)
                    throw new FormatException("the IPP answer has too many attributes");
                current = name;
                attributes[name] = Decode(tag, value);
            }
            else
            {
                // An additional value of the attribute before it.
                if (current is null)
                    throw new FormatException("an IPP value belongs to no attribute");
                Append(attributes, current, Decode(tag, value));
            }
        }
        return new Response(status, attributes);
    }

    private static int ReadLength(ReadOnlySpan<byte> data, ref int position)
    {
        if (position + 2 > data.Length)
            throw new FormatException("the IPP answer ends inside an attribute");
        var length = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, 2));
        position += 2;
        return length;
    }

    private static ReadOnlySpan<byte> Take(ReadOnlySpan<byte> data, ref int position, int length)
    {
        if (position + length > data.Length)
            throw new FormatException("an IPP length runs past the end of the answer");
        var slice = data.Slice(position, length);
        position += length;
        return slice;
    }

    private static void SkipCollection(ReadOnlySpan<byte> data, ref int position)
    {
        var depth = 1;
        while (depth > 0)
        {
            if (position >= data.Length)
                throw new FormatException("the IPP answer ends inside a collection");
            var tag = data[position++];
            Take(data, ref position, ReadLength(data, ref position));
            Take(data, ref position, ReadLength(data, ref position));
            if (tag == 0x34 && ++depth > MaxDepth)
                throw new FormatException("an IPP collection is nested too deeply");
            if (tag == 0x37)
                depth--;
        }
    }

    private static void Append(Dictionary<string, JsonNode?> attributes, string name, JsonNode? value)
    {
        if (attributes[name] is JsonArray list)
        {
            if (list.Count >= MaxValues)
                throw new FormatException("an IPP attribute has too many values");
            list.Add(value);
        }
        else
        {
            attributes[name] = new JsonArray(attributes[name], value);
        }
    }

    private static JsonNode? Decode(byte tag, ReadOnlySpan<byte> value)
    {
        switch (tag)
        {
            case 0x10 or 0x12 or 0x13:
                return null;
            case 0x21 or 0x23:
                return value.Length == 4 ? JsonValue.Create((long)BinaryPrimitives.ReadInt32BigEndian(value)) : JsonValue.Create(Convert.ToHexString(value));
            case 0x22:
                return value.Length == 1 ? JsonValue.Create(value[0] != 0) : null;
            case 0x31 when value.Length == 11:
                var year = BinaryPrimitives.ReadUInt16BigEndian(value[..2]);
                var offset = TimeSpan.FromMinutes((value[9] * 60 + value[10]) * (value[8] == (byte)'-' ? -1 : 1));
                try
                {
                    return JsonValue.Create(new DateTimeOffset(year, value[2], value[3], value[4], value[5], value[6], offset).ToUniversalTime()
                        .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
                }
                catch (ArgumentOutOfRangeException)
                {
                    return JsonValue.Create(Convert.ToHexString(value));
                }
            case 0x32 when value.Length == 9:
                return JsonValue.Create($"{BinaryPrimitives.ReadInt32BigEndian(value[..4])}x{BinaryPrimitives.ReadInt32BigEndian(value[4..8])} {(value[8] == 3 ? "dpi" : "dpcm")}");
            case 0x33 when value.Length == 8:
                return JsonValue.Create($"{BinaryPrimitives.ReadInt32BigEndian(value[..4])}-{BinaryPrimitives.ReadInt32BigEndian(value[4..8])}");
            case 0x35 or 0x36:
                // language (length + text) then the text (length + text): the text is what matters.
                if (value.Length >= 4)
                {
                    var languageLength = BinaryPrimitives.ReadUInt16BigEndian(value[..2]);
                    var textAt = 2 + languageLength;
                    if (textAt + 2 <= value.Length)
                    {
                        var textLength = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(textAt, 2));
                        if (textAt + 2 + textLength <= value.Length)
                            return JsonValue.Create(Encoding.UTF8.GetString(value.Slice(textAt + 2, textLength)));
                    }
                }
                return JsonValue.Create(Convert.ToHexString(value));
            case 0x30:
                return JsonValue.Create(Convert.ToHexString(value));
            case >= 0x40:
                return JsonValue.Create(Encoding.UTF8.GetString(value));
            default:
                return JsonValue.Create(Convert.ToHexString(value));
        }
    }
}
