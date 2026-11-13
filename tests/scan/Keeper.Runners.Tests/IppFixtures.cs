using System.Text;

namespace Keeper.Runners.Tests;

/// <summary>Builds IPP responses byte by byte, the way a printer would, for the codec and the fake printer.</summary>
internal sealed class IppResponseBuilder
{
    private readonly List<byte> _bytes = [];

    public IppResponseBuilder(int status = 0)
    {
        _bytes.AddRange([0x01, 0x01, (byte)(status >> 8), (byte)status, 0, 0, 0, 1]);
        _bytes.Add(0x01);
        Text(0x47, "attributes-charset", "utf-8");
        Text(0x48, "attributes-natural-language", "en");
    }

    public IppResponseBuilder PrinterGroup()
    {
        _bytes.Add(0x04);
        return this;
    }

    private void Header(byte tag, string name)
    {
        _bytes.Add(tag);
        _bytes.AddRange([(byte)(name.Length >> 8), (byte)name.Length]);
        _bytes.AddRange(Encoding.UTF8.GetBytes(name));
    }

    private void Value(byte[] value)
    {
        _bytes.AddRange([(byte)(value.Length >> 8), (byte)value.Length]);
        _bytes.AddRange(value);
    }

    public IppResponseBuilder Text(byte tag, string name, string value)
    {
        Header(tag, name);
        Value(Encoding.UTF8.GetBytes(value));
        return this;
    }

    public IppResponseBuilder Keyword(string name, params string[] values)
    {
        Header(0x44, name);
        Value(Encoding.UTF8.GetBytes(values[0]));
        foreach (var more in values.Skip(1))
        {
            Header(0x44, "");
            Value(Encoding.UTF8.GetBytes(more));
        }
        return this;
    }

    public IppResponseBuilder Integer(string name, params int[] values)
    {
        Header(0x21, name);
        Value(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(values[0])));
        foreach (var more in values.Skip(1))
        {
            Header(0x21, "");
            Value(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(more)));
        }
        return this;
    }

    public IppResponseBuilder Enum(string name, int value)
    {
        Header(0x23, name);
        Value(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(value)));
        return this;
    }

    public IppResponseBuilder Boolean(string name, bool value)
    {
        Header(0x22, name);
        Value([(byte)(value ? 1 : 0)]);
        return this;
    }

    public IppResponseBuilder Uri(string name, params string[] values)
    {
        Header(0x45, name);
        Value(Encoding.UTF8.GetBytes(values[0]));
        foreach (var more in values.Skip(1))
        {
            Header(0x45, "");
            Value(Encoding.UTF8.GetBytes(more));
        }
        return this;
    }

    /// <summary>A collection attribute with one text member, and a nested collection inside it.</summary>
    public IppResponseBuilder Collection(string name)
    {
        Header(0x34, name);
        Value([]);
        Header(0x4A, "");
        Value(Encoding.UTF8.GetBytes("media-size"));
        Header(0x34, "");
        Value([]);
        Header(0x4A, "");
        Value(Encoding.UTF8.GetBytes("x-dimension"));
        Header(0x21, "");
        Value(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(21590)));
        Header(0x37, "");
        Value([]);
        Header(0x37, "");
        Value([]);
        return this;
    }

    public IppResponseBuilder NoValue(string name)
    {
        Header(0x13, name);
        Value([]);
        return this;
    }

    public byte[] Build()
    {
        var all = _bytes.ToList();
        all.Add(0x03);
        return [.. all];
    }

    /// <summary>The same bytes without the end tag and cut short, as a dropped connection leaves them.</summary>
    public byte[] BuildTruncated() => [.. _bytes.Take(_bytes.Count - 3)];
}
