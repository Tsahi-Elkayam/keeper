using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Gpo;

/// <summary>
/// The files a Group Policy object keeps in SYSVOL, read as rows: Registry.pol (administrative templates),
/// GptTmpl.inf (security settings), audit.csv (advanced audit policy) and GPT.INI (versions). Pure parsing:
/// the runner reads the bytes.
/// </summary>
public static class GpoFiles
{
    private const uint PolSignature = 0x67655250;   // "PReg"

    /// <summary>
    /// Registry.pol: "PReg", version 1, then [key;value;type;size;data] entries in UTF-16. Values named
    /// **del.x, **delvals. and the like are instructions (delete x, delete all values), kept as rows with
    /// action set. Null when the file is not a Registry.pol.
    /// </summary>
    public static List<JsonObject>? RegistryPol(byte[] bytes)
    {
        if (bytes.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(bytes) != PolSignature || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)) != 1)
            return null;
        var rows = new List<JsonObject>();
        var at = 8;
        while (at < bytes.Length)
        {
            if (!Expect(bytes, ref at, '['))
                return null;
            var key = Text(bytes, ref at);
            if (key is null || !Expect(bytes, ref at, ';'))
                return null;
            var value = Text(bytes, ref at);
            if (value is null || !Expect(bytes, ref at, ';') || at + 4 > bytes.Length)
                return null;
            var type = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
            at += 4;
            if (!Expect(bytes, ref at, ';') || at + 4 > bytes.Length)
                return null;
            var size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
            at += 4;
            if (!Expect(bytes, ref at, ';') || size > bytes.Length - at)
                return null;
            var data = bytes.AsSpan(at, (int)size).ToArray();
            at += (int)size;
            if (!Expect(bytes, ref at, ']'))
                return null;

            // A text or binary value under a name like DefaultPassword is never kept: "set" says one is there.
            var masked = type is not (4 or 5 or 11) && data.Length > 0 && SecretProperties.LooksSecret(value.TrimStart('*'));
            var row = new JsonObject { ["key"] = key, ["value"] = value, ["type"] = TypeName(type), ["data"] = masked ? FieldPath.MaskedValue : Data(type, data) };
            if (value.StartsWith("**", StringComparison.Ordinal))
            {
                // **del.Name: delete Name; **delvals.: delete every value; **DeleteValues / **DeleteKeys: lists.
                var instruction = value[2..];
                var dot = instruction.IndexOf('.', StringComparison.Ordinal);
                row["action"] = (dot < 0 ? instruction : instruction[..dot]).ToLowerInvariant();
                row["value"] = dot < 0 ? "" : instruction[(dot + 1)..];
            }
            rows.Add(row);
        }
        return rows;
    }

    private static bool Expect(byte[] bytes, ref int at, char c)
    {
        if (at + 2 > bytes.Length || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(at)) != c)
            return false;
        at += 2;
        return true;
    }

    /// <summary>A null-terminated UTF-16 string.</summary>
    private static string? Text(byte[] bytes, ref int at)
    {
        for (var end = at; end + 2 <= bytes.Length; end += 2)
        {
            if (BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(end)) != 0)
                continue;
            var text = Encoding.Unicode.GetString(bytes, at, end - at);
            at = end + 2;
            return text;
        }
        return null;
    }

    private static string TypeName(uint type) => type switch
    {
        0 => "none", 1 => "sz", 2 => "expand-sz", 3 => "binary", 4 => "dword", 5 => "dword-big-endian", 7 => "multi-sz", 11 => "qword",
        _ => type.ToString(CultureInfo.InvariantCulture),
    };

    private static JsonNode? Data(uint type, byte[] data) => type switch
    {
        1 or 2 => Encoding.Unicode.GetString(data).TrimEnd('\0'),
        4 when data.Length >= 4 => BinaryPrimitives.ReadUInt32LittleEndian(data),
        5 when data.Length >= 4 => BinaryPrimitives.ReadUInt32BigEndian(data),
        11 when data.Length >= 8 => BinaryPrimitives.ReadUInt64LittleEndian(data),
        7 => new JsonArray([.. Encoding.Unicode.GetString(data).Split('\0', StringSplitOptions.RemoveEmptyEntries).Select(s => (JsonNode?)s)]),
        _ => Convert.ToHexStringLower(data),
    };

    /// <summary>
    /// GptTmpl.inf, an INI file: one row per setting - section, key, value; a list (privilege rights, group
    /// members) also as values, with SIDs written *S-1-... given without the star.
    /// </summary>
    public static List<JsonObject> SecurityTemplate(string text)
    {
        var rows = new List<JsonObject>();
        string? section = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim().TrimStart('﻿');
            if (line.Length == 0 || line.StartsWith(';'))
                continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (section is null || equals <= 0 || section is "Unicode" or "Version")
                continue;
            var key = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            var row = new JsonObject { ["section"] = section, ["key"] = key, ["value"] = value };
            if (section is "Privilege Rights" || section == "Group Membership")
                row["values"] = new JsonArray([.. value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                    .Select(v => (JsonNode?)v.TrimStart('*'))]);
            if (section == "Registry Values" && value.IndexOf(',', StringComparison.Ordinal) is var comma and > 0)
            {
                // MACHINE\...\Name=4,1: the type, then the value. Text under a secret's name (Winlogon's
                // DefaultPassword) is never kept.
                var type = value[..comma];
                var name = key[(key.LastIndexOf('\\') + 1)..];
                var secret = type is not ("4" or "11") && SecretProperties.LooksSecret(name);
                row["type"] = type;
                row["data"] = secret ? FieldPath.MaskedValue : value[(comma + 1)..].Trim('"');
                if (secret)
                    row["value"] = $"{type},{FieldPath.MaskedValue}";
            }
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>audit.csv (advanced audit policy): one row per subcategory with its inclusion setting and value.</summary>
    public static List<JsonObject> AuditPolicy(string text)
    {
        var rows = new List<JsonObject>();
        var lines = text.Split('\n').Select(l => l.Trim().TrimStart('﻿')).Where(l => l.Length > 0).ToList();
        if (lines.Count == 0)
            return rows;
        var header = lines[0].Split(',').Select(h => h.Trim()).ToList();
        foreach (var line in lines.Skip(1))
        {
            var cells = line.Split(',');
            var row = new JsonObject();
            for (var i = 0; i < header.Count && i < cells.Length; i++)
                row[header[i]] = cells[i].Trim();
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>GPT.INI: the version, split into its machine (low word) and user (high word) halves.</summary>
    public static JsonObject Gpt(string text)
    {
        var row = new JsonObject();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
                continue;
            var key = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            row[key] = value;
            if (key.Equals("Version", StringComparison.OrdinalIgnoreCase) && uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            {
                row["machineVersion"] = version & 0xFFFF;
                row["userVersion"] = version >> 16;
            }
        }
        return row;
    }
}
