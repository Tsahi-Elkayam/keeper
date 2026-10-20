using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keeper.Common;

/// <summary>JSON Lines: one JSON object per line, UTF-8 without BOM. Readers accept a BOM.</summary>
public static class JsonLines
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        // Non-Latin text stays readable; this output is data, never HTML.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    public static IEnumerable<JsonObject> Read(string file)
    {
        using var reader = new StreamReader(file, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
        var number = 0;
        while (reader.ReadLine() is { } line)
        {
            number++;
            if (line.Length == 0)
                continue;

            JsonNode? node;
            try
            {
                node = JsonNode.Parse(line);
            }
            catch (JsonException ex)
            {
                throw new FormatException($"{file}:{number}: not valid JSON: {ex.Message}");
            }
            yield return node as JsonObject ?? throw new FormatException($"{file}:{number}: each line must be a JSON object.");
        }
    }

    public static IEnumerable<T> Read<T>(string file) =>
        Read(file).Select(o => o.Deserialize<T>(Options) ?? throw new FormatException($"{file}: empty record."));
}

/// <summary>Appends records to a JSON Lines file. Not thread-safe; one writer per file.</summary>
public sealed class JsonLinesWriter : IDisposable
{
    private readonly StreamWriter _writer;

    public JsonLinesWriter(string file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        _writer = new StreamWriter(file, append: false, new UTF8Encoding(false)) { NewLine = "\n" };
        File = file;
    }

    public string File { get; }

    public int Count { get; private set; }

    public void Write<T>(T record)
    {
        _writer.WriteLine(JsonSerializer.Serialize(record, JsonLines.Options));
        Count++;
    }

    public void Dispose() => _writer.Dispose();
}
