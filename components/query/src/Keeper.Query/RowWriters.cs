using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Keeper.Query;

/// <summary>One JSON object per row, UTF-8, for the next stage of a pipeline.</summary>
public sealed class JsonLinesRowWriter : IRowWriter, IDisposable
{
    private readonly Stream _output;
    private readonly Utf8JsonWriter _json;
    private IReadOnlyList<string> _names = [];

    public JsonLinesRowWriter(Stream output)
    {
        _output = output;
        // Relaxed escaping keeps non-Latin text readable; this output is data, never HTML.
        _json = new Utf8JsonWriter(output, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    public void Columns(IReadOnlyList<string> names) => _names = names;

    public void Row(IReadOnlyList<object?> values)
    {
        _json.Reset();
        _json.WriteStartObject();
        for (var i = 0; i < _names.Count; i++)
        {
            _json.WritePropertyName(_names[i]);
            switch (values[i])
            {
                case null: _json.WriteNullValue(); break;
                case long number: _json.WriteNumberValue(number); break;
                case double number: _json.WriteNumberValue(number); break;
                case byte[] bytes: _json.WriteBase64StringValue(bytes); break;
                default: _json.WriteStringValue(Convert.ToString(values[i], CultureInfo.InvariantCulture)); break;
            }
        }
        _json.WriteEndObject();
        _json.Flush();
        _output.WriteByte((byte)'\n');
    }

    public void Complete() => _output.Flush();

    public void Dispose() => _json.Dispose();
}

/// <summary>Aligned columns for a person to read. Long cells are cut at 60 characters.</summary>
public sealed class TableWriter(TextWriter output) : IRowWriter
{
    private const int MaxCell = 60;
    private readonly List<string[]> _rows = [];
    private IReadOnlyList<string> _names = [];

    public void Columns(IReadOnlyList<string> names) => _names = names;

    public void Row(IReadOnlyList<object?> values) => _rows.Add(values.Select(Cell).ToArray());

    public void Complete()
    {
        var widths = _names.Select((name, i) => Math.Max(name.Length, _rows.Count == 0 ? 0 : _rows.Max(r => r[i].Length))).ToArray();
        output.WriteLine(Line([.. _names], widths));
        output.WriteLine(string.Join("  ", widths.Select(w => new string('-', w))));
        foreach (var row in _rows)
            output.WriteLine(Line(row, widths));
        output.WriteLine($"({_rows.Count} rows)");
    }

    private static string Line(string[] cells, int[] widths) =>
        string.Join("  ", cells.Select((cell, i) => cell.PadRight(widths[i]))).TrimEnd();

    private static string Cell(object? value)
    {
        var text = (Convert.ToString(value, CultureInfo.InvariantCulture) ?? "").ReplaceLineEndings(" ");
        return text.Length > MaxCell ? text[..(MaxCell - 3)] + "..." : text;
    }
}
