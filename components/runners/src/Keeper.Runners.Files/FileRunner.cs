using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using Keeper.Common;
using Keeper.Rules;

namespace Keeper.Runners.Files;

/// <summary>
/// file: reads a report another tool wrote (PingCastle, Maester, ScubaGear, Prowler, a CSV export) from the
/// Keeper home's imports\ folder. The newest file matching the pattern wins. XML is parsed with DTDs and
/// external entities disabled; paths cannot leave imports\ and links are not followed.
/// </summary>
public sealed class FileRunner : IRunner
{
    public const long MaxBytes = 200L * 1024 * 1024;
    private const int MaxDepth = 6;

    public string Protocol => "file";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        var path = query.Text("path");
        if (string.IsNullOrWhiteSpace(path))
            yield return "path is required (relative to the Keeper home's imports folder)";
        else if (Path.IsPathRooted(path) || path.Replace('\\', '/').Split('/').Any(s => s is ".." or "."))
            yield return "path must be relative to the imports folder, without . or ..";
        else if (Path.GetDirectoryName(path)?.Contains('*') == true)
            yield return "wildcards are allowed in the file name only";

        var format = query.Text("format") ?? "json";
        if (format is not ("json" or "xml" or "csv"))
            yield return "format must be json, xml or csv";
        if (format == "xml" && string.IsNullOrWhiteSpace(query.Text("items")))
            yield return "xml needs items: an XPath selecting one element per row";
        if (query.Text("delimiter") is { Length: not 1 })
            yield return "delimiter must be one character";
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var relative = query.Text("path")!.Replace('\\', '/');
        var folderPart = Path.GetDirectoryName(relative) ?? "";
        var pattern = Path.GetFileName(relative);

        string folder;
        try
        {
            folder = folderPart.Length == 0 ? context.ImportsDir : PathGuard.Resolve(context.ImportsDir, folderPart);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Task.FromResult(RunnerResult.Failed(ex.Message));
        }
        if (!Directory.Exists(folder))
            return Task.FromResult(RunnerResult.Failed($"no folder imports/{folderPart}: put the tool's report there"));

        var file = Directory.GetFiles(folder, pattern)
            .Select(f => new FileInfo(f))
            .Where(f => f.LinkTarget is null)
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .FirstOrDefault();
        if (file is null)
            return Task.FromResult(RunnerResult.Failed($"no file matches imports/{relative}"));
        if (file.Length > MaxBytes)
            return Task.FromResult(RunnerResult.Failed($"{file.Name} is larger than {MaxBytes / (1024 * 1024)} MB"));

        try
        {
            var rows = (query.Text("format") ?? "json") switch
            {
                "xml" => Xml(file.FullName, query.Text("items")!),
                "csv" => Csv(file.FullName, (query.Text("delimiter") ?? ",")[0]),
                _ => Json(file.FullName, query.Text("items")),
            };
            foreach (var row in rows)
            {
                SecretProperties.Mask(row);   // JSON rows are masked already; XML and CSV columns too
                row["_file"] = file.Name;
                row["_modified"] = RowValues.Iso(file.LastWriteTimeUtc);
            }
            context.Log($"{file.Name}: {rows.Count} rows");
            return Task.FromResult(RunnerResult.Ok(rows));
        }
        catch (Exception ex) when (ex is JsonException or XmlException or FormatException or System.Xml.XPath.XPathException)
        {
            return Task.FromResult(RunnerResult.Failed($"{file.Name} could not be read: {ex.Message}"));
        }
    }

    private static List<JsonObject> Json(string path, string? items)
    {
        var body = JsonNode.Parse(File.ReadAllText(path), documentOptions: new JsonDocumentOptions { MaxDepth = 64, CommentHandling = JsonCommentHandling.Skip });
        return RowValues.ItemsOf(body, items).ToList();
    }

    private static List<JsonObject> Xml(string path, string xpath)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = MaxBytes,
        };
        using var reader = XmlReader.Create(path, settings);
        var document = new XmlDocument { XmlResolver = null };
        document.Load(reader);

        var rows = new List<JsonObject>();
        foreach (var element in document.SelectNodes(xpath)?.OfType<XmlElement>() ?? [])
            rows.Add(ElementToJson(element, 0));
        return rows;
    }

    private static JsonObject ElementToJson(XmlElement element, int depth)
    {
        var row = new JsonObject();
        foreach (XmlAttribute attribute in element.Attributes)
            row[attribute.LocalName] = attribute.Value;

        foreach (var group in element.ChildNodes.OfType<XmlElement>().GroupBy(e => e.LocalName))
        {
            var values = group.Select(child =>
                    child.HasChildNodes && child.ChildNodes.OfType<XmlElement>().Any() && depth < MaxDepth
                        ? (JsonNode)ElementToJson(child, depth + 1)
                        : JsonValue.Create(child.InnerText.Trim()))
                .ToList();
            row[group.Key] = values.Count == 1 ? values[0] : new JsonArray(values.ToArray());
        }

        if (!element.ChildNodes.OfType<XmlElement>().Any() && element.InnerText.Trim() is { Length: > 0 } text)
            row["_text"] = text;
        return row;
    }

    /// <summary>RFC 4180: a header row, quoted fields, doubled quotes, line breaks inside quotes.</summary>
    public static List<JsonObject> Csv(string path, char delimiter)
    {
        var records = ParseCsv(File.ReadAllText(path, Encoding.UTF8), delimiter);
        if (records.Count == 0)
            return [];

        var header = records[0].Select(h => h.Trim().TrimStart('﻿')).ToList();
        var rows = new List<JsonObject>();
        foreach (var record in records.Skip(1).Where(r => r.Count > 1 || r[0].Length > 0))
        {
            var row = new JsonObject();
            for (var i = 0; i < header.Count; i++)
                row[header[i]] = i < record.Count ? record[i] : null;
            rows.Add(row);
        }
        return rows;
    }

    private static List<List<string>> ParseCsv(string text, char delimiter)
    {
        var records = new List<List<string>>();
        var record = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"')
                {
                    field.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
                else
                {
                    field.Append(c);
                }
                continue;
            }

            if (c == '"' && field.Length == 0)
                quoted = true;
            else if (c == delimiter)
            {
                record.Add(field.ToString());
                field.Clear();
            }
            else if (c is '\n' or '\r')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
                    i++;
                record.Add(field.ToString());
                field.Clear();
                records.Add(record);
                record = [];
            }
            else
            {
                field.Append(c);
            }
        }
        if (field.Length > 0 || record.Count > 0)
        {
            record.Add(field.ToString());
            records.Add(record);
        }
        return records;
    }
}
