using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;

namespace Keeper.Runners.Gpo;

/// <summary>
/// gpo: every Group Policy object's settings, read from the domain's SYSVOL share in-process (the Windows
/// SMB client; no gpresult, no PowerShell). part: registry (Registry.pol), security (GptTmpl.inf), audit
/// (audit.csv), preferences (Group Policy Preferences XML; any cpassword comes back as "set"), gpt (GPT.INI
/// versions). scope: machine, user or both. Rows carry gpo (the GPO's GUID), scope and _file. A GPO folder
/// that cannot be read makes the result partial; SYSVOL that cannot be read, failed.
/// </summary>
public sealed partial class GpoRunner(Func<IConnection, string>? policiesRoot = null) : IRunner
{
    private const long MaxFileBytes = 16L * 1024 * 1024;
    private static readonly string[] Parts = ["registry", "security", "audit", "preferences", "gpt"];
    private static readonly string[] Scopes = ["machine", "user", "both"];

    [GeneratedRegex(@"\A\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\z", RegexOptions.CultureInvariant)]
    private static partial Regex GpoFolder();

    [GeneratedRegex(@"\A(?=.{1,253}\z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\z", RegexOptions.CultureInvariant)]
    private static partial Regex DomainName();

    public string Protocol => "gpo";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        var part = query.Text("part");
        if (part is null || !Parts.Contains(part))
            yield return $"part must be {string.Join(", ", Parts)}";
        if (query.Text("scope") is { } scope && !Scopes.Contains(scope))
            yield return "scope must be machine, user or both";
        else if (part is "security" or "audit" && query.Text("scope") is "user")
            yield return $"{part} settings are the computer's: scope machine";
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        string root;
        if (policiesRoot is not null)
        {
            root = policiesRoot(context.Connection);
        }
        else
        {
            // The domain's own SYSVOL: \\example.org\SYSVOL\example.org\Policies, from the ldap integration's domain.
            var domain = Domain(context.Connection.Endpoint);
            if (domain is null)
                return Task.FromResult(RunnerResult.Failed("the integration's endpoint does not name a domain (example.org) whose SYSVOL to read"));
            root = $@"\\{domain}\SYSVOL\{domain}\Policies";
        }
        return Task.Run(() => Read(root, query, cancellationToken), cancellationToken);
    }

    /// <summary>A domain name from an ldap endpoint: example.org, ldap://example.org, ldaps://dc1.example.org:636 (its host).</summary>
    public static string? Domain(string endpoint)
    {
        var text = endpoint.Trim();
        if (text.Contains("://", StringComparison.Ordinal))
            text = Uri.TryCreate(text, UriKind.Absolute, out var uri) ? uri.Host : "";
        return DomainName().IsMatch(text) ? text : null;
    }

    private static RunnerResult Read(string root, QuerySpec query, CancellationToken cancellationToken)
    {
        var part = query.Text("part")!;
        var scope = query.Text("scope") ?? (part is "security" or "audit" ? "machine" : "both");
        List<string> folders;
        try
        {
            folders = [.. Directory.EnumerateDirectories(root).Where(f => GpoFolder().IsMatch(Path.GetFileName(f)))];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return RunnerResult.Failed($"SYSVOL could not be read ({root}): {ex.Message}");
        }

        var rows = new List<JsonObject>();
        var problems = new List<string>();
        foreach (var folder in folders)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var gpo = Path.GetFileName(folder).ToUpperInvariant();
            try
            {
                foreach (var row in Rows(folder, part, scope))
                {
                    row["gpo"] = gpo;
                    rows.Add(row);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException or InvalidDataException)
            {
                problems.Add($"{gpo}: {ex.Message}");
            }
        }
        if (folders.Count == 0)
            return RunnerResult.Partial(rows, $"SYSVOL lists no Group Policy objects ({root}): a domain has at least two");
        if (problems.Count == folders.Count)
            return RunnerResult.Failed($"no Group Policy object could be read: {string.Join("; ", problems.Take(3))}");
        return problems.Count == 0 ? RunnerResult.Ok(rows)
            : RunnerResult.Partial(rows, $"{problems.Count} of {folders.Count} Group Policy objects could not be read: {string.Join("; ", problems.Take(3))}");
    }

    private static IEnumerable<JsonObject> Rows(string folder, string part, string scope)
    {
        var halves = scope switch { "machine" => new[] { "Machine" }, "user" => ["User"], _ => ["Machine", "User"] };
        switch (part)
        {
            case "gpt":
                if (ReadText(Path.Combine(folder, "GPT.INI")) is { } gpt)
                    yield return Tagged(GpoFiles.Gpt(gpt), null, "GPT.INI");
                break;
            case "registry":
                foreach (var half in halves)
                {
                    var file = Path.Combine(folder, half, "Registry.pol");
                    if (ReadBytes(file) is not { } bytes)
                        continue;
                    var entries = GpoFiles.RegistryPol(bytes) ?? throw new InvalidDataException($"{half}\\Registry.pol is not a Registry.pol file");
                    foreach (var entry in entries)
                        yield return Tagged(entry, half, $@"{half}\Registry.pol");
                }
                break;
            case "security":
                if (ReadText(Path.Combine(folder, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")) is { } template)
                    foreach (var row in GpoFiles.SecurityTemplate(template))
                        yield return Tagged(row, "Machine", @"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf");
                break;
            case "audit":
                if (ReadText(Path.Combine(folder, "Machine", "Microsoft", "Windows NT", "Audit", "audit.csv")) is { } audit)
                    foreach (var row in GpoFiles.AuditPolicy(audit))
                        yield return Tagged(row, "Machine", @"Machine\Microsoft\Windows NT\Audit\audit.csv");
                break;
            case "preferences":
                foreach (var half in halves)
                {
                    var preferences = Path.Combine(folder, half, "Preferences");
                    if (!Directory.Exists(preferences))
                        continue;
                    foreach (var file in Directory.EnumerateFiles(preferences, "*.xml", SearchOption.AllDirectories).Order(StringComparer.OrdinalIgnoreCase))
                    {
                        if (ReadText(file) is not { } xml)
                            continue;
                        var document = XmlRows.Load(new StringReader(xml), MaxFileBytes);
                        // Every preference item has its settings in a Properties child.
                        foreach (var item in XmlRows.Select(document, "//*[Properties]"))
                        {
                            MaskPasswords(item);
                            yield return Tagged(item, half, Path.GetRelativePath(folder, file));
                        }
                    }
                }
                break;
        }
    }

    private static JsonObject Tagged(JsonObject row, string? half, string file)
    {
        if (half is not null)
            row["scope"] = half.ToLowerInvariant();
        row["_file"] = file;
        return row;
    }

    /// <summary>
    /// cpassword: a preference's password, encrypted with a key Microsoft published (MS14-025) - as good as
    /// clear text. Never kept: "set" says one is there, which is the finding.
    /// </summary>
    private static void MaskPasswords(JsonObject item)
    {
        SecretProperties.Mask(item);
        MaskCpassword(item);
    }

    private static void MaskCpassword(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).ToList())
                {
                    if (name.Equals("cpassword", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Values.Text(o[name]) is { Length: > 0 })
                            o[name] = FieldPath.MaskedValue;
                    }
                    else
                    {
                        MaskCpassword(o[name]);
                    }
                }
                break;
            case JsonArray a:
                foreach (var item in a)
                    MaskCpassword(item);
                break;
        }
    }

    private static byte[]? ReadBytes(string file)
    {
        var info = new FileInfo(file);
        if (!info.Exists)
            return null;
        if (info.Length > MaxFileBytes)
            throw new InvalidDataException($"{info.Name} is larger than {MaxFileBytes / 1024 / 1024} MB");
        return File.ReadAllBytes(file);
    }

    /// <summary>The file's text, by its BOM (GptTmpl.inf is UTF-16), or null when it is not there.</summary>
    private static string? ReadText(string file) => ReadBytes(file) is { } bytes ? new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true).ReadToEnd() : null;
}
