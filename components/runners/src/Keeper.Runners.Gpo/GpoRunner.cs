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
            // Read as the Windows user Keeper runs as: a stored credential is never used for SMB.
            if (context.Connection.AuthKind != "negotiate")
                return Task.FromResult(RunnerResult.Failed("gpo reads SYSVOL as the Windows user Keeper runs as: the integration's auth must be negotiate"));
            // The domain's own SYSVOL: \\example.org\SYSVOL\example.org\Policies - named by the domain, never a DC.
            var domain = Domain(context.Connection.Options["domain"]?.ToString() ?? context.Connection.Endpoint);
            if (domain is null)
                return Task.FromResult(RunnerResult.Failed(
                    "gpo needs the domain's name (example.org): the integration's endpoint is not one - set its option domain"));
            root = $@"\\{domain}\SYSVOL\{domain}\Policies";
        }
        return Task.Run(() => Read(root, query, cancellationToken), cancellationToken);
    }

    /// <summary>
    /// The domain's name from an ldap endpoint or the domain option: example.org, or ldap://example.org. An
    /// endpoint with a port, or one that names a server rather than the domain, cannot be told apart from a
    /// domain here, so a URL is taken only without a port; otherwise the option domain says it.
    /// </summary>
    public static string? Domain(string endpoint)
    {
        var text = endpoint.Trim();
        if (text.Contains("://", StringComparison.Ordinal))
            text = Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.IsDefaultPort && uri.AbsolutePath is "" or "/" ? uri.Host : "";
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
        // Every GPO has a GPT.INI. One that cannot be opened is a GPO this account cannot read - never one
        // without settings. (Windows says "not there" for "not allowed" too, so it is opened, not looked for.)
        var gpt = ReadText(Path.Combine(folder, "GPT.INI"))
                  ?? throw new InvalidDataException("no GPT.INI: the folder cannot be read, or is an orphan or still replicating - not a whole GPO");
        switch (part)
        {
            case "gpt":
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
                    List<string> files;
                    try
                    {
                        files = [.. Directory.EnumerateFiles(Path.Combine(folder, half, "Preferences"), "*.xml", SearchOption.AllDirectories)
                            .Order(StringComparer.OrdinalIgnoreCase)];
                    }
                    catch (DirectoryNotFoundException)
                    {
                        continue;   // no preferences in this half; a folder that is there but closed throws on
                    }
                    foreach (var file in files)
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
        if (item["Properties"] is not JsonObject properties)
            return;
        // A registry preference names its value: <Properties name="DefaultPassword" value="..."/>; an ini
        // preference its property: <Properties property="Password" value="..."/>.
        foreach (var label in new[] { "name", "property" })
        {
            if (Values.Text(properties[label]) is { } name && SecretProperties.LooksSecret(name) && Values.Text(properties["value"]) is { Length: > 0 }
                && Values.Text(properties["type"]) is not ("REG_DWORD" or "REG_QWORD"))
                properties["value"] = FieldPath.MaskedValue;
        }
        // A scheduled task's command line can carry a password - wherever the task keeps it (Arguments of an
        // Exec action, deep in a v2 task, or the arguments of a v1 one).
        MaskCommandLines(item);
    }

    // A password on a command line: -p secret, /p:secret, password=..., pwd ... Never "Bypass" or "-PassThru".
    [GeneratedRegex(@"\bpass(w(or)?d|phrase)?\b|\bpwd\b|-p\s+\S|/p[:\s]\S|secret|token|credential", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PasswordArguments();

    private static readonly string[] CommandLines = ["arguments", "args", "command", "commandLine"];

    private static void MaskCommandLines(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).ToList())
                {
                    if (CommandLines.Contains(name, StringComparer.OrdinalIgnoreCase) && Values.Text(o[name]) is { } line && o[name] is JsonValue
                        && PasswordArguments().IsMatch(line))
                        o[name] = FieldPath.MaskedValue;
                    else
                        MaskCommandLines(o[name]);
                }
                break;
            case JsonArray a:
                foreach (var child in a)
                    MaskCommandLines(child);
                break;
        }
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

    /// <summary>
    /// The file's bytes, or null when it is not there. Opened, never looked for: Windows answers "not there"
    /// to an existence check it may not make, so only "not found" is absence - "access denied" and any other
    /// error stop the GPO's read.
    /// </summary>
    private static byte[]? ReadBytes(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            if (stream.Length > MaxFileBytes)
                throw new InvalidDataException($"{Path.GetFileName(file)} is larger than {MaxFileBytes / 1024 / 1024} MB");
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return bytes;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>The file's text, by its BOM (GptTmpl.inf is UTF-16), or null when it is not there.</summary>
    private static string? ReadText(string file) => ReadBytes(file) is { } bytes ? new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true).ReadToEnd() : null;
}
