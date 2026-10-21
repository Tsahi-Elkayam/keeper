using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;

namespace Keeper.Runners.Cim;

/// <summary>
/// registry: values of one key on each target host, through WMI's StdRegProv over WinRM (CIM). Only the
/// read methods are ever called - EnumKey, EnumValues and the Get*Value family; every method that writes
/// (SetValue, CreateKey, DeleteKey, ...) is unreachable from a rule. Values that hold credentials (an
/// automatic-logon password) come back as "set", never as the value. Binary values come back as hex.
/// certificates: true reads a certificate store key (SOFTWARE\Microsoft\SystemCertificates\Root, ...\MY,
/// the policy stores under SOFTWARE\Policies\...) as one row per certificate - the certificate only: the
/// registry holds no private key.
/// </summary>
public sealed partial class RegistryRunner : IRunner
{
    private const string Namespace = "root/default";
    private const string Provider = "StdRegProv";

    private static readonly Dictionary<string, uint> Hives = new(StringComparer.OrdinalIgnoreCase)
    {
        ["HKLM"] = 0x80000002, ["HKEY_LOCAL_MACHINE"] = 0x80000002,
        ["HKU"] = 0x80000003, ["HKEY_USERS"] = 0x80000003,
    };

    /// <summary>Value names whose data is a credential: only whether they are set is reported.</summary>
    public static readonly IReadOnlySet<string> SecretValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "DefaultPassword", "AltDefaultPassword", "AutoAdminLogonPassword", "Password", "Passwd", "pwd",
    };

    public string Protocol => "registry";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (query.Text("hive") is { } hive && !Hives.ContainsKey(hive))
            yield return "hive must be HKLM or HKU";
        if (query.Text("path") is not { } path || !KeyPath().IsMatch(path))
            yield return @"path is required: a key such as SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System (query key: names the entity field, as everywhere)";
        foreach (var value in query.List("values"))
        {
            if (value.Length is 0 or > 255 || value.Contains('\\', StringComparison.Ordinal))
                yield return $"values: '{value}' is not a value name";
        }
        if (query.Text("certificates") is not (null or "true" or "false"))
            yield return "certificates must be true or false";
        else if (query.Text("certificates") == "true" && (query.Fields["values"] is not null || query.Text("subkeys") == "true"))
            yield return "certificates reads a store's certificates: it takes no values and no subkeys";
        else if (query.Text("certificates") == "true" && !(query.Text("path") ?? "").Contains("Certificates", StringComparison.OrdinalIgnoreCase))
            yield return @"certificates needs a certificate store key, such as SOFTWARE\Microsoft\SystemCertificates\Root";
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(RunnerResult.Failed("registry needs Windows"));
        if (string.IsNullOrWhiteSpace(context.Target))
            return Task.FromResult(RunnerResult.Failed("registry needs a target host"));
        return Task.Run(() => OperatingSystem.IsWindows() ? Run(query, context) : RunnerResult.Failed("registry needs Windows"), cancellationToken);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Run(QuerySpec query, RunnerContext context)
    {
        var host = context.Target!;
        var hive = Hives[query.Text("hive") ?? "HKLM"];
        var key = query.Text("path")!;
        try
        {
            using var session = CimSessions.Open(host, context);

            if (query.Text("certificates") == "true")
                return Certificates(session, host, hive, key, context.Now);

            if (query.Text("subkeys") == "true")
            {
                var (code, subkeys) = Call(session, "EnumKey", hive, key);
                if (code == 2)
                    return RunnerResult.Ok([]);       // no such key: no subkeys
                if (code != 0)
                    return RunnerResult.Failed($"{host}: EnumKey {key} returned {code}");
                return RunnerResult.Ok(Strings(subkeys, "sNames")
                    .Select(n => new JsonObject { ["host"] = host, ["key"] = key, ["subkey"] = n }).ToList());
            }

            var (enumCode, listing) = Call(session, "EnumValues", hive, key);
            var row = new JsonObject { ["host"] = host, ["key"] = key, ["exists"] = enumCode == 0 };
            if (enumCode == 2)
                return RunnerResult.Ok([row]);       // the key does not exist: a fact a rule can judge
            if (enumCode != 0)
                return RunnerResult.Failed($"{host}: EnumValues {key} returned {enumCode}");

            var names = Strings(listing, "sNames");
            var types = listing?.OutParameters["Types"]?.Value is int[] t ? t : [];
            var wanted = query.List("values");
            var unread = new List<string>();
            for (var i = 0; i < names.Count; i++)
            {
                var name = names[i].Length == 0 ? "(default)" : names[i];
                if (wanted.Count > 0 && !wanted.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                var type = i < types.Length ? types[i] : 1;
                // A credential's value is never read: by its exact name, or - for text and bytes - by a name that
                // says it is one (ControlPassword, ProxyPass). A number under such a name is a setting.
                if (SecretValues.Contains(name) || (type is not (4 or 11) && SecretProperties.LooksSecret(name)))
                {
                    row[name] = "set";
                    continue;
                }
                var value = Read(session, hive, key, names[i], type);
                if (value is null)
                    unread.Add(name);
                row[name] = value;
            }
            // A value that is there but could not be read is unknown, never absent.
            return unread.Count == 0 ? RunnerResult.Ok([row])
                : RunnerResult.Partial([row], $"{host}: {unread.Count} value(s) of {key} could not be read ({string.Join(", ", unread.Take(5))})");
        }
        catch (CimException ex)
        {
            return RunnerResult.Failed($"{host}: {ex.Message}");
        }
    }

    /// <summary>
    /// One row per certificate of a store: store\Certificates\&lt;thumbprint&gt;\Blob. A store that is not there
    /// has no certificates; one whose blob cannot be read makes the read partial, never a smaller store.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Certificates(CimSession session, string host, uint hive, string store, DateTimeOffset now)
    {
        var certificates = store.EndsWith(@"\Certificates", StringComparison.OrdinalIgnoreCase) ? store : store + @"\Certificates";
        var (code, listing) = Call(session, "EnumKey", hive, certificates);
        if (code == 2)
            return RunnerResult.Ok([]);
        if (code != 0)
            return RunnerResult.Failed($"{host}: EnumKey {certificates} returned {code}");
        var rows = new List<JsonObject>();
        var unread = new List<string>();
        foreach (var thumbprint in Strings(listing, "sNames"))
        {
            var (blobCode, blob) = Call(session, "GetBinaryValue", hive, $@"{certificates}\{thumbprint}", "Blob");
            if (blobCode != 0 || blob?.OutParameters["uValue"]?.Value is not byte[] bytes
                || CertificateRows.FromStoreBlob(bytes) is not { } parsed)
            {
                unread.Add(thumbprint);
                continue;
            }
            using var certificate = parsed.Certificate;
            var row = CertificateRows.Of(certificate, now);
            row["host"] = host;
            row["store"] = store;
            row["friendlyName"] = parsed.FriendlyName;
            rows.Add(row);
        }
        return unread.Count == 0 ? RunnerResult.Ok(rows)
            : RunnerResult.Partial(rows, $"{host}: {unread.Count} certificate(s) of {store} could not be read ({string.Join(", ", unread.Take(3))})");
    }

    /// <summary>Calls one of the read methods. Nothing else can be passed here.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (uint Code, CimMethodResult? Result) Call(CimSession session, string method, uint hive, string key, string? value = null)
    {
        if (method is not ("EnumKey" or "EnumValues" or "GetStringValue" or "GetExpandedStringValue" or "GetDWORDValue"
            or "GetQWORDValue" or "GetMultiStringValue" or "GetBinaryValue"))
            throw new InvalidOperationException($"{method} is not a read method.");

        using var parameters = new CimMethodParametersCollection
        {
            CimMethodParameter.Create("hDefKey", hive, CimType.UInt32, CimFlags.In),
            CimMethodParameter.Create("sSubKeyName", key, CimType.String, CimFlags.In),
        };
        if (value is not null)
            parameters.Add(CimMethodParameter.Create("sValueName", value, CimType.String, CimFlags.In));
        var result = session.InvokeMethod(Namespace, Provider, method, parameters);
        return (Convert.ToUInt32(result.ReturnValue.Value, System.Globalization.CultureInfo.InvariantCulture), result);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static JsonNode? Read(CimSession session, uint hive, string key, string name, int type)
    {
        switch (type)
        {
            case 1:
                return Single(Call(session, "GetStringValue", hive, key, name), "sValue");
            case 2:
                return Single(Call(session, "GetExpandedStringValue", hive, key, name), "sValue");
            case 4:
                return Single(Call(session, "GetDWORDValue", hive, key, name), "uValue");
            case 11:
                return Single(Call(session, "GetQWORDValue", hive, key, name), "uValue");
            case 7:
                var (code, result) = Call(session, "GetMultiStringValue", hive, key, name);
                return code == 0 ? new JsonArray([.. Strings(result, "sValue").Select(s => (JsonNode)JsonValue.Create(s))]) : null;
            case 3:
                // Binary as hex; a large blob is said by its size (a rule judges whether it is there, not its bytes).
                // Read, but empty: an empty value, not an unread one.
                var (binaryCode, binary) = Call(session, "GetBinaryValue", hive, key, name);
                if (binaryCode != 0)
                    return null;
                return binary?.OutParameters["uValue"]?.Value is byte[] bytes
                    ? bytes.Length <= MaxBinaryBytes ? Convert.ToHexStringLower(bytes) : $"({bytes.Length} bytes)"
                    : "";
            default:
                return $"(type {type})";   // a type no rule reads (a link, a resource list): there, not read
        }
    }

    private const int MaxBinaryBytes = 4096;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    // Null only when the read failed: a value read as empty is "".
    private static JsonNode? Single((uint Code, CimMethodResult? Result) call, string parameter) =>
        call.Code == 0 ? RowValues.From(call.Result?.OutParameters[parameter]?.Value) ?? JsonValue.Create("") : null;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static List<string> Strings(CimMethodResult? result, string parameter) =>
        result?.OutParameters[parameter]?.Value is string[] values ? [.. values] : [];

    [GeneratedRegex(@"^[A-Za-z0-9 _.()\-{}]+(\\[A-Za-z0-9 _.()\-{}]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyPath();
}
