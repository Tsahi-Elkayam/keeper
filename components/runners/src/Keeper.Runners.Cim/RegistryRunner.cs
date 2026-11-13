using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

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
public sealed partial class RegistryRunner : ISessionRunner, IQueryMerger
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

    public string SessionFamily => "cim";

    public Task<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken cancellationToken) =>
        CimSessions.OpenAsync(Protocol, context, cancellationToken);

    /// <summary>Outside a scan: one session for this one query.</summary>
    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (Precheck(context) is { } failed)
            return Task.FromResult(failed);
        return CimSessions.OneShot(Protocol, context, cancellationToken, session => RunAsync(session, query, context, cancellationToken));
    }

    public async Task<RunnerResult> RunAsync(IRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (Precheck(context) is { } failed)
            return failed;
        if (session is not CimRunnerSession cim)
            return RunnerResult.Failed("registry was given a session of another family");
        return await RunOnWindows(cim, query, context, cancellationToken).ConfigureAwait(false);
    }

    private static RunnerResult? Precheck(RunnerContext context)
    {
        if (!OperatingSystem.IsWindows())
            return RunnerResult.Failed("registry needs Windows");
        if (string.IsNullOrWhiteSpace(context.Target))
            return RunnerResult.Failed("registry needs a target host");
        return null;
    }

    private static Task<RunnerResult> RunOnWindows(CimRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken) =>
        OperatingSystem.IsWindows() ? Run(session, query, context, cancellationToken) : Task.FromResult(RunnerResult.Failed("registry needs Windows"));

    // ---- merging: registry queries on one key become one read of the union of their values ----

    /// <summary>Added to a merged query so its row carries the names it could not read, for <see cref="Split"/>. Never set on a query of its own.</summary>
    private const string MergedMarker = "_merged";

    /// <summary>The row field that carries the unread value names of a merged read. A NUL cannot be part of a registry value name.</summary>
    private const string UnreadField = "\0unread";

    public string? MergeKey(QuerySpec query)
    {
        // Subkey listings and certificate stores are read on their own; so is a query that already is a merge.
        if (query.Text("subkeys") == "true" || query.Text("certificates") == "true" || query.Fields[MergedMarker] is not null)
            return null;
        if (!Hives.TryGetValue(query.Text("hive") ?? "HKLM", out var hive) || query.Text("path") is not { } path)
            return null;
        // The path as written: queries that spell a key differently are not merged, so each row keeps the key its rules read.
        return $"{hive:x}|{path}|{query.Key}|{string.Join(',', query.List("fallback_chain")).ToLowerInvariant()}";
    }

    public QuerySpec Merge(IReadOnlyList<QuerySpec> queries)
    {
        var fields = (JsonObject)queries[0].Fields.DeepClone();
        // Reading all values already includes any named ones: one query without values makes the merge read all.
        if (queries.Any(q => q.List("values").Count == 0))
        {
            fields.Remove("values");
        }
        else
        {
            var union = new List<string>();
            foreach (var name in queries.SelectMany(q => q.List("values")))
            {
                if (!union.Contains(name, StringComparer.OrdinalIgnoreCase))
                    union.Add(name);
            }
            fields["values"] = new JsonArray([.. union.Select(n => (JsonNode)JsonValue.Create(n))]);
        }
        fields[MergedMarker] = true;
        return new QuerySpec(queries[0].Protocol, fields, queries[0].Key, queries[0].Name);
    }

    public RunnerResult Split(QuerySpec original, RunnerResult merged)
    {
        // A failed read is failed for everyone who asked, for the same reason and of the same kind.
        if (merged.State == "failed")
            return RunnerResult.Failed(merged.Reason ?? "failed", merged.Failure);
        var wanted = original.List("values");
        bool Wanted(string name) => wanted.Count == 0 || wanted.Contains(name, StringComparer.OrdinalIgnoreCase);

        var rows = new List<JsonObject>();
        var unread = new List<string>();
        var host = "";
        var key = "";
        foreach (var row in merged.Rows)
        {
            var own = new JsonObject();
            foreach (var (name, value) in row)
            {
                if (name == UnreadField)
                {
                    if (value is JsonArray names)
                        unread.AddRange(names.Select(n => n?.ToString() ?? "").Where(n => Wanted(n)));
                }
                else if (name is "host" or "key" or "exists" || Wanted(name))
                {
                    own[name] = value?.DeepClone();
                }
            }
            host = row["host"]?.ToString() ?? host;
            key = row["key"]?.ToString() ?? key;
            rows.Add(own);
        }
        // Partial only for this query's own values; a value another query asked for does not make this one unknown.
        return unread.Count == 0 ? RunnerResult.Ok(rows) : RunnerResult.Partial(rows, UnreadReason(host, key, unread));
    }

    private static string UnreadReason(string host, string key, IReadOnlyList<string> unread) =>
        $"{host}: {unread.Count} value(s) of {key} could not be read ({string.Join(", ", unread.Take(5))})";

    /// <summary>
    /// The calls of one query over the shared session. A query makes several (EnumValues, then one Get*Value per
    /// value; EnumKey, then one GetBinaryValue per certificate): the first goes out after the scan's own wait, every
    /// further one waits on the host's pace first.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private sealed class Calls(CimSession session, RunnerContext context, CancellationToken cancellationToken)
    {
        private int _count;

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        public async Task<(uint Code, CimMethodResult? Result)> CallAsync(string method, uint hive, string key, string? value = null)
        {
            if (_count++ > 0)
                await context.Pace.WaitAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return await Task.Run(() => Invoke(session, context.Timeout, method, hive, key, value), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The failure kind of a StdRegProv return code: 5 is access denied on this key (signed in, not allowed), the rest is an error.</summary>
    private static FailureKind KindOf(uint code) => code == 5 ? FailureKind.Denied : FailureKind.Error;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task<RunnerResult> Run(CimRunnerSession shared, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var host = context.Target!;
        var hive = Hives[query.Text("hive") ?? "HKLM"];
        var key = query.Text("path")!;
        try
        {
            using var lease = CimSessions.Lease(shared, host, context, query.List("fallback_chain"));
            var calls = new Calls(lease.Session, context, cancellationToken);

            if (query.Text("certificates") == "true")
                return await Certificates(calls, host, hive, key, context.Now).ConfigureAwait(false);

            if (query.Text("subkeys") == "true")
            {
                var (code, subkeys) = await calls.CallAsync("EnumKey", hive, key).ConfigureAwait(false);
                if (code == 2)
                    return RunnerResult.Ok([]);       // no such key: no subkeys
                if (code != 0)
                    return RunnerResult.Failed($"{host}: EnumKey {key} returned {code}", KindOf(code));
                return RunnerResult.Ok(Strings(subkeys, "sNames")
                    .Select(n => new JsonObject { ["host"] = host, ["key"] = key, ["subkey"] = n }).ToList());
            }

            var (enumCode, listing) = await calls.CallAsync("EnumValues", hive, key).ConfigureAwait(false);
            var row = new JsonObject { ["host"] = host, ["key"] = key, ["exists"] = enumCode == 0 };
            if (enumCode == 2)
                return RunnerResult.Ok([row]);       // the key does not exist: a fact a rule can judge
            if (enumCode != 0)
                return RunnerResult.Failed($"{host}: EnumValues {key} returned {enumCode}", KindOf(enumCode));

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
                var value = await Read(calls, hive, key, names[i], type).ConfigureAwait(false);
                if (value is null)
                    unread.Add(name);
                row[name] = value;
            }
            // A value that is there but could not be read is unknown, never absent.
            if (unread.Count == 0)
                return RunnerResult.Ok([row]);
            // A merged read keeps the names in the row, so Split can tell which of its queries they belong to.
            if (query.Fields[MergedMarker] is not null)
                row[UnreadField] = new JsonArray([.. unread.Select(n => (JsonNode)JsonValue.Create(n))]);
            return RunnerResult.Partial([row], UnreadReason(host, key, unread));
        }
        catch (CimException ex)
        {
            return RunnerResult.Failed($"{host}: {ex.Message}", CimErrors.Of(ex));
        }
        catch (RunnerFailureException ex)
        {
            // The rule's own fallback_chain needed a session of its own and that sign-in failed.
            return RunnerResult.Failed(ex.Message, ex.Kind);
        }
    }

    /// <summary>
    /// One row per certificate of a store: store\Certificates\&lt;thumbprint&gt;\Blob. A store that is not there
    /// has no certificates; one whose blob cannot be read makes the read partial, never a smaller store.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task<RunnerResult> Certificates(Calls calls, string host, uint hive, string store, DateTimeOffset now)
    {
        var certificates = store.EndsWith(@"\Certificates", StringComparison.OrdinalIgnoreCase) ? store : store + @"\Certificates";
        var (code, listing) = await calls.CallAsync("EnumKey", hive, certificates).ConfigureAwait(false);
        if (code == 2)
            return RunnerResult.Ok([]);
        if (code != 0)
            return RunnerResult.Failed($"{host}: EnumKey {certificates} returned {code}", KindOf(code));
        var rows = new List<JsonObject>();
        var unread = new List<string>();
        foreach (var thumbprint in Strings(listing, "sNames"))
        {
            var (blobCode, blob) = await calls.CallAsync("GetBinaryValue", hive, $@"{certificates}\{thumbprint}", "Blob").ConfigureAwait(false);
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
    private static (uint Code, CimMethodResult? Result) Invoke(CimSession session, TimeSpan timeout, string method, uint hive, string key, string? value)
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
        // The session's timeout is fixed when it is created; each call carries this query's own limit.
        using var options = new CimOperationOptions { Timeout = timeout };
        var result = session.InvokeMethod(Namespace, Provider, method, parameters, options);
        return (Convert.ToUInt32(result.ReturnValue.Value, System.Globalization.CultureInfo.InvariantCulture), result);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async Task<JsonNode?> Read(Calls calls, uint hive, string key, string name, int type)
    {
        switch (type)
        {
            case 1:
                return Single(await calls.CallAsync("GetStringValue", hive, key, name).ConfigureAwait(false), "sValue");
            case 2:
                return Single(await calls.CallAsync("GetExpandedStringValue", hive, key, name).ConfigureAwait(false), "sValue");
            case 4:
                return Single(await calls.CallAsync("GetDWORDValue", hive, key, name).ConfigureAwait(false), "uValue");
            case 11:
                return Single(await calls.CallAsync("GetQWORDValue", hive, key, name).ConfigureAwait(false), "uValue");
            case 7:
                var (code, result) = await calls.CallAsync("GetMultiStringValue", hive, key, name).ConfigureAwait(false);
                return code == 0 ? new JsonArray([.. Strings(result, "sValue").Select(s => (JsonNode)JsonValue.Create(s))]) : null;
            case 3:
                // Binary as hex; a large blob is said by its size (a rule judges whether it is there, not its bytes).
                // Read, but empty: an empty value, not an unread one.
                var (binaryCode, binary) = await calls.CallAsync("GetBinaryValue", hive, key, name).ConfigureAwait(false);
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

    // Null only when the read failed: a value read as empty is "".
    private static JsonNode? Single((uint Code, CimMethodResult? Result) call, string parameter) =>
        call.Code == 0 ? RowValues.From(call.Result?.OutParameters[parameter]?.Value) ?? JsonValue.Create("") : null;

    private static List<string> Strings(CimMethodResult? result, string parameter) =>
        result?.OutParameters[parameter]?.Value is string[] values ? [.. values] : [];

    [GeneratedRegex(@"^[A-Za-z0-9 _.()\-{}]+(\\[A-Za-z0-9 _.()\-{}]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyPath();
}
