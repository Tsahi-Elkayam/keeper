using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;

namespace Keeper.Runners.Cim;

/// <summary>
/// registry: values of one key on each target host, through WMI's StdRegProv over WinRM (CIM). Only the
/// read methods are ever called - EnumKey, EnumValues and the Get*Value family; every method that writes
/// (SetValue, CreateKey, DeleteKey, ...) is unreachable from a rule. Values that hold credentials (an
/// automatic-logon password) come back as "set", never as the value.
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
        if (query.Text("key") is not { } key || !KeyPath().IsMatch(key))
            yield return @"key is required: a path such as SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        foreach (var value in query.List("values"))
        {
            if (value.Length is 0 or > 255 || value.Contains('\\', StringComparison.Ordinal))
                yield return $"values: '{value}' is not a value name";
        }
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
        var key = query.Text("key")!;
        try
        {
            using var session = CimSessions.Open(host, context);

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
            for (var i = 0; i < names.Count; i++)
            {
                var name = names[i].Length == 0 ? "(default)" : names[i];
                if (wanted.Count > 0 && !wanted.Contains(name, StringComparer.OrdinalIgnoreCase))
                    continue;
                if (SecretValues.Contains(name))
                {
                    row[name] = "set";
                    continue;
                }
                row[name] = Read(session, hive, key, names[i], i < types.Length ? types[i] : 1);
            }
            return RunnerResult.Ok([row]);
        }
        catch (CimException ex)
        {
            return RunnerResult.Failed($"{host}: {ex.Message}");
        }
    }

    /// <summary>Calls one of the read methods. Nothing else can be passed here.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (uint Code, CimMethodResult? Result) Call(CimSession session, string method, uint hive, string key, string? value = null)
    {
        if (method is not ("EnumKey" or "EnumValues" or "GetStringValue" or "GetExpandedStringValue" or "GetDWORDValue"
            or "GetQWORDValue" or "GetMultiStringValue"))
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
            default:
                return null;       // binary and other types: not read
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static JsonNode? Single((uint Code, CimMethodResult? Result) call, string parameter) =>
        call.Code == 0 ? RowValues.From(call.Result?.OutParameters[parameter]?.Value) : null;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static List<string> Strings(CimMethodResult? result, string parameter) =>
        result?.OutParameters[parameter]?.Value is string[] values ? [.. values] : [];

    [GeneratedRegex(@"^[A-Za-z0-9 _.()\-{}]+(\\[A-Za-z0-9 _.()\-{}]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyPath();
}
