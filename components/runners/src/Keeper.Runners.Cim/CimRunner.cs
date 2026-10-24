using System.Security;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace Keeper.Runners.Cim;

/// <summary>
/// cim: a WQL SELECT over WinRM (CIM) on each target Windows host - disks, services, OS, uptime.
/// In-process: no PowerShell, no child processes. Kerberos with the current user, or the integration's
/// stored credential. Only SELECT is accepted; CIM methods are never invoked.
/// </summary>
public sealed partial class CimRunner : IRunner
{
    public string Protocol => "cim";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (Problem(query.Text("wql")) is { } problem)
            yield return problem;
        if (query.Text("namespace") is { } ns && !Namespace().IsMatch(ns))
            yield return "namespace must look like root/cimv2";
    }

    public static string? Problem(string? wql)
    {
        if (string.IsNullOrWhiteSpace(wql))
            return "wql is required";
        if (!Select().IsMatch(wql) || wql.Contains(';'))
            return "only one WQL SELECT is allowed";
        // Reading Win32_Product (and its Win32_Product* siblings) makes Windows Installer re-check, and so repair, every package.
        if (InstallerClasses().IsMatch(wql))
            return "Win32_Product is never read: it makes Windows Installer re-check every package. Read the Uninstall registry keys instead.";
        return null;
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(RunnerResult.Failed("cim needs Windows"));
        if (Problem(query.Text("wql")) is { } problem)
            return Task.FromResult(RunnerResult.Failed(problem));
        if (string.IsNullOrWhiteSpace(context.Target))
            return Task.FromResult(RunnerResult.Failed("cim needs a target host"));
        return Task.Run(() => OperatingSystem.IsWindows() ? Run(query, context, cancellationToken) : RunnerResult.Failed("cim needs Windows"),
            cancellationToken);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Run(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var host = context.Target!;
        try
        {
            if (Expand(query.Text("wql")!, host) is not { } wql)
                return RunnerResult.Failed($"{host}: not a host name {{HOST}} can stand for");

            using var session = CimSessions.Open(host, context, query.List("fallback_chain"));
            var rows = new List<JsonObject>();
            foreach (var instance in session.QueryInstances(query.Text("namespace") ?? "root/cimv2", "WQL", wql))
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (instance)
                {
                    var row = new JsonObject { ["host"] = host };
                    foreach (var property in instance.CimInstanceProperties)
                        row[property.Name] = RowValues.From(property.Value);
                    rows.Add(row);
                }
            }
            return RunnerResult.Ok(rows);
        }
        catch (CimException ex)
        {
            return RunnerResult.Failed($"{host}: {ex.Message}");
        }
    }

    /// <summary>
    /// {HOST} becomes the target's computer name - its first DNS label, upper case - which is what
    /// local accounts and groups carry as their Domain (Win32_Group.Domain='PC01',Name='Administrators').
    /// The name is checked strictly first: targets come from scanned data and must not reach WQL raw.
    /// </summary>
    public static string? Expand(string wql, string target)
    {
        if (!wql.Contains("{HOST}", StringComparison.Ordinal))
            return wql;
        var name = target.Split('.')[0].ToUpperInvariant();
        return HostName().IsMatch(name) ? wql.Replace("{HOST}", name, StringComparison.Ordinal) : null;
    }

    [GeneratedRegex(@"Win32_Product", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InstallerClasses();

    [GeneratedRegex(@"^\s*select\s", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Select();

    [GeneratedRegex("^[A-Z0-9][A-Z0-9-]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex HostName();

    [GeneratedRegex(@"^root(/[A-Za-z0-9_]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex Namespace();
}
