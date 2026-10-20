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
            using var options = new WSManSessionOptions { Timeout = context.Timeout };
            var credential = context.Connection.WindowsCredential();
            if (credential is not null)
            {
                using var password = new SecureString();
                foreach (var c in credential.Password)
                    password.AppendChar(c);
                options.AddDestinationCredentials(new CimCredential(PasswordAuthenticationMechanism.Kerberos, credential.Domain, credential.UserName, password));
            }

            using var session = CimSession.Create(host, options);
            var rows = new List<JsonObject>();
            foreach (var instance in session.QueryInstances(query.Text("namespace") ?? "root/cimv2", "WQL", query.Text("wql")))
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

    [GeneratedRegex(@"^\s*select\s", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Select();

    [GeneratedRegex(@"^root(/[A-Za-z0-9_]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex Namespace();
}
