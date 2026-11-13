using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Scan;
using Keeper.Store;
using Keeper.Vault;

// keeper connect: one command that connects a whole tenant, then proves the sign-in and says - before any scan -
// which rules its permissions leave unable to run. It reads one token and nothing else from the tenant.
public static class ConnectVerb
{
    private const string DefaultName = "microsoft";

    public static int Run(string[] args)
    {
        try
        {
            var cli = new CliArgs(args);
            if (cli.Help || cli.At(0) is null)
                return Usage(asked: cli.Help);
            return cli.At(0) switch
            {
                "microsoft" => Microsoft(cli),
                "check" => Check(cli, cli.At(1)),
                "permissions" => Permissions(),
                _ => Usage(asked: false),
            };
        }
        catch (Exception ex) when (ex is SettingsException or ArgumentException or IntegrationException or RuleException)
        {
            Console.Error.WriteLine(ex.Message);
            return ExitCodes.Usage;
        }
    }

    private static int Usage(bool asked) => CliUsage.Print("""
        keeper connect - connect a tenant in one step and check what Keeper may read there

          keeper connect microsoft --tenant <tenant id> --client-id <app id> --certificate <thumbprint> [--name microsoft]
                                         Microsoft 365 (Entra ID, Intune, Microsoft 365, Defender) through one app
                                         registration that signs in with a certificate; creates or updates the
                                         integration, signs in once and lists the permissions still missing
          keeper connect check [<integration>]
                                         sign in again and list the missing permissions (after an admin granted more)
          keeper connect permissions     the Graph application permissions to grant the app, one per line

        The app registration, its certificate and the permissions: CONNECT-MICROSOFT.md beside keeper. Keeper only reads;
        every permission it asks for is a Read permission, and none that reads mail, files or secret values.
        """, asked);

    private static int Microsoft(CliArgs cli)
    {
        var tenant = cli.Require("tenant");
        var clientId = cli.Require("client-id");
        var thumbprint = cli.Require("certificate").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
        var name = cli.Get("name") ?? DefaultName;
        if (!Guid.TryParse(clientId, out _))
            throw new ArgumentException("--client-id is the app registration's Application (client) ID, a GUID.");
        if (!Guid.TryParse(tenant, out _) && !tenant.Contains('.', StringComparison.Ordinal))
            throw new ArgumentException("--tenant is the Directory (tenant) ID, a GUID, or a domain of the tenant (example.onmicrosoft.com).");
        if (!IntegrationTypes.IsValidId(name))
            throw new ArgumentException("--name: lower-case letters, digits and dashes, starting with a letter.");

        // The certificate is checked here, on this machine, before anything is stored: the commonest first-run failure.
        if (FindCertificate(thumbprint) is not { } certificate)
            throw new ArgumentException($"No certificate {thumbprint} in the current user's certificate store (CurrentUser\\My) with its private key. " +
                                        "CONNECT-MICROSOFT.md, beside keeper, shows how to create one and upload its public part to the app.");
        Console.WriteLine($"Certificate: {certificate.Subject}, valid until {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd}");

        var (_, paths) = KeeperContext.Load(cli);
        var all = Integrations(paths);
        var exists = all.Any(i => i.Id == name);
        // A finding is known by its rule, entity and target, and every Graph tenant has the same target: two tenants
        // in one home would resolve each other's findings. One Keeper home per tenant keeps them apart.
        if (OtherTenant(all, name, tenant) is { } other)
            throw new ArgumentException($"This Keeper home already reads tenant {other.Options["tenantId"]} through integration {other.Id}. " +
                                        "Use one Keeper home per tenant: set KEEPER_HOME to a new folder, run 'keeper setup' there, then connect.");
        var reason = cli.Get("reason") ?? $"Connect Microsoft 365 tenant {tenant}";
        string[] change =
        [
            exists ? "set" : "add", name, .. exists ? Array.Empty<string>() : ["--type", "graph"],
            "--auth", "entra-certificate", "--endpoint", "https://graph.microsoft.com",
            "--option", $"tenantId={tenant}", "--option", $"clientId={clientId}", "--option", $"certificateThumbprint={thumbprint}",
            "--reason", reason, .. Passed(cli, "settings"),
        ];
        if (Commands.Run("integration", change) != ExitCodes.Ok || Commands.Run("qm", ["run", .. Passed(cli, "settings")]) != ExitCodes.Ok)
            return ExitCodes.Failed;
        Console.WriteLine($"Integration {name}: {(exists ? "updated" : "added")}.");
        Console.WriteLine();
        return Check(cli, name);
    }

    private static int Check(CliArgs cli, string? id)
    {
        var (_, paths) = KeeperContext.Load(cli);
        var graph = Integrations(paths).Where(i => i.Type == "graph").ToList();
        var record = id is null
            ? graph.FirstOrDefault(i => i.Enabled) ?? throw new ArgumentException("No Graph integration yet: keeper connect microsoft ... sets one up.")
            : graph.FirstOrDefault(i => i.Id == id) ?? throw new ArgumentException($"No Graph integration {id}. 'keeper integration list' shows them.");

        string token;
        using (var connection = new IntegrationConnection(record, record.Secrets.Count > 0 ? LoadVault(paths) : null))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/organization");
            try
            {
                connection.AuthorizeAsync(request, CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is IntegrationException or SignInException)
            {
                Console.WriteLine($"Sign-in to {record.Options["tenantId"]} as app {record.Options["clientId"]}: FAILED");
                Console.WriteLine($"  {Redactor.Clean(ex.Message)}");
                if (Hint(ex.Message) is { } hint)
                    Console.WriteLine($"  {hint}");
                return ExitCodes.Failed;
            }
            token = request.Headers.Authorization?.Parameter ?? throw new IntegrationException("The sign-in returned no token.");
        }

        var (_, expires, app) = GraphPermissions.Describe(token);
        var granted = GraphPermissions.Granted(token);
        Console.WriteLine($"Signed in to {record.Options["tenantId"]} as {app ?? "app " + record.Options["clientId"]}" +
                          $"{(expires is { } e ? $" (token until {e.ToLocalTime():HH:mm})" : "")}. Nothing was read from the tenant.");

        var report = Assess(RuleSources.Load(paths.TenantRules), granted);
        Print(report, granted);
        return ExitCodes.Ok;
    }

    /// <summary>One system's rules through Graph: how many can run with the permissions granted.</summary>
    public sealed record SystemReadiness(string System, int Rules, int Ready);

    public sealed record Readiness(IReadOnlyList<SystemReadiness> Systems,
        IReadOnlyList<(string Need, bool Confirm, IReadOnlyList<(string System, int Rules)> Blocked)> Missing, int Unmapped);

    /// <summary>For every Graph rule, whether the token's permissions cover what its request needs.</summary>
    public static Readiness Assess(RuleSet rules, IReadOnlySet<string> granted)
    {
        var systems = new List<SystemReadiness>();
        var missing = new Dictionary<string, (bool Confirm, Dictionary<string, int> Blocked)>(StringComparer.Ordinal);
        var unmapped = 0;
        foreach (var file in rules.Files.Where(f => f.Integration == "graph").GroupBy(f => f.System).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var total = 0;
            var ready = 0;
            foreach (var rule in file.SelectMany(f => f.Rules).Where(r => r.Query.Protocol == "graph"))
            {
                total++;
                var select = rule.Query.Fields["select"] is System.Text.Json.Nodes.JsonArray list
                    ? list.Select(v => v?.ToString() ?? "")
                    : (rule.Query.Text("select") ?? "").Split(',', StringSplitOptions.TrimEntries);
                var needs = GraphPermissions.Needs(rule.Query.Text("path") ?? "", select);
                if (needs is null)
                {
                    unmapped++;
                    continue;
                }
                var unmet = needs.Where(n => !n.MetBy(granted)).ToList();
                if (unmet.Count == 0)
                {
                    ready++;
                    continue;
                }
                foreach (var need in unmet)
                {
                    var entry = missing.TryGetValue(need.Text, out var found) ? found : (need.Confirm, new Dictionary<string, int>(StringComparer.Ordinal));
                    entry.Item2[file.Key] = entry.Item2.GetValueOrDefault(file.Key) + 1;
                    missing[need.Text] = entry;
                }
            }
            systems.Add(new SystemReadiness(file.Key, total, ready));
        }
        var ordered = missing
            .Select(m => (Need: m.Key, m.Value.Confirm, Blocked: (IReadOnlyList<(string, int)>)m.Value.Blocked.OrderBy(b => b.Key, StringComparer.Ordinal).Select(b => (b.Key, b.Value)).ToList()))
            .OrderByDescending(m => m.Blocked.Sum(b => b.Item2)).ThenBy(m => m.Need, StringComparer.Ordinal)
            .ToList();
        return new Readiness(systems, ordered, unmapped);
    }

    private static string Rules(int n) => n == 1 ? "1 rule" : $"{n} rules";

    private static void Print(Readiness report, IReadOnlySet<string> granted)
    {
        Console.WriteLine();
        Console.WriteLine("Ready to scan");
        foreach (var s in report.Systems)
            Console.WriteLine($"  {s.System,-12} {s.Ready,4} of {Rules(s.Rules),-10}{(s.Ready == s.Rules ? "" : "   (the rest record 'could not check' until the permissions below are granted)")}");
        Console.WriteLine();
        if (report.Missing.Count == 0)
        {
            Console.WriteLine($"Permissions: everything the rules need is granted ({granted.Count} in the token).");
        }
        else
        {
            Console.WriteLine("Missing permissions (grant them to the app, then admin-consent; 'keeper connect check' again)");
            foreach (var (need, confirm, blocked) in report.Missing)
                Console.WriteLine($"  {need,-48} {Rules(blocked.Sum(b => b.Rules)),10}: {string.Join(", ", blocked.Select(b => $"{b.System} {b.Rules}"))}" +
                                  (confirm ? "  (Microsoft documents this loosely; confirmed on the first scan)" : ""));
        }
        if (report.Unmapped > 0)
            Console.WriteLine($"{report.Unmapped} rule(s) read Graph paths the permission map does not list; their first scan tells.");
        Console.WriteLine();
        Console.WriteLine("Next: keeper run   (or keeper scan entra --plan to see what one scan costs first)");
    }

    private static int Permissions()
    {
        foreach (var permission in GraphPermissions.Recommended())
            Console.WriteLine(permission);
        return ExitCodes.Ok;
    }

    /// <summary>The Entra errors a first connection meets, said in what to do.</summary>
    public static string? Hint(string message) =>
        message.Contains("AADSTS700016", StringComparison.Ordinal) ? "The app id is not known in this tenant: check --client-id and --tenant."
        : message.Contains("AADSTS700027", StringComparison.Ordinal) || message.Contains("AADSTS700024", StringComparison.Ordinal)
            ? "The tenant does not accept this certificate: upload its public part (.cer) to the app under Certificates & secrets."
        : message.Contains("AADSTS90002", StringComparison.Ordinal) || message.Contains("AADSTS900023", StringComparison.Ordinal)
            ? "The tenant was not found: use the Directory (tenant) ID from the app's Overview page."
        : message.Contains("AADSTS7000112", StringComparison.Ordinal) ? "The app is disabled in this tenant."
        : message.Contains("AADSTS53003", StringComparison.Ordinal) ? "Conditional Access blocked the app's sign-in: exclude it, or allow it from this machine's address."
        : message.Contains("is not in CurrentUser", StringComparison.Ordinal) ? "Import the certificate with its private key into this user's store on this machine."
        : null;

    /// <summary>An enabled Graph integration other than <paramref name="name"/> that reads a different tenant, or null.</summary>
    public static IntegrationRecord? OtherTenant(IEnumerable<IntegrationRecord> integrations, string name, string tenant) =>
        integrations.FirstOrDefault(i => i.Type == "graph" && i.Enabled && i.Id != name
            && i.Options["tenantId"]?.ToString() is { } other && !string.Equals(other, tenant, StringComparison.OrdinalIgnoreCase));

    private static X509Certificate2? FindCertificate(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .FirstOrDefault(c => c.HasPrivateKey);
    }

    private static IReadOnlyList<IntegrationRecord> Integrations(KeeperPaths paths)
    {
        using var connection = new Database(paths.Database).OpenReadOnly();
        SchemaManager.EnsureCurrent(connection, [Vault.Schema, IntegrationStore.Schema]);
        return IntegrationStore.All(connection);
    }

    private static Vault LoadVault(KeeperPaths paths)
    {
        using var connection = new Database(paths.Database).OpenReadOnly();
        return Vault.Load(connection, KeyProtectors.Default(paths.SettingsDir));
    }

    private static string[] Passed(CliArgs cli, params string[] names) =>
        names.Where(n => cli.Get(n) is not null).SelectMany(n => new[] { "--" + n, cli.Get(n)! }).ToArray();
}
