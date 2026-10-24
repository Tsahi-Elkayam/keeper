using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Store;

namespace Keeper.Scan.Tests;

internal sealed class StoreConnection : IConnection
{
    public string Instance => "keeper";
    public string Type => "keeper";
    public string Endpoint => "";
    public string AuthKind => "none";
    public string? Identity => null;
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>The rule packs in the repo's rules\ folder, run against a real store built from every schema.</summary>
public sealed class ShippedRulesTests : IDisposable
{
    // Real time, whole seconds: the questions read julianday('now'), so the data must be relative to it.
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public ShippedRulesTests()
    {
        using var connection = Store.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Composition.Composition.Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Store => new(Path.Combine(_dir, "keeper.db"));

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static string RulesFolder
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                    return Path.Combine(dir.FullName, "rules");
            }
            throw new DirectoryNotFoundException("The repo's rules folder was not found above the test binaries.");
        }
    }

    private static RuleSet Shipped() => RuleLoader.LoadAll([(RulesFolder, "builtin")], Runners.Registry().Validators);

    private async Task<ScanReport> Scan(IReadOnlyList<RuleFile> files) =>
        await new Scanner(Runners.Registry(), new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = files,
            Connection = new StoreConnection(),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
            StoreFile = Store.DbFile,
        }, CancellationToken.None);

    private static string Ago(int days) => Iso.Utc(Now.AddDays(-days));

    private void Seen(string runId, string system, int startedDaysAgo, params (string Key, JsonObject Attrs)[] users)
    {
        using var connection = Store.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES (:id, :instance, :system, :at, :at, 'ok', :id, '{}', :at);
            """,
            null, (":id", runId), (":instance", system + "-1"), (":system", system), (":at", Ago(startedDaysAgo)));
        foreach (var (key, attrs) in users)
        {
            Sql.Execute(connection,
                """
                INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at)
                VALUES (:run, 'q-users', 'user', :key, NULL, :attrs, :at);
                """,
                null, (":run", runId), (":key", key), (":attrs", attrs.ToJsonString()), (":at", Ago(startedDaysAgo)));
        }
    }

    [Fact]
    public void No_shipped_rule_reads_win32_product_because_reading_it_makes_windows_re_check_every_package()
    {
        var offenders = Directory.EnumerateFiles(RulesFolder, "*.yaml")
            .Where(f => File.ReadAllText(f).Contains("Win32_Product", StringComparison.OrdinalIgnoreCase))
            .Select(Path.GetFileName)
            .ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Every_shipped_rule_file_loads_and_rule_ids_are_unique_across_them()
    {
        var rules = Shipped();

        Assert.NotEmpty(rules.Files);
        var ids = rules.Files.SelectMany(f => f.Rules).Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    // A baseline rule written for one kind of Windows host (-CLIENT / -SERVER) must say so, or it is judged on every host
    // and reports findings that do not apply to them.
    [Fact]
    public void Every_client_or_server_variant_rule_says_which_hosts_it_applies_to()
    {
        var variants = Shipped().Files.Where(f => f.System == "windows-baseline").SelectMany(f => f.Rules)
            .Where(r => r.Id.EndsWith("-CLIENT", StringComparison.Ordinal) || r.Id.EndsWith("-SERVER", StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(variants);
        Assert.Empty(variants.Where(r => r.Applies is null).Select(r => r.Id));
    }

    [Fact]
    public async Task Every_store_rule_runs_on_a_current_store_without_a_failed_query()
    {
        var storeFiles = Shipped().Files.Where(f => f.Integration == "keeper").ToList();

        var report = await Scan(storeFiles);

        Assert.Equal(0, report.FailedQueries);
        Assert.Equal("ok", report.Manifest.Status);
    }

    private static JsonObject Ad(string sid, string uac, string? logon, string created, string? mailbox = null, string? expires = null,
        string ou = "Staff")
    {
        var o = new JsonObject
        {
            ["objectSid"] = sid, ["userAccountControl"] = uac, ["whenCreated"] = created, ["accountExpires"] = expires ?? "9223372036854775807",
            ["distinguishedName"] = $"CN=x,OU={ou},DC=example,DC=org",
        };
        if (logon is not null)
            o["lastLogonTimestamp"] = logon;
        if (mailbox is not null)
            o["msExchRecipientTypeDetails"] = mailbox;
        return o;
    }

    private static JsonObject Cloud(string sid, string signIn) =>
        new() { ["onPremisesSecurityIdentifier"] = sid, ["signInActivity"] = new JsonObject { ["lastSuccessfulSignInDateTime"] = signIn } };

    private void SeedDirectories()
    {
        Seen("ad-run", "active-directory", 0,
            ("alice", Ad("S-1-5-21-9-1", "512", Ago(200), Ago(900))),          // cloud only: signed in to Entra 5 days ago
            ("bob", Ad("S-1-5-21-9-2", "512", Ago(200), Ago(900))),            // stale in both
            ("carol", Ad("S-1-5-21-9-3", "512", null, Ago(300))),              // never signed in, created long ago
            ("dave", Ad("S-1-5-21-9-4", "512", null, Ago(10))),                // new, not used yet
            ("erin", Ad("S-1-5-21-9-5", "514", Ago(900), Ago(1000))),          // disabled
            ("room1", Ad("S-1-5-21-9-6", "512", null, Ago(900), mailbox: "16")),   // room mailbox object
            ("frank", Ad("S-1-5-21-9-7", "512", Ago(5), Ago(900))),            // used this week
            ("gina", Ad("S-1-5-21-9-8", "512", Ago(400), Ago(900), expires: Ago(30))),    // expired
            ("hank", Ad("S-1-5-21-9-9", "512", Ago(300), Ago(900), ou: "Disabled Accounts")), // moved to the leavers OU, never disabled
            ("judy", Ad("S-1-5-21-9-10", "512", Ago(3), Ago(900), ou: "Disabled Accounts")),  // ... and still signing in
            ("MSOL_0123abcd", Ad("S-1-5-21-9-11", "512", null, Ago(900))));               // directory sync account
        Seen("entra-run", "entra", 0,
            ("alice@example.org", Cloud("S-1-5-21-9-1", Ago(5))),
            ("bob@example.org", Cloud("S-1-5-21-9-2", Ago(200))));
    }

    [Fact]
    public async Task A_user_is_stale_only_when_neither_directory_shows_a_sign_in()
    {
        SeedDirectories();

        var hybrid = Shipped().ForSystem("hybrid-identity");
        var report = await Scan(hybrid);

        var findings = JsonLines.Read<FindingRecord>(Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings)).ToList();
        Assert.Equal(new[] { "active-directory-1/bob", "active-directory-1/carol" },
            findings.Where(f => f.RuleId == "HYB-USER-STALE").Select(f => f.Target).Order(StringComparer.Ordinal));
        var cloudOnly = Assert.Single(findings, f => f.RuleId == "HYB-USER-CLOUD-ONLY-ACTIVITY");
        Assert.Contains("1 enabled accounts", cloudOnly.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void The_stale_users_question_explains_the_gap_between_domain_logons_and_the_truth()
    {
        SeedDirectories();
        var query = Composition.Composition.KeeperQuestions.Load().Single(q => q.Name == "stale-users");
        var output = new StringWriter();

        using (var connection = Store.OpenReadOnly())
            Query.QueryRunner.Run(connection, query, new Dictionary<string, string?>(), new Query.TableWriter(output));

        var text = output.ToString();
        // Every enabled account lands in exactly one bucket; only bob and carol are truly stale.
        Assert.Matches(@"01 disabled\s+1", text);
        Assert.Matches(@"02 shared, room or equipment mailbox object\s+1", text);
        Assert.Matches(@"03 expired\s+1", text);
        Assert.Matches(@"04 built-in or service account \(by name\)\s+1", text);
        Assert.Matches(@"05 in a leavers OU but enabled - STILL SIGNING IN\s+1", text);
        Assert.Matches(@"06 in a leavers OU but enabled\s+1", text);
        Assert.Matches(@"07 active: domain logon\s+1\s+0", text);
        Assert.Matches(@"08 active: cloud sign-in only\s+1\s+1", text);      // a domain-logon report would call alice stale
        Assert.Matches(@"09 new, not used yet\s+1", text);
        Assert.Matches(@"11 stale: never signed in anywhere\s+1", text);
        Assert.Matches(@"13 stale: last sign-in in the window to a year ago\s+1", text);
    }
}
