using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Push;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Store;
using Keeper.Vault;
using Microsoft.Data.Sqlite;

// keeper-push: tickets in ServiceNow or monday.com for findings handed off to someone.
// The only Keeper binary that changes anything outside Keeper. By default it only shows the plan;
// 'apply' opens tickets after you type the confirmation at the keyboard.
try
{
    var cli = new CliArgs(args);
    if (cli.Help)
        return Usage(asked: true);
    var command = cli.At(0) ?? "plan";
    var tracker = cli.Get("tracker") ?? "servicenow";
    var (_, paths) = KeeperContext.Load(cli);
    var writer = new RequestWriter(paths.Spool);

    IntegrationRecord record;
    Vault? vault;
    IReadOnlyList<PushItem> plan;
    List<Dictionary<string, object?>> refs;
    using (var connection = new Database(paths.Database).OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, PushComponent.Schema, Vault.Schema, IntegrationStore.Schema]);
        record = IntegrationStore.Resolve(connection, tracker, cli.Get("integration"));
        vault = record.Secrets.Count > 0 ? Vault.Load(connection, KeyProtectors.Default()) : null;
        plan = PushComponent.Plan(connection, tracker, cli.All("finding"));
        refs = Sql.Rows(connection, "SELECT finding_key, ext_id FROM finding_ref WHERE tracker = :t AND closed_at IS NULL;", null, (":t", tracker));
    }
    using var link = new IntegrationConnection(record, vault);
    var target = PushComponent.Tracker(tracker, link);

    switch (command)
    {
        case "plan":
            Print(plan, tracker, record.Id);
            Console.WriteLine(plan.Count == 0 ? "Nothing to open." : "Dry run: nothing was sent. 'keeper push apply' opens them after you confirm.");
            return ExitCodes.Ok;

        case "apply":
            Print(plan, tracker, record.Id);
            if (plan.Count == 0)
                return ExitCodes.Ok;
            if (Console.IsInputRedirected || !Environment.UserInteractive)
                throw new ArgumentException("Opening tickets needs a person at the keyboard to confirm; this session has none.");
            Console.Write($"This opens {plan.Count} ticket(s) in {tracker} ({record.Endpoint}). Type CREATE {plan.Count} to go on: ");
            if (Console.ReadLine()?.Trim() != $"CREATE {plan.Count}")
            {
                Console.WriteLine("Not confirmed; nothing was sent.");
                return ExitCodes.Ok;
            }
            var failed = 0;
            foreach (var item in plan)
            {
                try
                {
                    var ticket = await target.OpenAsync(item, CancellationToken.None);
                    writer.Submit("push.record", $"Ticket for {item.FindingKey[..8]}", new
                    {
                        findingKey = item.FindingKey, tracker, integration = record.Id, extId = ticket.ExtId, url = ticket.Url, status = "sent",
                    });
                    Console.WriteLine($"  opened {ticket.ExtId}: {item.Title}");
                }
                catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or IntegrationException or TaskCanceledException)
                {
                    failed++;
                    writer.Submit("push.record", $"Ticket for {item.FindingKey[..8]} failed", new
                    {
                        findingKey = item.FindingKey, tracker, integration = record.Id, status = "failed", detail = Redactor.Clean(ex.Message),
                    });
                    Console.Error.WriteLine($"  failed: {item.Title}: {Redactor.Clean(ex.Message)}");
                }
            }
            Console.WriteLine("Recorded. 'keeper qm run' links the tickets to their findings.");
            return failed > 0 ? ExitCodes.Failed : ExitCodes.Ok;

        case "sync":
            var closed = 0;
            foreach (var r in refs)
            {
                var status = await target.StatusAsync((string)r["ext_id"]!, CancellationToken.None);
                if (status is not { Status: "closed" } s)
                    continue;
                writer.Submit("push.ref-status", "Ticket closed in the tracker", new
                {
                    findingKey = (string)r["finding_key"]!, tracker, extId = (string)r["ext_id"]!, status = "closed", closedAt = s.ClosedAt,
                });
                closed++;
            }
            Console.WriteLine($"{refs.Count} open ticket(s) checked, {closed} closed in {tracker}. A closed ticket marks its finding claimed-fixed; only a passing check resolves it.");
            return ExitCodes.Ok;

        default:
            return Usage();
    }
}
catch (Exception ex) when (ex is ArgumentException or SettingsException or IntegrationException or VaultException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static int Usage(bool asked = false) =>
    CliUsage.Print("""
        keeper-push - tickets for findings handed off to someone (the only binary that changes anything outside Keeper)

          keeper-push plan  [--tracker servicenow|monday] [--finding <key-prefix> ...]   what would be opened (default)
          keeper-push apply [--tracker ...] [--finding ...]                              open them, after you confirm
          keeper-push sync  [--tracker ...]                                              read ticket states back: a closed
                                                                                         ticket marks its finding claimed-fixed;
                                                                                         only a passing check resolves it
          --integration <id>   which integration, when there are several of the tracker's type
        """, asked);

static void Print(IReadOnlyList<PushItem> plan, string tracker, string integration)
{
    Console.WriteLine($"{plan.Count} finding(s) to ticket in {tracker} via {integration}:");
    foreach (var item in plan)
        Console.WriteLine($"  [{item.Severity}] {item.Title} - {item.SystemId} / {item.Target}{(item.Owner is null ? "" : $" (with {item.Owner})")}");
}
