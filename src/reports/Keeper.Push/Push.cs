using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Queue;
using Keeper.Runners;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Push;

public sealed record PushItem(string FindingKey, string Title, string Severity, string SystemId, string Target, string? Evidence,
    string? Fix, string? Owner, string? Deadline);

public sealed record Ticket(string ExtId, string? Url, string Status);

/// <summary>An outside tracker Keeper may open tickets in. The only component that writes outside Keeper.</summary>
public interface ITracker
{
    string Kind { get; }

    Task<Ticket> OpenAsync(PushItem item, CancellationToken cancellationToken);

    /// <summary>The ticket's current state (read-only), or null when the tracker cannot tell.</summary>
    Task<(string Status, string? ClosedAt)?> StatusAsync(string extId, CancellationToken cancellationToken);
}

public static class PushComponent
{
    public static MigrationSet Schema { get; } = MigrationSet.FromResources("push", typeof(PushComponent).Assembly, "push/", "review");

    public static IReadOnlyList<IRequestHandler> Handlers() => [new RecordHandler(), new RefStatusHandler()];

    /// <summary>
    /// Findings to ticket: handed off (delegated) and open, on a system routed to this tracker, without a
    /// ticket there yet - or exactly the keys asked for.
    /// </summary>
    public static IReadOnlyList<PushItem> Plan(SqliteConnection connection, string tracker, IReadOnlyCollection<string>? keys)
    {
        var rows = Sql.Rows(connection,
            """
            SELECT f.finding_key, f.title, f.severity, f.system_id, f.target, f.evidence, f.fix, f.delegated_to, f.deadline, s.route
            FROM active_finding f
            LEFT JOIN system s ON s.system_id = f.system_id
            WHERE NOT EXISTS (SELECT 1 FROM finding_ref r WHERE r.finding_key = f.finding_key AND r.tracker = :t AND r.closed_at IS NULL);
            """, null, (":t", tracker));
        return rows
            .Where(r => keys is { Count: > 0 }
                ? keys.Any(k => ((string)r["finding_key"]!).StartsWith(k, StringComparison.OrdinalIgnoreCase))
                : r["delegated_to"] is string && string.Equals(r["route"] as string, tracker, StringComparison.OrdinalIgnoreCase))
            .Select(r => new PushItem((string)r["finding_key"]!, (string)r["title"]!, (string)r["severity"]!, (string)r["system_id"]!,
                (string)r["target"]!, r["evidence"] as string, r["fix"] as string, r["delegated_to"] as string, r["deadline"] as string))
            .ToList();
    }

    public static ITracker Tracker(string kind, IConnection connection) => kind switch
    {
        "servicenow" => new ServiceNowTracker(connection),
        "monday" => new MondayTracker(connection),
        _ => throw new ArgumentException($"Keeper can open tickets in: servicenow, monday. Not in {kind}."),
    };

    internal static HttpClient Client(IConnection connection, out Uri endpoint)
    {
        if (!Uri.TryCreate(connection.Endpoint, UriKind.Absolute, out var parsed) || parsed.Scheme != "https")
            throw new InvalidOperationException($"{connection.Instance}: the tracker endpoint must be https.");
        endpoint = parsed;
        return new HttpClient(new HostPinningHandler(parsed, connection.CreateHttpHandler())) { Timeout = TimeSpan.FromSeconds(60) };
    }

    internal static string Description(PushItem item) =>
        string.Join("\n", new[]
        {
            $"Found by Keeper on {item.SystemId} / {item.Target}.",
            item.Evidence is null ? null : $"Evidence: {item.Evidence}",
            item.Fix is null ? null : $"Fix: {item.Fix}",
            item.Deadline is null ? null : $"Deadline: {item.Deadline}",
            $"Keeper finding: {item.FindingKey}",
        }.Where(l => l is not null));
}

/// <summary>ServiceNow: an incident per finding, correlated by the finding key so a retry never duplicates.</summary>
public sealed class ServiceNowTracker(IConnection connection) : ITracker
{
    public string Kind => "servicenow";

    public async Task<Ticket> OpenAsync(PushItem item, CancellationToken cancellationToken)
    {
        using var client = PushComponent.Client(connection, out var endpoint);
        var body = new JsonObject
        {
            ["short_description"] = $"[Keeper] {item.Title}".Length > 160 ? $"[Keeper] {item.Title}"[..160] : $"[Keeper] {item.Title}",
            ["description"] = PushComponent.Description(item),
            ["urgency"] = item.Severity switch { "critical" => "1", "high" => "2", _ => "3" },
            ["impact"] = item.Severity switch { "critical" => "1", "high" => "2", _ => "3" },
            ["correlation_id"] = item.FindingKey,
            ["correlation_display"] = "Keeper",
        };
        if (connection.Options["assignmentGroup"]?.ToString() is { Length: > 0 } group)
            body["assignment_group"] = group;

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint, "/api/now/table/incident"))
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        await connection.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"ServiceNow answered {(int)response.StatusCode}.");
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false))?["result"];
        var sysId = result?["sys_id"]?.ToString() ?? throw new HttpRequestException("ServiceNow returned no sys_id.");
        return new Ticket(sysId, new Uri(endpoint, $"/nav_to.do?uri=incident.do?sys_id={sysId}").ToString(), "open");
    }

    public async Task<(string Status, string? ClosedAt)?> StatusAsync(string extId, CancellationToken cancellationToken)
    {
        using var client = PushComponent.Client(connection, out var endpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(endpoint, $"/api/now/table/incident/{Uri.EscapeDataString(extId)}?sysparm_fields=state,closed_at,resolved_at"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        await connection.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return null;
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false))?["result"];
        var state = result?["state"]?.ToString();
        var closedAt = result?["closed_at"]?.ToString() is { Length: > 0 } c ? c : result?["resolved_at"]?.ToString() is { Length: > 0 } r ? r : null;
        // Incident states 6 (Resolved) and 7 (Closed) count as done.
        return state is "6" or "7" ? ("closed", closedAt ?? DateTimeOffset.UtcNow.ToString("o")) : ("open", null);
    }
}

/// <summary>monday.com: an item per finding on the integration's board (option boardId).</summary>
public sealed class MondayTracker(IConnection connection) : ITracker
{
    public string Kind => "monday";

    public async Task<Ticket> OpenAsync(PushItem item, CancellationToken cancellationToken)
    {
        var board = connection.Options["boardId"]?.ToString() ?? throw new InvalidOperationException($"{connection.Instance} needs the option boardId.");
        using var client = PushComponent.Client(connection, out var endpoint);
        var body = new JsonObject
        {
            ["query"] = "mutation ($board: ID!, $name: String!) { create_item (board_id: $board, item_name: $name) { id } }",
            ["variables"] = new JsonObject { ["board"] = board, ["name"] = $"[Keeper] {item.Title} - {item.Target}" },
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        await connection.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"monday.com answered {(int)response.StatusCode}.");
        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        var id = json?["data"]?["create_item"]?["id"]?.ToString() ?? throw new HttpRequestException("monday.com returned no item id.");
        return new Ticket(id, null, "open");
    }

    public Task<(string Status, string? ClosedAt)?> StatusAsync(string extId, CancellationToken cancellationToken) =>
        Task.FromResult<(string, string?)?>(null);   // board status columns differ per board; not read
}

/// <summary>push.record: { "findingKey", "tracker", "integration", "extId", "url", "status": "sent|failed", "detail" }.</summary>
public sealed class RecordHandler : IRequestHandler
{
    public string Kind => "push.record";

    public void Apply(RequestContext context)
    {
        var p = context.Request.Payload;
        var key = Payload.Required(p, "findingKey");
        var tracker = Payload.OneOf(p, "tracker", "servicenow", "monday");
        var status = Payload.OneOf(p, "status", "sent", "failed");
        var extId = Payload.Text(p, "extId");
        context.Execute(
            """
            INSERT INTO outbound (finding_key, tracker, integration, op, ext_id, url, status, detail, actor, at)
            VALUES (:k, :t, :i, 'open', :ext, :url, :s, :d, :by, :at);
            """,
            (":k", key), (":t", tracker), (":i", Payload.Required(p, "integration")), (":ext", extId), (":url", Payload.Text(p, "url")),
            (":s", status), (":d", Payload.Text(p, "detail")), (":by", context.Request.SubmittedBy), (":at", context.NowText));
        if (status == "sent" && extId is not null)
        {
            context.Execute(
                """
                INSERT INTO finding_ref (finding_key, tracker, ext_id, status, url, opened_at) VALUES (:k, :t, :ext, 'open', :url, :at)
                ON CONFLICT (finding_key, tracker, ext_id) DO NOTHING;
                """,
                (":k", key), (":t", tracker), (":ext", extId), (":url", Payload.Text(p, "url")), (":at", context.NowText));
        }
    }
}

/// <summary>push.ref-status: { "findingKey", "tracker", "extId", "status": "open|closed", "closedAt" } - read back from the tracker.</summary>
public sealed class RefStatusHandler : IRequestHandler
{
    public string Kind => "push.ref-status";

    public void Apply(RequestContext context)
    {
        var p = context.Request.Payload;
        var status = Payload.OneOf(p, "status", "open", "closed");
        var changed = context.Execute(
            "UPDATE finding_ref SET status = :s, closed_at = :c WHERE finding_key = :k AND tracker = :t AND ext_id = :ext;",
            (":s", status), (":c", status == "closed" ? Payload.Text(p, "closedAt") ?? context.NowText : null),
            (":k", Payload.Required(p, "findingKey")), (":t", Payload.Required(p, "tracker")), (":ext", Payload.Required(p, "extId")));
        if (changed == 0)
            throw new RequestException("No such ticket reference.");
    }
}
