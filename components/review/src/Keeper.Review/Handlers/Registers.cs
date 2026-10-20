using System.Text.Json;
using Keeper.Queue;

namespace Keeper.Review.Handlers;

public enum FieldType { Text, Date, Int, Real, Bool, Choice }

/// <summary>One payload field of a register and the column it lands in. Columns are code, never input.</summary>
/// <param name="Default">The value an upsert writes when the field is absent (booleans default to false).</param>
public sealed record RegisterField(string Name, string Column, FieldType Type, bool Required = false, string[]? Choices = null, object? Default = null);

public sealed record RegisterSpec(string Kind, string Table, string IdColumn, string IdField, IReadOnlyList<RegisterField> Fields);

/// <summary>
/// The registers people keep - vendors, contracts, licences, key dates, saving initiatives. One generic
/// handler per register: { "op": "upsert", "&lt;id&gt;", ...fields } or { "op": "remove", "&lt;id&gt;" }.
/// </summary>
public static class Registers
{
    public static readonly RegisterSpec Vendor = new("review.vendor", "vendor", "vendor_id", "vendorId",
    [
        new("name", "name", FieldType.Text, Required: true),
        new("state", "state", FieldType.Choice, Choices: ["candidate", "confirmed", "rejected"], Default: "confirmed"),
        new("soleVendor", "sole_vendor", FieldType.Bool),
        new("exitPlan", "exit_plan", FieldType.Text),
        new("sla", "sla", FieldType.Text),
        new("dataHandled", "data_handled", FieldType.Text),
        new("sensitive", "sensitive", FieldType.Bool),
        new("securityReviewOn", "security_review_on", FieldType.Date),
        new("notes", "notes", FieldType.Text),
    ]);

    public static readonly RegisterSpec Contract = new("review.contract", "contract", "contract_id", "contractId",
    [
        new("title", "title", FieldType.Text, Required: true),
        new("vendorId", "vendor_id", FieldType.Text),
        new("systemId", "system_id", FieldType.Text),
        new("startOn", "start_on", FieldType.Date),
        new("endOn", "end_on", FieldType.Date),
        new("noticeDays", "notice_days", FieldType.Int, Default: 90L),
        new("value", "value", FieldType.Real),
        new("currency", "currency", FieldType.Text),
        new("decision", "decision", FieldType.Choice, Choices: ["renew", "replace", "end", "undecided"]),
        new("owner", "owner", FieldType.Text),
        new("notes", "notes", FieldType.Text),
    ]);

    public static readonly RegisterSpec Licence = new("review.licence", "licence", "licence_id", "licenceId",
    [
        new("product", "product", FieldType.Text, Required: true),
        new("vendorId", "vendor_id", FieldType.Text),
        new("systemId", "system_id", FieldType.Text),
        new("seats", "seats", FieldType.Int),
        new("seatsUsed", "seats_used", FieldType.Int),
        new("expiresOn", "expires_on", FieldType.Date),
        new("noticeDays", "notice_days", FieldType.Int, Default: 60L),
        new("autoRenews", "auto_renews", FieldType.Bool),
        new("cost", "cost", FieldType.Real),
        new("currency", "currency", FieldType.Text),
        new("owner", "owner", FieldType.Text),
        new("notes", "notes", FieldType.Text),
    ]);

    public static readonly RegisterSpec KeyDate = new("review.key-date", "key_date", "key_date_id", "keyDateId",
    [
        new("kind", "kind", FieldType.Choice, Required: true,
            Choices: ["contract", "renewal", "licence", "certificate", "report", "maintenance", "price-change", "other"]),
        new("title", "title", FieldType.Text, Required: true),
        new("dueOn", "due_on", FieldType.Date, Required: true),
        new("noticeDays", "notice_days", FieldType.Int, Default: 14L),
        new("systemId", "system_id", FieldType.Text),
        new("owner", "owner", FieldType.Text),
        new("notes", "notes", FieldType.Text),
    ]);

    public static readonly RegisterSpec Initiative = new("review.initiative", "initiative", "initiative_id", "initiativeId",
    [
        new("title", "title", FieldType.Text, Required: true),
        new("owner", "owner", FieldType.Text),
        new("status", "status", FieldType.Choice, Required: true, Choices: ["proposed", "approved", "in-progress", "done", "dropped"]),
        new("savingMonthly", "saving_monthly", FieldType.Real),
        new("currency", "currency", FieldType.Text),
        new("measured", "measured", FieldType.Choice, Choices: ["bill", "estimate"]),
        new("notes", "notes", FieldType.Text),
    ]);

    public static readonly IReadOnlyList<RegisterSpec> All = [Vendor, Contract, Licence, KeyDate, Initiative];

    public static IEnumerable<IRequestHandler> Handlers() => All.Select(s => new RegisterRecordHandler(s));
}

public sealed class RegisterRecordHandler(RegisterSpec spec) : IRequestHandler
{
    public string Kind => spec.Kind;

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var id = Payload.Required(payload, spec.IdField);
        if (!Identifiers.IsRecordId(id))
            throw new RequestException($"payload.{spec.IdField} must be letters, digits, dots, dashes or underscores.");

        if (Payload.OneOf(payload, "op", "upsert", "remove") == "remove")
        {
            if (context.Execute($"DELETE FROM {spec.Table} WHERE {spec.IdColumn} = :id;", (":id", id)) == 0)
                throw new RequestException($"No {spec.Table} {id}.");
            return;
        }

        var parameters = new List<(string, object?)> { (":id", id), (":actor", context.Request.SubmittedBy), (":at", context.NowText) };
        foreach (var field in spec.Fields)
            parameters.Add((":" + field.Column, Read(payload, field)));

        var columns = string.Join(", ", spec.Fields.Select(f => f.Column));
        var values = string.Join(", ", spec.Fields.Select(f => ":" + f.Column));
        var updates = string.Join(", ", spec.Fields.Select(f => $"{f.Column} = excluded.{f.Column}"));
        context.Execute(
            $"""
            INSERT INTO {spec.Table} ({spec.IdColumn}, {columns}, updated_by, updated_at)
            VALUES (:id, {values}, :actor, :at)
            ON CONFLICT ({spec.IdColumn}) DO UPDATE SET {updates}, updated_by = excluded.updated_by, updated_at = excluded.updated_at;
            """,
            [.. parameters]);
    }

    private static object? Read(JsonElement payload, RegisterField field)
    {
        var present = payload.TryGetProperty(field.Name, out var raw) && raw.ValueKind != JsonValueKind.Null;
        if (!present)
        {
            if (field.Required)
                throw new RequestException($"payload.{field.Name} is required.");
            // An upsert writes every column, so an absent field takes its declared default.
            return field.Default ?? (field.Type == FieldType.Bool ? 0 : null);
        }

        switch (field.Type)
        {
            case FieldType.Text:
                return raw.ValueKind == JsonValueKind.String && raw.GetString()!.Length <= 2000
                    ? raw.GetString()
                    : throw new RequestException($"payload.{field.Name} must be text of at most 2000 characters.");
            case FieldType.Date:
                return Payload.Date(payload, field.Name);
            case FieldType.Int:
                return raw.ValueKind == JsonValueKind.Number && raw.TryGetInt64(out var integer)
                    ? integer
                    : throw new RequestException($"payload.{field.Name} must be a whole number.");
            case FieldType.Real:
                return raw.ValueKind == JsonValueKind.Number
                    ? raw.GetDouble()
                    : throw new RequestException($"payload.{field.Name} must be a number.");
            case FieldType.Bool:
                return raw.ValueKind switch
                {
                    JsonValueKind.True => 1,
                    JsonValueKind.False => 0,
                    _ => throw new RequestException($"payload.{field.Name} must be true or false."),
                };
            case FieldType.Choice:
                var choice = raw.ValueKind == JsonValueKind.String ? raw.GetString() : null;
                return choice is not null && field.Choices!.Contains(choice, StringComparer.Ordinal)
                    ? choice
                    : throw new RequestException($"payload.{field.Name} must be one of: {string.Join(", ", field.Choices!)}.");
            default:
                throw new RequestException($"payload.{field.Name}: unsupported field type.");
        }
    }
}
