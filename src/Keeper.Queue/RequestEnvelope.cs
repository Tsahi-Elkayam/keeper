using System.Text.Json;

namespace Keeper.Queue;

/// <summary>One write request. The payload's shape depends on <see cref="Kind"/>; its handler validates it.</summary>
public sealed record RequestEnvelope(
    string Id,
    string Kind,
    string SubmittedBy,
    DateTimeOffset SubmittedAt,
    string Reason,
    JsonElement Payload)
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static RequestEnvelope Parse(string text)
    {
        Dto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<Dto>(text, Json);
        }
        catch (JsonException ex)
        {
            throw new RequestException($"Not a valid request file: {ex.Message}");
        }

        if (dto is null)
            throw new RequestException("Empty request file.");
        if (!Guid.TryParse(dto.Id, out _))
            throw new RequestException("id must be a GUID.");
        if (string.IsNullOrWhiteSpace(dto.Kind))
            throw new RequestException("kind is required.");
        if (string.IsNullOrWhiteSpace(dto.SubmittedBy))
            throw new RequestException("submittedBy is required.");
        if (dto.SubmittedAt is null)
            throw new RequestException("submittedAt is required.");
        if (string.IsNullOrWhiteSpace(dto.Reason) || dto.Reason.Length > 500)
            throw new RequestException("reason is required: why, in 1 to 500 characters.");
        if (dto.Payload.ValueKind != JsonValueKind.Object)
            throw new RequestException("payload must be a JSON object.");

        return new RequestEnvelope(dto.Id!, dto.Kind, dto.SubmittedBy, dto.SubmittedAt.Value, dto.Reason, dto.Payload);
    }

    internal sealed class Dto
    {
        public string? Id { get; set; }
        public string? Kind { get; set; }
        public string? SubmittedBy { get; set; }
        public DateTimeOffset? SubmittedAt { get; set; }
        public string? Reason { get; set; }
        public JsonElement Payload { get; set; }
    }
}

public sealed class RequestException(string message) : Exception(message);

public sealed class QueueBusyException(string message) : Exception(message);
