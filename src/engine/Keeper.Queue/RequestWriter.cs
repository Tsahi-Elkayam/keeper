using System.Globalization;
using System.Text.Json;

namespace Keeper.Queue;

/// <summary>
/// How a producer asks for a write. The file is written to tmp\ and renamed into queue\, so the
/// queue manager never reads half a file. Names sort in submission order.
/// </summary>
public sealed class RequestWriter(string spoolDir, TimeProvider? clock = null)
{
    private static int _sequence;
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <returns>The request id.</returns>
    public string Submit(string kind, string reason, JsonElement payload, string? submittedBy = null)
    {
        Spool.EnsureFolders(spoolDir);

        var now = _clock.GetUtcNow();
        var id = Guid.NewGuid().ToString("D");
        var envelope = new RequestEnvelope(id, kind, submittedBy ?? CurrentUser(), now, reason, payload);
        var sequence = Interlocked.Increment(ref _sequence) % 1_000_000;
        var name = $"{now.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture)}-{sequence:D6}-{id}.json";

        var tmp = Path.Combine(spoolDir, Spool.Tmp, name);
        File.WriteAllText(tmp, JsonSerializer.Serialize(envelope, RequestEnvelope.Json));
        File.Move(tmp, Path.Combine(spoolDir, Spool.Queue, name));
        return id;
    }

    /// <summary>Serialises <paramref name="payload"/> (any object) as the request payload.</summary>
    public string Submit<T>(string kind, string reason, T payload, string? submittedBy = null) where T : notnull =>
        Submit(kind, reason, JsonSerializer.SerializeToElement(payload, RequestEnvelope.Json), submittedBy);

    public static string CurrentUser() => $"{Environment.UserDomainName}\\{Environment.UserName}";
}
