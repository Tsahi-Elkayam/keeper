using System.Globalization;
using System.Text.Json;

namespace Keeper.Queue;

/// <summary>
/// How a producer asks for a write. The file is written to tmp\ and renamed into queue\,
/// so keeper-qm never reads half a file.
/// </summary>
public sealed class RequestWriter(string spoolDir, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <returns>The request id.</returns>
    public string Submit(string kind, string reason, JsonElement payload, string? submittedBy = null)
    {
        Spool.EnsureFolders(spoolDir);

        var now = _clock.GetUtcNow();
        var id = Guid.NewGuid().ToString("D");
        var envelope = new RequestEnvelope(id, kind, submittedBy ?? CurrentUser(), now, reason, payload);
        var name = $"{now.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture)}-{id}.json";

        var tmp = Path.Combine(spoolDir, Spool.Tmp, name);
        File.WriteAllText(tmp, JsonSerializer.Serialize(envelope, RequestEnvelope.Json));
        File.Move(tmp, Path.Combine(spoolDir, Spool.Queue, name));
        return id;
    }

    internal static string CurrentUser() => $"{Environment.UserDomainName}\\{Environment.UserName}";
}
