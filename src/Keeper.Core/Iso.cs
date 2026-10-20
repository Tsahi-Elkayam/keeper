using System.Globalization;

namespace Keeper.Core;

/// <summary>The one time format Keeper stores: ISO 8601, UTC, whole seconds.</summary>
public static class Iso
{
    public static string Utc(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
