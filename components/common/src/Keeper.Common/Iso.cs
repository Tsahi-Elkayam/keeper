using System.Globalization;

namespace Keeper.Common;

/// <summary>The one time format Keeper stores: ISO 8601, UTC, whole seconds.</summary>
public static class Iso
{
    public static string Utc(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static string Date(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>A timestamp safe for file and folder names: yyyyMMdd-HHmmss, UTC.</summary>
    public static string Stamp(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
}
