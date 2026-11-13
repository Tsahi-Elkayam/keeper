using System.Globalization;

namespace Keeper.Common;

/// <summary>Short durations as people write them in rule files: 30m, 6h, 1d, 7d, 2w.</summary>
public static class Durations
{
    public static bool TryParse(string? text, out TimeSpan duration)
    {
        duration = default;
        if (string.IsNullOrWhiteSpace(text) || text.Length < 2)
            return false;

        var unit = char.ToLowerInvariant(text[^1]);
        if (!int.TryParse(text[..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var amount) || amount <= 0)
            return false;

        duration = unit switch
        {
            'm' => TimeSpan.FromMinutes(amount),
            'h' => TimeSpan.FromHours(amount),
            'd' => TimeSpan.FromDays(amount),
            'w' => TimeSpan.FromDays(amount * 7),
            _ => default,
        };
        return duration > TimeSpan.Zero;
    }

    public static TimeSpan Parse(string text) =>
        TryParse(text, out var duration)
            ? duration
            : throw new FormatException($"'{text}' is not a duration; use a number and m, h, d or w (e.g. 30m, 1d).");
}
