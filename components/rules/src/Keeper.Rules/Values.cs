using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keeper.Rules;

/// <summary>How rule conditions read values: text, numbers, booleans, and dates in the formats estates use.</summary>
public static class Values
{
    public static string? Text(JsonNode? node) => node switch
    {
        null => null,
        JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
        JsonValue v when v.GetValueKind() is JsonValueKind.True or JsonValueKind.False => v.GetValue<bool>() ? "true" : "false",
        JsonValue v when v.GetValueKind() == JsonValueKind.Null => null,
        JsonValue v => v.ToJsonString(),
        _ => node.ToJsonString(),
    };

    public static bool TryNumber(JsonNode? node, out double number) => TryNumber(Text(node), out number);

    public static bool TryNumber(string? text, out double number)
    {
        number = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        if (text is "true" or "True")
        {
            number = 1;
            return true;
        }
        if (text is "false" or "False")
            return true;
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number);
    }

    public static bool TryLong(string? text, out long number) =>
        long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out number);

    /// <summary>
    /// ISO 8601 (with or without time), Windows FILETIME (0 = never happened, max = never expires) and
    /// LDAP generalized time (yyyyMMddHHmmss.0Z). Never-happened is MinValue; never-expires is MaxValue.
    /// </summary>
    public static bool TryDate(string? text, out DateTimeOffset date)
    {
        date = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        text = text.Trim();

        if (text.Length >= 15 && text.All(char.IsAsciiDigit) && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var fileTime))
        {
            date = fileTime switch
            {
                0 => DateTimeOffset.MinValue,
                long.MaxValue => DateTimeOffset.MaxValue,
                _ => fileTime >= DateTime.MaxValue.ToFileTimeUtc() ? DateTimeOffset.MaxValue : new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime)),
            };
            // "Never" is 0 or the largest value; anything else before 1980 is an id or a count, not a time.
            return date == DateTimeOffset.MinValue || date == DateTimeOffset.MaxValue || date.Year >= 1980;
        }
        if (text == "0")
        {
            date = DateTimeOffset.MinValue;
            return true;
        }
        // Unix time: 13 digits in milliseconds (Dynatrace, many REST APIs), 10 in seconds; /Date(ms)/ in old JSON.
        if (text.StartsWith("/Date(", StringComparison.Ordinal) && text.EndsWith(")/", StringComparison.Ordinal))
            text = new string(text[6..^2].TakeWhile(c => char.IsAsciiDigit(c) || c == '-').ToArray());
        // Only between 2000 and 2100: a 10-digit id or byte count is not a date.
        if (text.Length is 10 or 13 && text.All(char.IsAsciiDigit) && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var epoch))
        {
            var seconds = text.Length == 13 ? epoch / 1000 : epoch;
            if (seconds is < 946_684_800 or > 4_102_444_800)
                return false;
            date = text.Length == 13 ? DateTimeOffset.FromUnixTimeMilliseconds(epoch) : DateTimeOffset.FromUnixTimeSeconds(epoch);
            return true;
        }
        if (text.Length >= 14 && text[..14].All(char.IsAsciiDigit)
            && DateTime.TryParseExact(text[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var generalized))
        {
            date = new DateTimeOffset(generalized, TimeSpan.Zero);
            return true;
        }
        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out date);
    }

    /// <summary>
    /// A dotted version: "10.0.19045.3803", "v8.1", "2.4.1-beta". Missing parts compare as 0, so 10.0 equals
    /// 10.0.0; a pre-release ("-beta") is below its release; "+build" is ignored. False for anything with a
    /// non-numeric part - and for a "-" after a bare number, which is a date (2026-10-21), not a version.
    /// </summary>
    public static bool TryVersion(string? text, out Version parsed)
    {
        parsed = new Version([], false);
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var trimmed = text.Trim().TrimStart('v', 'V').Split('+')[0];
        var dash = trimmed.IndexOf('-', StringComparison.Ordinal);
        var core = dash < 0 ? trimmed : trimmed[..dash];
        if (dash >= 0 && !core.Contains('.', StringComparison.Ordinal))
            return false;
        var pieces = core.Split('.');
        var numbers = new long[pieces.Length];
        for (var i = 0; i < pieces.Length; i++)
        {
            if (!long.TryParse(pieces[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
                return false;
        }
        parsed = new Version(numbers, dash >= 0);
        return true;
    }

    public sealed record Version(long[] Parts, bool PreRelease);

    public static int CompareVersions(Version a, Version b)
    {
        for (var i = 0; i < Math.Max(a.Parts.Length, b.Parts.Length); i++)
        {
            var (x, y) = (i < a.Parts.Length ? a.Parts[i] : 0, i < b.Parts.Length ? b.Parts[i] : 0);
            if (x != y)
                return x.CompareTo(y);
        }
        return a.PreRelease == b.PreRelease ? 0 : a.PreRelease ? -1 : 1;
    }

    /// <summary>
    /// A length of time in days: ISO 8601 (P90D, PT8H, P1DT12H, P2W) or .NET's d.hh:mm:ss. Years and months have
    /// no fixed length and a negative length no meaning here, so both are refused.
    /// </summary>
    public static bool TryDays(string? text, out double days)
    {
        days = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        text = text.Trim();
        if (text.StartsWith('-'))
            return false;
        if (text.StartsWith('P'))
        {
            var datePart = text.Split('T')[0];
            if (datePart.Contains('Y', StringComparison.Ordinal) || datePart.Contains('M', StringComparison.Ordinal))
                return false;
            if (datePart.EndsWith('W') && double.TryParse(datePart[1..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var weeks) && !text.Contains('T', StringComparison.Ordinal))
            {
                days = weeks * 7;
                return true;
            }
            try
            {
                days = System.Xml.XmlConvert.ToTimeSpan(text).TotalDays;
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (OverflowException)
            {
                return false;
            }
        }
        if (text.Contains(':', StringComparison.Ordinal) && TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out var span) && span >= TimeSpan.Zero)
        {
            days = span.TotalDays;
            return true;
        }
        return false;
    }

    /// <summary>A literal yyyy-MM-dd that is a real date.</summary>
    public static bool IsLiteralDate(string? text) =>
        text is { Length: 10 } && DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    /// <summary>Days from <paramref name="date"/> to now; infinite for never-happened, minus infinite for never-expires.</summary>
    public static double AgeDays(DateTimeOffset date, DateTimeOffset now) =>
        date == DateTimeOffset.MinValue ? double.PositiveInfinity
        : date == DateTimeOffset.MaxValue ? double.NegativeInfinity
        : (now - date).TotalDays;

    public static double DaysLeft(DateTimeOffset date, DateTimeOffset now) => -AgeDays(date, now);

    public static string? IsoDate(string? text) =>
        TryDate(text, out var date) && date != DateTimeOffset.MinValue && date != DateTimeOffset.MaxValue
            ? date.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : null;
}
