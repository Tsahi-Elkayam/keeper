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
    /// A date in the format a condition names (format:), for values the automatic reading would miss or
    /// misread: ole (OLE Automation days, as Excel and some exports write them), unix or unix-ms (any year),
    /// or a .NET custom format such as dd/MM/yyyy HH:mm - read as UTC unless the format carries an offset.
    /// 0 is never-happened in the numeric formats, as a FILETIME 0 is. No format: <see cref="TryDate(string?, out DateTimeOffset)"/>.
    /// </summary>
    public static bool TryDate(string? text, string? format, out DateTimeOffset date)
    {
        if (format is null)
            return TryDate(text, out date);
        date = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        text = text.Trim();
        switch (format)
        {
            case "ole":
                // DateTime.FromOADate's own range: 100-01-01 to 9999-12-31.
                if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var days) || !double.IsFinite(days) || days is < -657434 or > 2958465)
                    return false;
                date = days == 0 ? DateTimeOffset.MinValue : new DateTimeOffset(DateTime.SpecifyKind(DateTime.FromOADate(days), DateTimeKind.Utc));
                return true;
            case "unix":
            case "unix-ms":
                if (!long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var epoch))
                    return false;
                try
                {
                    date = epoch == 0 ? DateTimeOffset.MinValue
                        : format == "unix" ? DateTimeOffset.FromUnixTimeSeconds(epoch) : DateTimeOffset.FromUnixTimeMilliseconds(epoch);
                    return true;
                }
                catch (ArgumentOutOfRangeException)
                {
                    return false;
                }
            default:
                return DateTimeOffset.TryParseExact(text, format, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out date);
        }
    }

    /// <summary>
    /// A format: value a condition can name: ole, unix, unix-ms, or a custom format that writes and reads back a
    /// whole date - year included, in any year, or a year-less format would read every date as this year's. For
    /// an hour of the day (<paramref name="timeOfDay"/>), a time alone (HH:mm) is enough.
    /// </summary>
    public static bool IsDateFormat(string? format, bool timeOfDay = false)
    {
        if (format is "ole" or "unix" or "unix-ms")
            return true;
        if (string.IsNullOrWhiteSpace(format) || format.Length > 64)
            return false;
        try
        {
            DateTimeOffset[] samples = [new(2026, 11, 23, 14, 35, 0, TimeSpan.Zero), new(1999, 2, 3, 9, 5, 0, TimeSpan.Zero)];
            return samples.All(sample => TryDate(sample.ToString(format, CultureInfo.InvariantCulture), format, out var back)
                                         && (timeOfDay ? back.Hour == sample.Hour : back.Date == sample.Date));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether a time names its instant (UTC or an offset: true), only the clock time as written (false), or
    /// cannot be told (null). Decided by what the parser read, not by the text's shape: FILETIME, Unix time,
    /// LDAP generalized time and /Date()/ are instants; text with Z, UTC, GMT or an offset is an instant;
    /// "2026-10-19 23:30" or an OLE day number is someone's clock - for an hour of the day, the organisation's.
    /// </summary>
    public static bool? NamesInstant(string text, string? format)
    {
        var t = text.Trim();
        switch (format)
        {
            case "unix" or "unix-ms":
                return true;
            case "ole":
                return false;
            case null:
                if (t.All(char.IsAsciiDigit) || t.StartsWith("/Date(", StringComparison.Ordinal)
                    || (t.Length >= 14 && t[..14].All(char.IsAsciiDigit)))
                    return true;
                return DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
                    ? parsed.Kind != DateTimeKind.Unspecified
                    : null;
            default:
                // Standard formats that always write UTC or an offset; a format ending in a literal Z, quoted or
                // not (Z is no specifier), writes UTC too.
                if (format is "o" or "O" or "u" or "r" or "R" || format.TrimEnd('\'', '"').EndsWith('Z'))
                    return true;
                return DateTime.TryParseExact(t, format, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var exact)
                    ? exact.Kind != DateTimeKind.Unspecified
                    : null;
        }
    }

    /// <summary>
    /// Hours of the day: "22-6" (from 22:00 up to 06:00, across midnight), "12" (12:00 to 12:59), several
    /// comma-separated or as a list. Hours are 0 to 23; a range's end is not included.
    /// </summary>
    public static bool TryHours(IEnumerable<string> ranges, out bool[] hours)
    {
        hours = new bool[24];
        var any = false;
        foreach (var range in ranges)
        {
            var ends = range.Split('-', StringSplitOptions.TrimEntries);
            if (ends.Length is not (1 or 2) || !ends.All(e => int.TryParse(e, NumberStyles.None, CultureInfo.InvariantCulture, out var h) && h is >= 0 and <= 23))
                return false;
            var from = int.Parse(ends[0], CultureInfo.InvariantCulture);
            var to = ends.Length == 1 ? (from + 1) % 24 : int.Parse(ends[1], CultureInfo.InvariantCulture);
            if (from == to && ends.Length == 2)
                return false;   // "8-8" is no hours, or every hour: say which
            for (var h = from; h != to; h = (h + 1) % 24)
                hours[h] = true;
            any = true;
        }
        return any;
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
