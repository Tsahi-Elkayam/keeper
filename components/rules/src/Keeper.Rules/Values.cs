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
            return true;
        }
        if (text == "0")
        {
            date = DateTimeOffset.MinValue;
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
