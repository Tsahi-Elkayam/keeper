using System.Text.Json.Nodes;

namespace Keeper.Rules.Tests;

public sealed class EvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

    private static Evaluator Engine(Dictionary<string, string>? thresholds = null) =>
        new(name => thresholds is not null && thresholds.TryGetValue(name, out var v) ? v : null, Now);

    private static LeafCondition Leaf(string field, string op, string? value = null, string? threshold = null) =>
        new(field, op, value is null ? null : JsonValue.Create(value), threshold);

    [Theory]
    [InlineData("10.0.19045.3803", "version-lt", "10.0.22621", true)]
    [InlineData("10.0.22631", "version-lt", "10.0.22621", false)]
    [InlineData("8.1", "version-ge", "8.1.0", true)]              // missing parts are 0
    [InlineData("v2.4.1-beta", "version-gt", "2.4", true)]
    [InlineData("unknown", "version-lt", "1.0", null)]           // not a version: n/a, never a pass
    [InlineData("192.0.2.15", "in-cidr", "192.0.2.0/24,198.51.100.0/24", true)]
    [InlineData("203.0.113.7", "in-cidr", "192.0.2.0/24", false)]
    [InlineData("203.0.113.7", "notin-cidr", "192.0.2.0/24", true)]
    [InlineData("2001:db8::1", "in-cidr", "2001:db8::/32", true)]
    [InlineData("not-an-ip", "in-cidr", "192.0.2.0/24", null)]
    [InlineData("P90D", "duration-gt", "60", true)]
    [InlineData("PT12H", "duration-gt", "1", false)]
    [InlineData("30.00:00:00", "duration-lt", "31", true)]
    [InlineData("ninety days", "duration-gt", "60", null)]
    [InlineData("2.4.1-beta", "version-lt", "2.4.1", true)]      // a pre-release is below its release
    [InlineData("2.4.1-beta", "version-lt", "2.4.1-rc", null)]   // two pre-releases of one version cannot be ordered
    [InlineData("1.0-beta", "version-lt", "1.0.0-alpha", null)]  // the same version, written shorter
    [InlineData("2026-10-21", "version-lt", "3000", null)]       // a date is not a version
    [InlineData("5", "notin-cidr", "192.0.2.0/24", null)]          // parses as 0.0.0.5, but is not an address
    [InlineData("3232235777", "notin-cidr", "192.0.2.0/24", null)]
    [InlineData("192.168.1", "notin-cidr", "192.0.2.0/24", null)]
    [InlineData("P1M", "duration-gt", "20", null)]                // a month has no fixed length
    [InlineData("P1Y", "duration-gt", "300", null)]
    [InlineData("-P5D", "duration-lt", "1", null)]                // a negative length means nothing here
    [InlineData("P2W", "duration-gt", "13", true)]
    [InlineData("PT1M", "duration-lt", "1", true)]                // a minute, not a month
    public void Versions_networks_and_durations_compare_as_what_they_are(string value, string op, string operand, bool? fails)
    {
        var verdict = Engine().Each(Leaf("v", op, operand), new JsonObject { ["v"] = value });

        Assert.Equal(fails, verdict.Fails);
    }

    [Theory]
    [InlineData("1760918400000", true)]   // milliseconds: 2025-10-20
    [InlineData("1760918400", true)]      // seconds
    [InlineData("/Date(1760918400000)/", true)]
    [InlineData("1792454400000", false)]  // 2026-10-20: today, not older than 30 days
    [InlineData("9999999999", null)]      // 2286: an id, not a date
    [InlineData("0000000042", null)]
    [InlineData("123456789012345", null)] // a 15-digit id read as FILETIME would be 1601
    public void Unix_times_are_dates(string value, bool? olderThan30Days)
    {
        Assert.Equal(olderThan30Days, Engine().Each(Leaf("at", "age-gt", "30"), new JsonObject { ["at"] = value }).Fails);
    }

    [Theory]
    [InlineData("46200", "ole", true)]                  // OLE days: 2026-06-27
    [InlineData("46314.5", "ole", false)]               // yesterday noon
    [InlineData("0", "ole", true)]                      // never
    [InlineData("01/09/2026", "dd/MM/yyyy", true)]
    [InlineData("15/10/2026", "dd/MM/yyyy", false)]
    [InlineData("2026-10-15", "dd/MM/yyyy", null)]      // not in the format named: n/a
    [InlineData("9999999999", "unix", false)]           // named, any year counts: 2286
    [InlineData("1760918400000", "unix-ms", true)]
    [InlineData("NaN", "ole", null)]
    [InlineData("Infinity", "ole", null)]
    public void A_named_date_format_reads_what_the_automatic_reading_would_miss(string value, string format, bool? olderThan30Days)
    {
        var leaf = Leaf("at", "age-gt", "30") with { Format = format };

        Assert.Equal(olderThan30Days, Engine().Each(leaf, new JsonObject { ["at"] = value }).Fails);
    }

    [Theory]
    [InlineData("2026-10-19T20:30:00Z", "22-6", true)]    // 23:30 in Jerusalem (UTC+3 in October)
    [InlineData("2026-10-19T08:00:00Z", "22-6", false)]   // 11:00
    [InlineData("2026-10-19T02:59:00Z", "22-6", true)]    // 05:59
    [InlineData("2026-10-19T03:00:00Z", "22-6", false)]   // 06:00: the end hour is not included
    [InlineData("2026-10-19T04:00:00Z", "8-17,22-6", false)]
    [InlineData("1760918400", "0-6", true)]               // unix seconds: 03:00 local
    [InlineData("tomorrow", "0-23", null)]                // not a time: n/a
    public void An_hour_of_the_day_is_read_on_the_organisations_clock(string value, string hours, bool? fails)
    {
        var engine = Engine(new() { [Rule.TimeZoneSetting] = "Asia/Jerusalem" });

        Assert.Equal(fails, engine.Each(Leaf("at", "hour-in", hours), new JsonObject { ["at"] = value }).Fails);
    }

    [Theory]
    [InlineData("2026-10-19 23:30", null, true)]                      // no Z, no offset: already the organisation's clock
    [InlineData("2026-10-19T23:30:00+03:00", null, true)]
    [InlineData("19/10/2026 23:30", "dd/MM/yyyy HH:mm", true)]
    [InlineData("23:30", "HH:mm", true)]                             // a time alone, for an hour of the day
    [InlineData("2026-10-19 20:30 +00:00", "yyyy-MM-dd HH:mm zzz", true)]   // the format names an offset: converted
    [InlineData("46314.979", "ole", true)]                           // 23:30 as Excel wrote it
    [InlineData("2026-10-19 20:30:00+00:00", null, true)]            // an offset after a space is still an offset
    [InlineData("Mon, 19 Oct 2026 20:30:00 GMT", null, true)]
    [InlineData("2026-10-19T20:30:00.0000000Z", "o", true)]          // a standard format that writes UTC
    [InlineData("20261019203000Z", "yyyyMMddHHmmss'Z'", true)]       // a literal Z the format quotes
    [InlineData("20261019203000.0Z", "yyyyMMddHHmmss.0Z", true)]     // or does not: Z is no specifier
    public void A_clock_time_without_an_offset_is_the_organisations_own(string value, string? format, bool fails)
    {
        var engine = Engine(new() { [Rule.TimeZoneSetting] = "Asia/Jerusalem" });

        Assert.Equal(fails, engine.Each(Leaf("at", "hour-in", "22-6") with { Format = format }, new JsonObject { ["at"] = value }).Fails);
    }

    [Theory]
    [InlineData("dd/MM/yyyy", false, true)]
    [InlineData("MM/dd", false, false)]        // no year: every date would be this year's
    [InlineData("HH:mm", false, false)]
    [InlineData("HH:mm", true, true)]          // enough for an hour of the day
    [InlineData("dd MMM", true, false)]
    public void A_custom_format_must_hold_what_the_condition_needs(string format, bool timeOfDay, bool valid) =>
        Assert.Equal(valid, Values.IsDateFormat(format, timeOfDay));

    [Fact]
    public void Conditions_on_the_last_read_are_unknown_without_one()
    {
        var absent = Leaf("_previous.owner", "absent");

        Assert.Null(Engine().Each(absent, new JsonObject { ["owner"] = "x" }).Fails);                           // no earlier read
        Assert.Null(Engine().Each(Leaf("_new", "absent"), new JsonObject()).Fails);
        Assert.Null(Engine().Each(absent, new JsonObject { ["_new"] = true }).Fails);                           // new: no earlier row
        Assert.True(Engine().Each(absent, new JsonObject { ["_new"] = false, ["_previous"] = new JsonObject() }).Fails);
    }

    [Fact]
    public void An_hour_of_the_day_without_a_known_time_zone_cannot_be_judged()
    {
        var row = new JsonObject { ["at"] = "2026-10-19T20:30:00Z" };

        Assert.Null(Engine().Each(Leaf("at", "hour-in", "22-6"), row).Fails);
        Assert.Null(Engine(new() { [Rule.TimeZoneSetting] = "Mars/Olympus" }).Each(Leaf("at", "hour-in", "22-6"), row).Fails);
    }

    [Theory]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-512", "domain-admins", true)]   // any domain's 512
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-513", "domain-admins", false)]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-519", "rid:519", true)]
    [InlineData("S-1-5-32-544", "domain-admins", false)]                                  // a builtin group is no domain group
    [InlineData("S-1-1-0", "everyone,anonymous", true)]
    [InlineData("S-1-5-21-1-2-3-4-512", "domain-admins", false)]                         // too many parts for a domain SID
    [InlineData("CN=Domain Admins", "domain-admins", null)]                               // not a SID: n/a
    public void Sids_match_by_name_rid_or_value(string sid, string names, bool? fails)
    {
        Assert.Equal(fails, Engine().Each(Leaf("sid", "sid-in", names), new JsonObject { ["sid"] = sid }).Fails);
    }

    [Fact]
    public void Any_member_sid_in_the_list_fires()
    {
        var row = new JsonObject { ["members"] = new JsonArray("S-1-5-21-1-2-3-1105", "S-1-5-11") };

        Assert.True(Engine().Each(Leaf("members", "sid-in", "authenticated-users"), row).Fails);
        Assert.True(Engine().Each(Leaf("members", "sid-notin", "authenticated-users"), row).Fails);   // 1105 is not
    }

    private static JsonObject Seen(JsonNode? now, JsonNode? before, bool? isNew = false, string field = "members")
    {
        var row = new JsonObject { [field] = now };
        if (isNew is null)
            return row;
        row["_new"] = isNew;
        if (isNew == false)
            row["_previous"] = new JsonObject { [field] = before };
        return row;
    }

    [Fact]
    public void Changed_compares_with_the_last_clean_read_arrays_as_sets()
    {
        var changed = new LeafCondition("members", "changed", null, null);

        Assert.False(Engine().Each(changed, Seen(new JsonArray("b", "a"), new JsonArray("A", "b"))).Fails);   // order and case are no change
        Assert.True(Engine().Each(changed, Seen(new JsonArray("a", "c"), new JsonArray("a", "b"))).Fails);
        Assert.True(Engine().Each(changed, Seen(new JsonArray("a"), null, isNew: true)).Fails);                // new since that read
        Assert.True(Engine().Each(changed, Seen(null, new JsonArray("a"))).Fails);                              // gone from the row
        Assert.Null(Engine().Each(changed, Seen(new JsonArray("a"), null, isNew: null)).Fails);                // no earlier read
    }

    [Fact]
    public void A_masked_field_is_compared_masked_so_its_value_is_never_shown()
    {
        var engine = new Evaluator(_ => null, Now) { Mask = ["secret"] };
        var verdict = engine.Each(new LeafCondition("secret", "changed", null, null), Seen("hunter2", FieldPath.MaskedValue, field: "secret"));

        Assert.False(verdict.Fails);   // set then, set now
        Assert.DoesNotContain("hunter2", verdict.Value, StringComparison.Ordinal);
        Assert.True(engine.Each(new LeafCondition("secret", "changed", null, null), Seen("", FieldPath.MaskedValue, field: "secret")).Fails);   // cleared
    }

    [Fact]
    public void Masking_replaces_values_at_a_path_and_leaves_nothing_as_nothing()
    {
        var row = new JsonObject
        {
            ["cpassword"] = "secret", ["empty"] = "", ["none"] = null,
            ["items"] = new JsonArray(new JsonObject { ["key"] = "k1" }, new JsonObject { ["key"] = null }),
        };
        foreach (var path in new[] { "cpassword", "empty", "none", "items[].key", "absent.deeper" })
            FieldPath.Mask(row, path);

        Assert.Equal("""{"cpassword":"set","empty":"","none":null,"items":[{"key":"set"},{"key":null}]}""", row.ToJsonString());
    }

    [Theory]
    [InlineData("22-6", new[] { 22, 23, 0, 5 }, new[] { 6, 21 })]
    [InlineData("12", new[] { 12 }, new[] { 11, 13 })]
    [InlineData("19-0", new[] { 19, 23 }, new[] { 0, 18 })]
    public void Hours_are_ranges_whose_end_is_not_included(string text, int[] inside, int[] outside)
    {
        Assert.True(Values.TryHours(text.Split(','), out var hours));
        Assert.All(inside, h => Assert.True(hours[h]));
        Assert.All(outside, h => Assert.False(hours[h]));
    }

    [Theory]
    [InlineData("8-8")]
    [InlineData("24")]
    [InlineData("night")]
    public void Hours_that_mean_nothing_are_refused(string text) => Assert.False(Values.TryHours([text], out _));

    private static readonly JsonObject Policy = new()
    {
        ["assignments"] = new JsonArray(
            new JsonObject { ["group"] = "All users", ["intent"] = "available" },
            new JsonObject { ["group"] = "Pilot", ["intent"] = "required" }),
    };

    [Fact]
    public void Two_conditions_on_one_element_are_judged_on_the_same_element()
    {
        var both = new AllCondition([Leaf("group", "eq", "All users"), Leaf("intent", "eq", "required")]);

        // Flattened, each condition finds an element of its own: a false alarm.
        Assert.True(Engine().Each(new AllCondition([Leaf("assignments[].group", "eq", "All users"), Leaf("assignments[].intent", "eq", "required")]), Policy).Fails);
        // On one element at a time, no assignment is both.
        Assert.False(Engine().Each(new ElementCondition("assignments", false, both), Policy).Fails);
        Assert.True(Engine().Each(new ElementCondition("assignments", false, new AllCondition([Leaf("group", "eq", "Pilot"), Leaf("intent", "eq", "required")])), Policy).Fails);
        Assert.False(Engine().Each(new ElementCondition("assignments", true, Leaf("intent", "eq", "required")), Policy).Fails);
        Assert.Null(Engine().Each(new ElementCondition("missing", false, both), Policy).Fails);    // no array at all: cannot be judged
        Assert.False(Engine().Each(new ElementCondition("none", false, both), new JsonObject { ["none"] = new JsonArray() }).Fails);   // an empty one fires nothing
        Assert.Null(Engine().Each(new ElementCondition("gaps", false, both), new JsonObject { ["gaps"] = new JsonArray(null, new JsonObject()) }).Fails);
    }

    private static readonly JsonObject User = new()
    {
        ["sAMAccountName"] = "svc-backup",
        ["userAccountControl"] = "66048",                       // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
        ["pwdLastSet"] = "2024-01-01T00:00:00Z",
        ["lastLogonTimestamp"] = "133000000000000000",          // FILETIME, early 2022
        ["memberOf"] = new JsonArray("CN=Admins", "CN=Users"),
        ["enabled"] = true,
        ["signIn"] = new JsonObject { ["last"] = "2026-10-10T00:00:00Z" },
        ["creds"] = new JsonArray(new JsonObject { ["end"] = "2026-10-25" }, new JsonObject { ["end"] = "2027-06-01" }),
        ["verdict"] = "Fail",
    };

    [Theory]
    [InlineData("userAccountControl", "flag", "65536", true)]
    [InlineData("userAccountControl", "noflag", "2", true)]
    [InlineData("userAccountControl", "flag", "2", false)]
    [InlineData("pwdLastSet", "age-gt", "365", true)]
    [InlineData("pwdLastSet", "age-gt", "3650", false)]
    [InlineData("lastLogonTimestamp", "age-gt", "180", true)]
    [InlineData("sAMAccountName", "match", "^svc-", true)]
    [InlineData("sAMAccountName", "eq", "SVC-BACKUP", true)]
    [InlineData("sAMAccountName", "in", "a,svc-backup,b", true)]
    [InlineData("sAMAccountName", "notin", "a,b", true)]
    [InlineData("memberOf", "contains", "CN=Admins", true)]
    [InlineData("memberOf", "size-gt", "1", true)]
    [InlineData("enabled", "eq", "true", true)]
    [InlineData("signIn.last", "age-lt", "30", true)]
    [InlineData("creds[].end", "until-lt", "30", true)]
    [InlineData("verdict", "status", null, true)]
    public void Leaf_ops_fire_when_the_problem_is_present(string field, string op, string? value, bool fails)
    {
        Assert.Equal(fails, Engine().Each(Leaf(field, op, value), User).Fails);
    }

    [Fact]
    public void A_comparison_on_a_missing_field_is_not_applicable_never_a_pass()
    {
        var verdict = Engine().Each(Leaf("noSuchField", "gt", "5"), User);

        Assert.Null(verdict.Fails);
        Assert.Equal("n-a", verdict.State);
    }

    [Fact]
    public void Exists_absent_and_empty_work_on_missing_fields()
    {
        Assert.Equal(false, Engine().Each(Leaf("noSuchField", "exists"), User).Fails);
        Assert.Equal(true, Engine().Each(Leaf("noSuchField", "absent"), User).Fails);
        Assert.Equal(true, Engine().Each(Leaf("noSuchField", "empty"), User).Fails);
        Assert.Equal(false, Engine().Each(Leaf("memberOf", "empty"), User).Fails);
    }

    [Fact]
    public void All_any_and_not_use_three_valued_logic()
    {
        var neverExpires = Leaf("userAccountControl", "flag", "65536");
        var missing = Leaf("noSuchField", "gt", "1");
        var passes = Leaf("sAMAccountName", "eq", "someone-else");

        Assert.Equal(true, Engine().Each(new AllCondition([neverExpires, Leaf("enabled", "eq", "true")]), User).Fails);
        Assert.Equal(false, Engine().Each(new AllCondition([neverExpires, passes]), User).Fails);
        Assert.Null(Engine().Each(new AllCondition([neverExpires, missing]), User).Fails);
        Assert.Equal(true, Engine().Each(new AnyCondition([missing, neverExpires]), User).Fails);
        Assert.Null(Engine().Each(new AnyCondition([missing, passes]), User).Fails);
        Assert.Equal(true, Engine().Each(new NotCondition(passes), User).Fails);
        Assert.Null(Engine().Each(new NotCondition(missing), User).Fails);
    }

    [Fact]
    public void A_tenant_threshold_replaces_the_literal()
    {
        var rule = Leaf("pwdLastSet", "age-gt", "365", threshold: "ad.password-max-age-days");

        Assert.Equal(true, Engine().Each(rule, User).Fails);
        Assert.Equal(false, Engine(new() { ["ad.password-max-age-days"] = "5000" }).Each(rule, User).Fails);
    }

    [Theory]
    [InlineData("none", 0, true)]
    [InlineData("none", 3, false)]
    [InlineData("some", 3, true)]
    [InlineData("some", 0, false)]
    public void Count_none_and_some(string mode, int rows, bool fails)
    {
        Assert.Equal(fails, Engine().Count(new CountCondition(mode, null, 0, null), rows).Fails);
    }

    [Theory]
    [InlineData(95, 100, true)]       // 95 used of 100: over 90%
    [InlineData(80, 100, false)]
    public void A_field_compares_with_another_field_of_the_same_row(int used, int total, bool fails)
    {
        var rule = new LeafCondition("used", "gt", new JsonObject { ["field"] = "total", ["times"] = 0.9 }, null);

        Assert.Equal(fails, Engine().Each(rule, new JsonObject { ["used"] = used, ["total"] = total }).Fails);
        Assert.Null(Engine().Each(rule, new JsonObject { ["used"] = used }).Fails);      // the other field missing: n/a
    }

    [Theory]
    [InlineData("CIS-CSC-v8:5.3", "CIS-Controls-v8:5.3")]
    [InlineData("cis-controls-8: 5.3 ", "CIS-Controls-v8:5.3")]
    [InlineData("CIS-M365-5.2.3.5", "CIS-M365:5.2.3.5")]
    [InlineData("NIST-800-53:AC-2(3)", "NIST-800-53:AC-2(3)")]
    [InlineData("RFC-5280", "RFC-5280")]
    [InlineData("Vendor-X:7", "Vendor-X:7")]
    public void References_get_one_spelling_per_framework(string written, string canonical)
    {
        Assert.Equal(canonical, Refs.Normalize(written));
    }

    [Fact]
    public void A_broken_pattern_in_a_tenant_setting_is_n_a_not_a_crash()
    {
        var rule = new LeafCondition("name", "notmatch", "^svc-", "ad.service-account-pattern");

        var verdict = Engine(new() { ["ad.service-account-pattern"] = "([unclosed" }).Each(rule, new JsonObject { ["name"] = "alice" });

        Assert.Null(verdict.Fails);
        Assert.Contains("not a valid regular expression", verdict.Why, StringComparison.Ordinal);
    }

    [Fact]
    public void Count_compares_with_a_threshold()
    {
        var rule = new CountCondition("compare", "gt", 4, "entra.max-global-admins");

        Assert.Equal(true, Engine().Count(rule, 5).Fails);
        Assert.Equal(false, Engine(new() { ["entra.max-global-admins"] = "8" }).Count(rule, 5).Fails);
    }

    [Theory]
    [InlineData("0", true)]                       // FILETIME 0: never logged on
    [InlineData("9223372036854775807", false)]    // never expires
    [InlineData("20200101000000.0Z", true)]       // LDAP generalized time
    [InlineData("2026-10-19", false)]
    public void Dates_read_in_the_formats_estates_use(string value, bool olderThan30Days)
    {
        var row = new JsonObject { ["when"] = value };

        Assert.Equal(olderThan30Days, Engine().Each(Leaf("when", "age-gt", "30"), row).Fails);
    }

    [Fact]
    public void A_pathological_pattern_times_out_as_not_applicable()
    {
        var row = new JsonObject { ["text"] = new string('a', 40) + "!" };

        var verdict = Engine().Each(Leaf("text", "match", "^(a+)+$"), row);

        Assert.Null(verdict.Fails);
    }

    [Fact]
    public void Severity_follows_the_days_left()
    {
        var map = new SeverityMap(null, "notAfter",
            [new(null, 0, "critical"), new(null, 14, "high"), new(null, 60, "medium")], new Dictionary<string, string>(), "low");

        Assert.Equal("critical", Engine().Severity(map, new JsonObject { ["notAfter"] = "2026-10-19" }));
        Assert.Equal("high", Engine().Severity(map, new JsonObject { ["notAfter"] = "2026-10-30" }));
        Assert.Equal("medium", Engine().Severity(map, new JsonObject { ["notAfter"] = "2026-12-01" }));
        Assert.Equal("low", Engine().Severity(map, new JsonObject { ["notAfter"] = "2028-01-01" }));
    }

    [Fact]
    public void Templates_fill_fields_and_keep_literal_braces()
    {
        Assert.Equal("svc-backup in CN=Admins, CN=Users {x}",
            Templates.Render("{sAMAccountName} in {memberOf} {{x}}", User));
    }
}
