using System.Text.Json.Nodes;

namespace Keeper.Rules.Tests;

public sealed class EvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

    private static Evaluator Engine(Dictionary<string, string>? thresholds = null) =>
        new(name => thresholds is not null && thresholds.TryGetValue(name, out var v) ? v : null, Now);

    private static LeafCondition Leaf(string field, string op, string? value = null, string? threshold = null) =>
        new(field, op, value is null ? null : JsonValue.Create(value), threshold);

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
