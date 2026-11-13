using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Cim;

namespace Keeper.Runners.Tests;

public sealed class CimErrorsTests
{
    private const int MiFailed = 1, MiAccessDenied = 2, MiInvalidClass = 5, MiServerLimits = 27;

    [Theory]
    [InlineData(1326)]          // ERROR_LOGON_FAILURE
    [InlineData(1331)]          // account disabled
    [InlineData(1909)]          // account locked out
    [InlineData(1793)]          // account expired
    [InlineData(1330)]          // password expired
    public void A_locked_expired_or_disabled_account_is_refused_by_its_code_in_any_language(int win32)
    {
        Assert.Equal(FailureKind.Refused, CimErrors.Classify(MiFailed, win32, 0, "Das Konto wurde gesperrt"));
    }

    [Fact]
    public void An_hresult_that_wraps_a_logon_failure_is_refused()
    {
        Assert.Equal(FailureKind.Refused, CimErrors.Classify(MiFailed, null, unchecked((int)0x8007052E), "nicht lesbar"));
    }

    [Fact]
    public void Access_denied_is_denied_not_refused()
    {
        Assert.Equal(FailureKind.Denied, CimErrors.Classify(MiAccessDenied, null, 0, "x"));
        Assert.Equal(FailureKind.Denied, CimErrors.Classify(MiFailed, 5, 0, "x"));
        Assert.Equal(FailureKind.Denied, CimErrors.Classify(MiFailed, unchecked((long)0x80070005), 0, "x"));
        Assert.Equal(FailureKind.Denied, CimErrors.Classify(MiFailed, unchecked((long)0x80041003), 0, "x"));
    }

    [Fact]
    public void A_kerberos_problem_is_about_the_host_so_it_is_denied_and_the_account_is_not_blamed()
    {
        Assert.Equal(FailureKind.Denied, CimErrors.Classify(MiFailed, null, 0, "The Kerberos authentication failed: the target principal name is incorrect"));
    }

    [Fact]
    public void English_refusal_phrases_are_the_last_resort()
    {
        Assert.Equal(FailureKind.Refused, CimErrors.Classify(MiFailed, null, 0, "Logon failure: unknown user name or bad password."));
        Assert.Equal(FailureKind.Refused, CimErrors.Classify(MiFailed, null, 0, "The referenced account is currently locked out"));
    }

    [Fact]
    public void Winrm_quota_errors_are_throttled()
    {
        Assert.Equal(FailureKind.Throttled, CimErrors.Classify(MiFailed, unchecked((long)0x803381A6), 0, "x"));
        Assert.Equal(FailureKind.Throttled, CimErrors.Classify(MiFailed, null, 0, "The maximum number of concurrent operations for this user has been exceeded."));
        Assert.Equal(FailureKind.Throttled, CimErrors.Classify(MiServerLimits, null, 0, "x"));
    }

    [Fact]
    public void An_rpc_server_that_is_not_there_is_unreachable_and_a_winrm_timeout_is_a_timeout()
    {
        Assert.Equal(FailureKind.Unreachable, CimErrors.Classify(MiFailed, null, unchecked((int)0x800706BA), "RPC server is unavailable"));
        Assert.Equal(FailureKind.Timeout, CimErrors.Classify(MiFailed, unchecked((long)0x80338029), 0, "x"));
    }

    [Fact]
    public void Anything_else_is_an_error()
    {
        Assert.Equal(FailureKind.Error, CimErrors.Classify(MiFailed, null, 0, "something odd"));
    }

    [Fact]
    public void Refused_denied_and_throttled_end_the_transport_walk_and_unreachable_does_not()
    {
        Assert.True(CimErrors.EndsWalk(FailureKind.Refused, MiFailed));
        Assert.True(CimErrors.EndsWalk(FailureKind.Denied, MiFailed));
        Assert.True(CimErrors.EndsWalk(FailureKind.Throttled, MiFailed));
        Assert.True(CimErrors.EndsWalk(FailureKind.Error, MiInvalidClass));   // the host answered and faulted the request
        Assert.False(CimErrors.EndsWalk(FailureKind.Unreachable, MiFailed));
        Assert.False(CimErrors.EndsWalk(FailureKind.Timeout, MiFailed));
        Assert.False(CimErrors.EndsWalk(FailureKind.Error, MiFailed));
    }

    [Fact]
    public async Task A_refused_account_is_never_presented_over_the_next_transport()
    {
        var asked = new List<string>();
        var result = TransportChain.Resolve(["wsman", "dcom"], t =>
        {
            asked.Add(t);
            var kind = CimErrors.Classify(MiFailed, 1909, 0, "gesperrt");
            return CimErrors.EndsWalk(kind, MiFailed) ? (Reach.Refused, "locked") : (Reach.Unreachable, "x");
        });
        await Task.CompletedTask;

        Assert.Equal(["wsman"], asked);
        Assert.Equal("wsman", result.Transport);
    }
}

public sealed class RegistryMergeTests
{
    private static readonly RegistryRunner Runner = new();

    private static QuerySpec Q(string key, string? values, params (string Name, JsonNode? Value)[] more)
    {
        var fields = new List<(string, JsonNode?)> { ("path", JsonValue.Create(@"SOFTWARE\Test")) };
        if (values is not null)
            fields.Add(("values", new JsonArray([.. values.Split(',').Select(v => (JsonNode)JsonValue.Create(v))])));
        fields.AddRange(more);
        return Context.Query("registry", key, [.. fields]);
    }

    private static JsonObject Row(params (string, JsonNode?)[] values)
    {
        var row = new JsonObject { ["host"] = "PC01", ["key"] = @"SOFTWARE\Test", ["exists"] = true };
        foreach (var (name, value) in values)
            row[name] = value;
        return row;
    }

    [Fact]
    public void Runners_belong_to_the_cim_family_and_the_event_log_has_its_own()
    {
        Assert.Equal("cim", new CimRunner().SessionFamily);
        Assert.Equal("cim", Runner.SessionFamily);
        Assert.Equal("eventlog", new EventLogRunner().SessionFamily);
    }

    [Fact]
    public void Plain_value_reads_of_one_key_share_a_merge_key()
    {
        Assert.Equal(Runner.MergeKey(Q("a", "A")), Runner.MergeKey(Q("a", "B")));
        Assert.Equal(Runner.MergeKey(Q("a", "A")), Runner.MergeKey(Q("a", null)));
    }

    [Fact]
    public void Another_key_hive_or_fallback_chain_does_not_merge()
    {
        var plain = Runner.MergeKey(Q("a", "A"));
        Assert.NotEqual(plain, Runner.MergeKey(Context.Query("registry", "a", ("path", JsonValue.Create(@"SOFTWARE\Other")))));
        Assert.NotEqual(plain, Runner.MergeKey(Q("a", "A", ("hive", JsonValue.Create("HKU")))));
        Assert.NotEqual(plain, Runner.MergeKey(Q("a", "A", ("fallback_chain", JsonValue.Create("dcom")))));
        Assert.NotEqual(plain, Runner.MergeKey(Q("b", "A")));
    }

    [Fact]
    public void Subkey_and_certificate_reads_are_not_merged()
    {
        Assert.Null(Runner.MergeKey(Q("a", null, ("subkeys", JsonValue.Create("true")))));
        Assert.Null(Runner.MergeKey(Q("a", null, ("certificates", JsonValue.Create("true")))));
    }

    [Fact]
    public void Merging_two_value_lists_gives_their_union()
    {
        var merged = Runner.Merge([Q("a", "A"), Q("a", "B,a")]);

        Assert.Equal(["A", "B"], merged.List("values"));
        Assert.Equal(@"SOFTWARE\Test", merged.Text("path"));
    }

    [Fact]
    public void A_member_that_reads_all_values_makes_the_merge_read_all_values()
    {
        var merged = Runner.Merge([Q("a", "A"), Q("a", null)]);

        Assert.Empty(merged.List("values"));
        Assert.Null(merged.Fields["values"]);
    }

    [Fact]
    public void A_merged_query_is_not_merged_again()
    {
        Assert.Null(Runner.MergeKey(Runner.Merge([Q("a", "A"), Q("a", "B")])));
    }

    [Fact]
    public void Split_keeps_only_the_originals_values()
    {
        var merged = RunnerResult.Ok([Row(("A", 1), ("B", "x"), ("C", 3))]);

        var split = Runner.Split(Q("a", "A"), merged);

        var row = Assert.Single(split.Rows);
        Assert.Equal(["host", "key", "exists", "A"], row.Select(p => p.Key));
        Assert.Equal("ok", split.State);
    }

    [Fact]
    public void Split_of_a_query_without_values_keeps_all_of_them()
    {
        var merged = RunnerResult.Ok([Row(("A", 1), ("B", "x"))]);

        var split = Runner.Split(Q("a", null), merged);

        Assert.Equal(["host", "key", "exists", "A", "B"], Assert.Single(split.Rows).Select(p => p.Key));
    }

    [Fact]
    public void A_value_only_another_query_could_not_read_does_not_make_this_one_partial()
    {
        var merged = RunnerResult.Partial([Row(("A", 1), ("B", null), ("\0unread", new JsonArray("B")))], "PC01: 1 value(s) of SOFTWARE\\Test could not be read (B)");

        var forA = Runner.Split(Q("a", "A"), merged);
        var forB = Runner.Split(Q("a", "B"), merged);

        Assert.Equal("ok", forA.State);
        Assert.Null(forA.Reason);
        Assert.False(Assert.Single(forA.Rows).ContainsKey("\0unread"));
        Assert.Equal("partial", forB.State);
        Assert.Contains("(B)", forB.Reason);
        Assert.False(Assert.Single(forB.Rows).ContainsKey("\0unread"));
    }

    [Fact]
    public void Partial_names_only_the_originals_unread_values()
    {
        var merged = RunnerResult.Partial([Row(("A", null), ("B", null), ("\0unread", new JsonArray("A", "B")))], "r");

        var split = Runner.Split(Q("a", "A,Z"), merged);

        Assert.Equal("partial", split.State);
        Assert.Contains("1 value(s)", split.Reason);
        Assert.Contains("(A)", split.Reason);
        Assert.DoesNotContain("B", split.Reason!.Replace("could not be read", ""));
    }

    [Fact]
    public void A_missing_key_stays_a_fact_for_every_original()
    {
        var merged = RunnerResult.Ok([new JsonObject { ["host"] = "PC01", ["key"] = @"SOFTWARE\Test", ["exists"] = false }]);

        var split = Runner.Split(Q("a", "A"), merged);

        Assert.False(Assert.Single(split.Rows)["exists"]!.GetValue<bool>());
    }

    [Fact]
    public void A_failed_merged_read_is_failed_for_every_original_with_its_reason_and_kind()
    {
        var merged = RunnerResult.Failed("PC01: EnumValues returned 5", FailureKind.Denied);

        foreach (var original in new[] { Q("a", "A"), Q("a", "B") })
        {
            var split = Runner.Split(original, merged);
            Assert.Equal("failed", split.State);
            Assert.Equal("PC01: EnumValues returned 5", split.Reason);
            Assert.Equal(FailureKind.Denied, split.Failure);
        }
    }
}

public sealed class EventLogClassifyTests
{
    [Fact]
    public void An_unauthorized_read_is_denied()
    {
        Assert.Equal(FailureKind.Denied, EventLogRunner.Classify(0, "Attempted to perform an unauthorized operation.", unauthorized: true));
        Assert.Equal(FailureKind.Denied, EventLogRunner.Classify(unchecked((int)0x80070005), "x", unauthorized: false));
    }

    [Fact]
    public void Logon_failure_codes_are_refused()
    {
        Assert.Equal(FailureKind.Refused, EventLogRunner.Classify(unchecked((int)0x8007052E), "x", false));
        Assert.Equal(FailureKind.Refused, EventLogRunner.Classify(1909, "x", false));
        Assert.Equal(FailureKind.Refused, EventLogRunner.Classify(0, "Logon failure: unknown user name or bad password", false));
    }

    [Fact]
    public void Rpc_server_unavailable_is_unreachable()
    {
        Assert.Equal(FailureKind.Unreachable, EventLogRunner.Classify(unchecked((int)0x800706BA), "The RPC server is unavailable", false));
        Assert.Equal(FailureKind.Unreachable, EventLogRunner.Classify(1722, "x", false));
    }

    [Fact]
    public void Anything_else_is_an_error()
    {
        Assert.Equal(FailureKind.Error, EventLogRunner.Classify(0, "boom", false));
    }
}
