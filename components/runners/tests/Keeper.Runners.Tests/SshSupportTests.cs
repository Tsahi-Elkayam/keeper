using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class SshSupportTests
{
    [Theory]
    [InlineData("192.0.2.10", "192.0.2.0/24", true)]
    [InlineData("192.0.2.10", "198.51.100.0/24", false)]
    [InlineData("192.0.2.10", "198.51.100.0/24, 192.0.2.0/28", true)]
    [InlineData("web01.example.org", "*.example.org", true)]
    [InlineData("a.b.example.org", "*.example.org", true)]
    [InlineData("example.org", "*.example.org", false)]
    [InlineData("web01.example.org.evil.test", "*.example.org", false)]
    [InlineData("evilexample.org", "*.example.org", false)]
    [InlineData("web01.example.org", "web01.example.org", true)]
    [InlineData("WEB01.EXAMPLE.ORG", "web01.example.org", true)]
    [InlineData("web02.example.org", "web01.example.org", false)]
    [InlineData("web01.example.org", "192.0.2.0/24", false)]   // a name never matches a range: DNS is not trusted with a credential
    [InlineData("192.0.2.10", "*.example.org", false)]
    [InlineData("192.0.2.10", "", false)]
    public void A_credential_goes_only_where_the_integrations_scope_names(string target, string scope, bool allowed)
    {
        Assert.Equal(allowed, SshScope.Allows(target, scope));
    }

    [Theory]
    [InlineData("SHA256:abc123", "abc123")]
    [InlineData("abc123=", "abc123")]
    [InlineData("SHA256:abc123=", "abc123")]
    public void Fingerprints_compare_without_their_prefix_or_padding(string pinned, string seen)
    {
        var policy = HostKeyPolicy.Decide("web01", seen, new Dictionary<string, string> { ["web01"] = pinned }, acceptAny: false);

        Assert.True(policy.Trust);
    }

    [Fact]
    public void A_host_may_pin_several_fingerprints_because_it_presents_a_different_key_per_algorithm()
    {
        var pinned = new Dictionary<string, string> { ["web01"] = "SHA256:ed25519key, SHA256:rsakey" };

        Assert.True(HostKeyPolicy.Decide("web01", "rsakey", pinned, acceptAny: false).Trust);
        Assert.True(HostKeyPolicy.Decide("web01", "ed25519key", pinned, acceptAny: false).Trust);
        Assert.False(HostKeyPolicy.Decide("web01", "otherkey", pinned, acceptAny: false).Trust);
    }

    [Fact]
    public void A_pinned_host_whose_key_changed_is_refused_and_the_reason_says_so()
    {
        var policy = HostKeyPolicy.Decide("web01", "newkey", new Dictionary<string, string> { ["web01"] = "SHA256:oldkey" }, acceptAny: false);

        Assert.False(policy.Trust);
        Assert.Contains("changed", policy.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_unknown_host_is_refused_and_the_reason_gives_the_fingerprint_to_check_and_pin()
    {
        var policy = HostKeyPolicy.Decide("web01", "AbCdEf123", new Dictionary<string, string>(), acceptAny: false);

        Assert.False(policy.Trust);
        Assert.Contains("SHA256:AbCdEf123", policy.Reason, StringComparison.Ordinal);
        Assert.Contains("hostKeys", policy.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Accepting_any_key_is_an_explicit_choice_and_still_says_so()
    {
        var policy = HostKeyPolicy.Decide("web01", "AbCdEf123", new Dictionary<string, string>(), acceptAny: true);

        Assert.True(policy.Trust);
        Assert.Contains("not verified", policy.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_pinned_host_is_checked_even_when_any_key_is_accepted_for_others()
    {
        var policy = HostKeyPolicy.Decide("web01", "wrong", new Dictionary<string, string> { ["web01"] = "right" }, acceptAny: true);

        Assert.False(policy.Trust);
    }

    [Fact]
    public void Host_names_are_matched_without_regard_to_case()
    {
        var policy = HostKeyPolicy.Decide("WEB01", "k", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["web01"] = "k" }, acceptAny: false);

        Assert.True(policy.Trust);
    }

    [Fact]
    public void Every_part_of_a_remote_command_line_is_quoted_and_the_environment_is_fixed()
    {
        var line = RemoteCommand.Line("defaults", ["com.apple.screensaver", "ask for password"]);

        Assert.StartsWith("env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ", line, StringComparison.Ordinal);
        Assert.EndsWith("'defaults' 'read' 'com.apple.screensaver' 'ask for password'", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_quote_inside_a_parameter_cannot_end_its_quoting()
    {
        Assert.Equal(@"'a'\''b; id'", RemoteCommand.Quote("a'b; id"));
    }

    [Fact]
    public void An_absolute_program_keeps_its_path_and_a_plain_one_is_looked_up_in_the_fixed_path()
    {
        Assert.Contains("'/usr/libexec/ApplicationFirewall/socketfilterfw' '--getglobalstate'", RemoteCommand.Line("socketfilterfw", []), StringComparison.Ordinal);
        Assert.Contains("'uname' '-s'", RemoteCommand.Line("uname", ["-s"]), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/etc/ssh/sshd_config", "sshd_config.d/*.conf", "/etc/ssh/sshd_config.d/*.conf")]
    [InlineData("/etc/ssh/sshd_config", "/etc/ssh/crypto.conf", "/etc/ssh/crypto.conf")]
    [InlineData("/etc/nginx/nginx.conf", "../shared/x.conf", "/etc/shared/x.conf")]
    [InlineData("/etc/nginx/nginx.conf", "./conf.d/a.conf", "/etc/nginx/conf.d/a.conf")]
    [InlineData("/nginx.conf", "a.conf", "/a.conf")]
    public void A_remote_include_is_resolved_as_a_posix_path_whatever_the_scanner_runs_on(string from, string include, string expected)
    {
        Assert.Equal(expected, PosixPath.ResolveInclude(from, include));
    }

    [Theory]
    [InlineData("/etc//ssh/./sshd_config", "/etc/ssh/sshd_config")]
    [InlineData("/etc/ssh/../ssh/sshd_config", "/etc/ssh/sshd_config")]
    [InlineData("/", "/")]
    public void A_remote_path_is_normalised(string path, string expected)
    {
        Assert.Equal(expected, PosixPath.Normalize(path));
    }
}
