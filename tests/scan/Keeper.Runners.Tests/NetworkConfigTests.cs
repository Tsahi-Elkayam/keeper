using System.Text.Json.Nodes;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class NetworkConfigTests
{
    internal const string Ios = """
        !
        version 15.2
        no service password-encryption
        !
        hostname core-sw01
        !
        enable password cisco123
        enable secret 5 $1$abcd$XYZsecrethash
        !
        username admin privilege 15 password 7 0822455D0A16
        username ops secret 9 $9$abc$defsecrethash
        !
        aaa new-model
        !
        interface GigabitEthernet0/1
         description uplink
         ip address 192.0.2.1 255.255.255.0
         no shutdown
        !
        interface GigabitEthernet0/2
         switchport mode access
         ip ospf message-digest-key 1 md5 7 094F471A1A0A
        !
        ip http server
        no ip http secure-server
        ip ssh version 1
        !
        snmp-server community public RO
        snmp-server community s3cr3tRW RW 10
        snmp-server user mon grp v3 auth sha AuthPass123 priv aes 128 PrivPass123
        tacacs-server host 198.51.100.5 key 7 0822455D0A16
        ntp authentication-key 1 md5 NtpKey123
        !
        banner motd ^C
        Authorized users only - password is not here
        ^C
        !
        line con 0
         exec-timeout 0 0
        line vty 0 4
         password cisco
         login
         transport input telnet
        line vty 5 15
         access-class 10 in
         transport input ssh
        !
        end
        """;

    private static List<JsonObject> Lines() => NetworkConfig.Parse(Ios, "core-sw01.cfg", "ios", "lines");

    private static JsonObject Row(List<JsonObject> rows, string text) => rows.Single(r => r["text"]!.ToString() == text);

    [Fact]
    public void Each_command_is_a_row_with_the_blocks_it_sits_in()
    {
        var rows = Lines();

        var description = Row(rows, "description uplink");
        Assert.Equal("interface GigabitEthernet0/1", description["context"]!.ToString());
        Assert.Equal(1, (int)description["depth"]!);
        Assert.Equal("", Row(rows, "hostname core-sw01")["context"]!.ToString());
        Assert.Equal("line vty 0 4", Row(rows, "transport input telnet")["context"]!.ToString());
        Assert.Equal("line vty 5 15", Row(rows, "transport input ssh")["context"]!.ToString());
        Assert.All(rows, r => Assert.Equal("core-sw01.cfg", r["file"]!.ToString()));
    }

    [Fact]
    public void Comment_lines_and_the_end_marker_are_not_commands()
    {
        var rows = Lines();

        Assert.DoesNotContain(rows, r => r["text"]!.ToString().StartsWith('!'));
        Assert.DoesNotContain(rows, r => r["text"]!.ToString() == "end");
    }

    [Fact]
    public void A_no_command_is_marked_and_its_command_text_drops_the_no()
    {
        var row = Row(Lines(), "no ip http secure-server");

        Assert.True((bool)row["negated"]!);
        Assert.Equal("ip http secure-server", row["command"]!.ToString());
        Assert.False((bool)Row(Lines(), "ip http server")["negated"]!);
    }

    [Fact]
    public void A_banner_is_one_statement_and_its_text_is_not_read_as_commands()
    {
        var rows = Lines();

        Assert.Contains(rows, r => r["text"]!.ToString().StartsWith("banner motd", StringComparison.Ordinal));
        Assert.DoesNotContain(rows, r => r["text"]!.ToString().Contains("Authorized", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("enable password cisco123", "enable password set")]
    [InlineData("enable secret 5 $1$abcd$XYZsecrethash", "enable secret 5 set")]
    [InlineData("username admin privilege 15 password 7 0822455D0A16", "username admin privilege 15 password 7 set")]
    [InlineData("username ops secret 9 $9$abc$defsecrethash", "username ops secret 9 set")]
    [InlineData("password cisco", "password set")]
    [InlineData("tacacs-server host 198.51.100.5 key 7 0822455D0A16", "tacacs-server host 198.51.100.5 key 7 set")]
    [InlineData("ntp authentication-key 1 md5 NtpKey123", "ntp authentication-key 1 md5 set")]
    [InlineData("ip ospf message-digest-key 1 md5 7 094F471A1A0A", "ip ospf message-digest-key 1 md5 7 set")]
    [InlineData("snmp-server user mon grp v3 auth sha AuthPass123 priv aes 128 PrivPass123", "snmp-server user mon grp v3 auth sha set priv aes 128 set")]
    [InlineData("neighbor 192.0.2.9 password 7 02050D480809", "neighbor 192.0.2.9 password 7 set")]
    [InlineData("crypto isakmp key MyPsk123 address 198.51.100.7", "crypto isakmp key set address 198.51.100.7")]
    public void Credentials_in_a_command_become_set_and_keep_the_type_that_says_how_weak_they_are(string line, string expected)
    {
        Assert.Equal(expected, NetworkConfig.Scrub(line));
    }

    [Theory]
    [InlineData("snmp-server community public RO", "snmp-server community <default> RO")]
    [InlineData("snmp-server community private RW", "snmp-server community <default> RW")]
    [InlineData("snmp-server community s3cr3tRW RW 10", "snmp-server community set RW 10")]
    [InlineData("snmp-server community Corp2026 RO view v1", "snmp-server community set RO view v1")]
    public void An_snmp_community_is_hidden_unless_it_is_a_well_known_default_which_is_the_finding(string line, string expected)
    {
        Assert.Equal(expected, NetworkConfig.Scrub(line));
    }

    [Theory]
    [InlineData("snmp-server host 192.0.2.5 version 2c TrapCommunity9", "snmp-server host 192.0.2.5 version 2c set")]
    [InlineData("snmp-server host 192.0.2.5 traps TrapCommunity9 config", "snmp-server host 192.0.2.5 traps set config")]
    [InlineData("snmp-server host 192.0.2.5 TrapCommunity9", "snmp-server host 192.0.2.5 set")]
    [InlineData("snmp-server host 192.0.2.5 version 3 priv monitoruser", "snmp-server host 192.0.2.5 version 3 priv monitoruser")]   // a user name, not a secret
    [InlineData("ip ospf authentication-key 7 094F471A1A0A", "ip ospf authentication-key 7 set")]
    [InlineData("ip ospf authentication-key PlainKey1", "ip ospf authentication-key set")]
    [InlineData("standby 1 authentication HsrpKey1", "standby 1 authentication set")]
    [InlineData("standby 1 authentication md5 key-string 7 02050D480809", "standby 1 authentication md5 key-string 7 set")]
    [InlineData("vrrp 2 authentication text VrrpKey1", "vrrp 2 authentication text set")]
    [InlineData("aaa authentication login default local", "aaa authentication login default local")]
    [InlineData("ip ssh authentication-retries 3", "ip ssh authentication-retries 3")]
    [InlineData("ntp authentication-key 1 md5 NtpKey123", "ntp authentication-key 1 md5 set")]
    public void More_places_a_network_configuration_keeps_a_secret(string line, string expected)
    {
        Assert.Equal(expected, NetworkConfig.Scrub(line));
    }

    [Theory]
    [InlineData("no service password-encryption")]
    [InlineData("service password-encryption")]
    [InlineData("aaa new-model")]
    [InlineData("ip ssh version 2")]
    [InlineData("transport input ssh")]
    [InlineData("key chain OSPF-KEYS")]
    [InlineData("key 1")]
    [InlineData("login local")]
    [InlineData("ip http authentication local")]
    public void Commands_that_only_mention_these_words_are_left_alone(string line)
    {
        Assert.Equal(line, NetworkConfig.Scrub(line));
    }

    [Fact]
    public void No_secret_survives_into_any_row()
    {
        var text = string.Join("\n", Lines().Select(r => r.ToJsonString()));

        foreach (var secret in new[] { "cisco123", "XYZsecrethash", "0822455D0A16", "defsecrethash", "s3cr3tRW", "AuthPass123", "PrivPass123", "NtpKey123", "094F471A1A0A" })
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        Assert.DoesNotContain("password cisco", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Blocks_carry_their_commands_so_a_rule_can_ask_what_a_section_lacks()
    {
        var blocks = NetworkConfig.Parse(Ios, "core-sw01.cfg", "ios", "blocks");

        var telnet = blocks.Single(b => b["header"]!.ToString() == "line vty 0 4");
        var ssh = blocks.Single(b => b["header"]!.ToString() == "line vty 5 15");
        Assert.Contains("transport input telnet", telnet["body"]!.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("access-class", telnet["body"]!.ToString(), StringComparison.Ordinal);
        Assert.Contains("access-class 10 in", ssh["body"]!.ToString(), StringComparison.Ordinal);
        Assert.Equal("line vty", telnet["name"]!.ToString());
        Assert.DoesNotContain(blocks, b => b["header"]!.ToString() == "hostname core-sw01");   // a lone command is not a block
    }

    [Fact]
    public void Deeper_nesting_belongs_to_the_top_level_block()
    {
        var blocks = NetworkConfig.Parse("router bgp 65000\n address-family ipv4\n  neighbor 192.0.2.2 activate\n network 192.0.2.0\n", "r.cfg", "ios", "blocks");

        var bgp = Assert.Single(blocks);
        Assert.Contains("neighbor 192.0.2.2 activate", bgp["body"]!.ToString(), StringComparison.Ordinal);
        Assert.Contains("network 192.0.2.0", bgp["body"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Tabs_and_windows_line_endings_are_handled()
    {
        var rows = NetworkConfig.Parse("interface Gi0/1\r\n\tdescription x\r\n", "r.cfg", "ios", "lines");

        Assert.Equal("interface Gi0/1", rows[1]["context"]!.ToString());
    }

    [Fact]
    public void An_unknown_style_or_mode_is_refused()
    {
        Assert.Throws<ArgumentException>(() => NetworkConfig.Parse("x", "f", "junos", "lines"));
        Assert.Throws<ArgumentException>(() => NetworkConfig.Parse("x", "f", "ios", "tree"));
    }
}
