using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Runners.Gpo;

namespace Keeper.Runners.Tests;

/// <summary>A SYSVOL Policies folder built on disk, read the way a domain's would be.</summary>
public sealed class GpoRunnerTests : IDisposable
{
    private const string Gpo1 = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
    private const string Gpo2 = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";
    private readonly string _root = Directory.CreateTempSubdirectory("keeper-sysvol-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private void Put(string gpo, string relative, byte[] bytes)
    {
        var path = Path.Combine(_root, gpo, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
    }

    private void Put(string gpo, string relative, string text, Encoding? encoding = null) =>
        Put(gpo, relative, (encoding ?? Encoding.UTF8).GetPreamble().Concat((encoding ?? Encoding.UTF8).GetBytes(text)).ToArray());

    /// <summary>A Registry.pol as Group Policy writes it.</summary>
    private static byte[] Pol(params (string Key, string Value, uint Type, byte[] Data)[] entries)
    {
        var bytes = new List<byte>();
        void Word(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); bytes.AddRange(b); }
        void Char(char c) => bytes.AddRange(Encoding.Unicode.GetBytes([c]));
        void Text(string s) { bytes.AddRange(Encoding.Unicode.GetBytes(s)); bytes.AddRange([0, 0]); }
        Word(0x67655250);
        Word(1);
        foreach (var (key, value, type, data) in entries)
        {
            Char('[');
            Text(key);
            Char(';');
            Text(value);
            Char(';');
            Word(type);
            Char(';');
            Word((uint)data.Length);
            Char(';');
            bytes.AddRange(data);
            Char(']');
        }
        return [.. bytes];
    }

    private static byte[] Dword(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        return b;
    }

    private Task<RunnerResult> Run(params (string, JsonNode?)[] fields) =>
        new GpoRunner(_ => _root).RunAsync(Context.Query("gpo", "key", fields), Context.For(new FakeConnection("example.org")), CancellationToken.None);

    [Fact]
    public async Task Registry_pol_settings_are_rows_with_their_gpo_and_scope()
    {
        Put(Gpo1, @"Machine\Registry.pol", Pol(
            (@"Software\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic", 4, Dword(0)),
            (@"Software\Policies\Microsoft\Windows NT\Terminal Services", "**del.fDenyTSConnections", 1, Encoding.Unicode.GetBytes(" \0"))));
        Put(Gpo2, @"User\Registry.pol", Pol((@"Software\Policies\Microsoft\Office", "Name", 1, Encoding.Unicode.GetBytes("x\0"))));

        var result = await Run(("part", "registry"));

        Assert.Equal("ok", result.State);
        var basic = result.Rows.Single(r => r["value"]!.ToString() == "AllowBasic");
        Assert.Equal(("dword", "0", Gpo1, "machine"), (basic["type"]!.ToString(), basic["data"]!.ToString(), basic["gpo"]!.ToString(), basic["scope"]!.ToString()));
        Assert.Equal("del", result.Rows.Single(r => r["value"]!.ToString() == "fDenyTSConnections")["action"]!.ToString());
        Assert.Contains(result.Rows, r => r["scope"]!.ToString() == "user" && r["gpo"]!.ToString() == Gpo2);
    }

    [Fact]
    public async Task Security_settings_list_privilege_rights_by_sid()
    {
        Put(Gpo1, @"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", """
            [Unicode]
            Unicode=yes
            [System Access]
            MinimumPasswordLength = 14
            [Privilege Rights]
            SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-1-2-3-1105
            [Registry Values]
            MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
            """, Encoding.Unicode);

        var result = await Run(("part", "security"));

        var debug = result.Rows.Single(r => r["key"]!.ToString() == "SeDebugPrivilege");
        Assert.Equal("""["S-1-5-32-544","S-1-5-21-1-2-3-1105"]""", debug["values"]!.ToJsonString());
        Assert.Equal("14", result.Rows.Single(r => r["key"]!.ToString() == "MinimumPasswordLength")["value"]!.ToString());
        Assert.Equal(("4", "5"), (result.Rows.Single(r => r["section"]!.ToString() == "Registry Values")["type"]!.ToString(),
            result.Rows.Single(r => r["section"]!.ToString() == "Registry Values")["data"]!.ToString()));
        Assert.DoesNotContain(result.Rows, r => r["section"]!.ToString() == "Unicode");
    }

    [Fact]
    public async Task A_preference_password_is_there_but_never_kept()
    {
        Put(Gpo1, @"Machine\Preferences\Groups\Groups.xml", """
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" changed="2019-01-01 00:00:00">
                <Properties action="U" newName="" fullName="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" userName="Administrator (built-in)"/>
              </User>
            </Groups>
            """);

        var result = await Run(("part", "preferences"));

        var item = Assert.Single(result.Rows);
        Assert.Equal("set", item["Properties"]!["cpassword"]!.ToString());
        Assert.Equal(@"Machine\Preferences\Groups\Groups.xml", item["_file"]!.ToString());
        Assert.DoesNotContain("j1Uyj3", item.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_gpo_that_cannot_be_read_makes_the_read_partial_and_no_sysvol_fails_it()
    {
        Put(Gpo1, "GPT.INI", "[General]\r\nVersion=131074\r\n");
        Put(Gpo2, @"Machine\Registry.pol", [1, 2, 3, 4, 5, 6, 7, 8, 9]);   // not a Registry.pol

        var gpt = await Run(("part", "gpt"));
        var registry = await Run(("part", "registry"));
        var missing = await new GpoRunner(_ => Path.Combine(_root, "absent")).RunAsync(Context.Query("gpo", "key", ("part", "gpt")),
            Context.For(new FakeConnection("example.org")), CancellationToken.None);

        var versions = Assert.Single(gpt.Rows);
        Assert.Equal(("2", "2"), (versions["machineVersion"]!.ToString(), versions["userVersion"]!.ToString()));
        Assert.Equal("partial", registry.State);   // the one GPO with a Registry.pol has a corrupt one; the other has none
        Assert.Contains("1 of 2", registry.Reason, StringComparison.Ordinal);
        Assert.Equal("failed", missing.State);
    }

    [Theory]
    [InlineData("example.org", "example.org")]
    [InlineData("ldaps://dc1.example.org:636", "dc1.example.org")]
    [InlineData(@"\\evil\share", null)]
    [InlineData("example", null)]
    public void The_domain_comes_from_the_ldap_endpoint(string endpoint, string? domain) => Assert.Equal(domain, GpoRunner.Domain(endpoint));
}
