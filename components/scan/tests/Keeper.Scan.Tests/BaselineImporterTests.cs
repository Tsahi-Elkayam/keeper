using Keeper.Rules;

namespace Keeper.Scan.Tests;

public sealed class BaselineImporterTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static BaselineSetting Setting(string path, string name, string op, string expected, string type = "Registry", string scope = "Computer") =>
        new("example-baseline", scope, type, path, name, expected, op, "High", $"Example: {name}", "EX.1.2");

    [Fact]
    public void Registry_settings_become_rules_that_load_and_share_one_read_per_key()
    {
        var settings = new[]
        {
            Setting(@"HKLM\SOFTWARE\Policies\Example\System", "EnableThing", "=", "1"),
            Setting(@"HKLM\\SOFTWARE\Policies\Example\System", "MaxSize", ">=", "32768"),     // a published typo: doubled backslash
            Setting(@"HKLM\SOFTWARE\Policies\Example\Other", "Legacy", "absent", ""),
            Setting(@"HKCU\SOFTWARE\Policies\Example", "UserThing", "=", "1", scope: "User"),
            Setting("", "SeDebugPrivilege", "set", "", type: "PrivilegeRight"),
            Setting(@"HKLM\SOFTWARE\Policies\Example", @"\\*\SYSVOL", "=", "x"),
            Setting(@"HKLM\SOFTWARE\Policies\Example", "Odd", "novalues", ""),
        };

        var import = BaselineImporter.Convert(settings, "example", "servers", "EX");

        Assert.Equal(3, import.Rules);
        Assert.Equal(2, import.Queries);                     // two keys, two reads per host
        Assert.Equal(4, import.Skipped.Count);
        var file = Path.Combine(_dir, "baseline.yaml");
        File.WriteAllText(file, import.Yaml);
        var loaded = RuleLoader.LoadFile(file, "tenant", Runners.Registry().Validators);
        Assert.Equal("baseline-example", loaded.System);
        Assert.Equal(2, loaded.Rules.Select(r => r.Query.Id).Distinct().Count());
        Assert.Contains("EX:1.2", loaded.Rules[0].Refs);
        Assert.All(loaded.Rules, r => Assert.Equal("registry", r.Query.Protocol));
    }

    [Theory]
    [InlineData("hk-cis_microsoft_windows_11_enterprise_24h2_machine", "workstations")]
    [InlineData("hk-msft_security_baseline_windows_server_2025_2602_dc_machine", "dcs")]
    [InlineData("hk-msft_security_baseline_windows_server_2022_21h2_member_machine", "members")]
    [InlineData("sct-server2025", "servers")]
    public void The_target_follows_the_baseline(string baselineId, string target)
    {
        Assert.Equal(target, BaselineImporter.TargetFor(baselineId));
    }
}
