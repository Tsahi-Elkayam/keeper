using System.Text.Json.Nodes;

namespace Keeper.Runners.Tests;

public sealed class CredentialMaskingTests
{
    [Theory]
    [InlineData("DB_PASSWORD=hunter2", "DB_PASSWORD=set")]
    [InlineData("--password=hunter2", "--password=set")]
    [InlineData("api_key: abc123", "api_key: set")]
    [InlineData("MODE=prod", "MODE=prod")]
    [InlineData("--port=8080", "--port=8080")]
    [InlineData("PasswordAuthentication=no", "PasswordAuthentication=no")]      // a setting about passwords, not one
    [InlineData("ssl_password_file=/etc/pw.txt", "ssl_password_file=/etc/pw.txt")]   // a path to one is only a path
    [InlineData("sleep", "sleep")]
    public void Credential_text_loses_its_value_and_keeps_its_name(string text, string expected)
    {
        Assert.Equal(expected, CredentialText.Scrub(text));
    }

    [Fact]
    public void A_kubectl_annotation_that_holds_the_whole_applied_manifest_is_masked()
    {
        var pod = JsonNode.Parse("""
            { "metadata": { "name": "bad-host", "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": "{\"spec\":{\"containers\":[{\"env\":[{\"name\":\"DB_PASSWORD\",\"value\":\"hunter2\"}]}]}}",
                "team": "payments" } } }
            """)!;

        SecretProperties.Mask(pod);

        var annotations = pod["metadata"]!["annotations"]!;
        Assert.Equal("set", annotations["kubectl.kubernetes.io/last-applied-configuration"]!.ToString());
        Assert.Equal("payments", annotations["team"]!.ToString());
        Assert.DoesNotContain("hunter2", pod.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Container_commands_and_arguments_are_scrubbed_but_keep_their_shape()
    {
        var container = JsonNode.Parse("""{ "name": "c", "command": ["app", "--password=hunter2", "--port=8080"], "args": ["--api_key=abc123", "serve"] }""")!;

        SecretProperties.Mask(container);

        Assert.Equal(["app", "--password=set", "--port=8080"], container["command"]!.AsArray().Select(n => n!.ToString()));
        Assert.Equal(["--api_key=set", "serve"], container["args"]!.AsArray().Select(n => n!.ToString()));
    }

    [Fact]
    public void A_docker_environment_list_of_name_value_strings_is_scrubbed()
    {
        var config = JsonNode.Parse("""{ "Config": { "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2", "MODE=prod"], "Cmd": ["run", "--secret=abc"], "Entrypoint": ["/entry.sh"] } }""")!;

        SecretProperties.Mask(config);

        Assert.Equal(["PATH=/usr/bin", "DB_PASSWORD=set", "MODE=prod"], config["Config"]!["Env"]!.AsArray().Select(n => n!.ToString()));
        Assert.Equal(["run", "--secret=set"], config["Config"]!["Cmd"]!.AsArray().Select(n => n!.ToString()));
        Assert.Equal(["/entry.sh"], config["Config"]!["Entrypoint"]!.AsArray().Select(n => n!.ToString()));
    }

    [Fact]
    public void Other_lists_are_left_alone()
    {
        var node = JsonNode.Parse("""{ "tags": ["password=notasecret"], "items": ["a=b"] }""")!;

        SecretProperties.Mask(node);

        Assert.Equal("password=notasecret", node["tags"]![0]!.ToString());
    }
}
