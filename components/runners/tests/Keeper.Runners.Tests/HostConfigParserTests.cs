using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class HostConfigParserTests
{
    [Fact]
    public void Key_value_files_give_one_row_per_setting_with_comments_and_both_separators_handled()
    {
        var rows = ConfigParsers.Kv("""
            # sshd
            PermitRootLogin yes
              PasswordAuthentication   no   # trailing comment
            Port=22
            """, "sshd_config");

        Assert.Equal(["permitrootlogin", "passwordauthentication", "port"], rows.Select(r => r["name"]!.ToString()));
        Assert.Equal(["yes", "no", "22"], rows.Select(r => r["value"]!.ToString()));
        Assert.Equal("PermitRootLogin", rows[0]["key"]!.ToString());
        Assert.Equal(["2", "3", "4"], rows.Select(r => r["line"]!.ToString()));
        Assert.All(rows, r => Assert.Equal("sshd_config", r["file"]!.ToString()));
    }

    [Fact]
    public void A_repeated_key_is_a_row_each()
    {
        var rows = ConfigParsers.Kv("Listen 80\nListen 443\n", "f");

        Assert.Equal(2, rows.Count);
    }

    [Fact]
    public void Ini_files_carry_their_section()
    {
        var rows = ConfigParsers.Ini("""
            top = 1
            [mysqld]
            bind-address = 0.0.0.0
            ; comment
            [client]
            port=3306
            """, "my.cnf");

        Assert.Equal(("", "top", "1"), (rows[0]["section"]!.ToString(), rows[0]["name"]!.ToString(), rows[0]["value"]!.ToString()));
        Assert.Equal(("mysqld", "bind-address", "0.0.0.0"), (rows[1]["section"]!.ToString(), rows[1]["name"]!.ToString(), rows[1]["value"]!.ToString()));
        Assert.Equal(("client", "port", "3306"), (rows[2]["section"]!.ToString(), rows[2]["name"]!.ToString(), rows[2]["value"]!.ToString()));
    }

    [Fact]
    public void An_nginx_config_becomes_directives_with_their_enclosing_blocks()
    {
        var rows = ConfigParsers.Directives("""
            user nginx;
            http {
                server_tokens on;
                server {
                    listen 443 ssl;
                    ssl_protocols TLSv1 TLSv1.2;   # old
                    location / { autoindex on; }
                }
            }
            """, "nginx.conf", "nginx");

        JsonRow Row(string name) => new(rows.First(r => r["name"]!.ToString() == name));

        Assert.Equal("", Row("user").Context);
        Assert.Equal("http", Row("server_tokens").Context);
        Assert.Equal("on", Row("server_tokens").Value);
        Assert.Equal("http > server", Row("listen").Context);
        Assert.Equal("443 ssl", Row("listen").Value);
        Assert.Equal(["443", "ssl"], Row("listen").Args);
        Assert.Equal("TLSv1 TLSv1.2", Row("ssl_protocols").Value);
        Assert.Equal("http > server > location /", Row("autoindex").Context);
        Assert.True(Row("http").IsBlock);
        Assert.False(Row("listen").IsBlock);
    }

    [Fact]
    public void An_apache_config_becomes_directives_with_their_sections_and_continued_lines()
    {
        var rows = ConfigParsers.Directives("""
            ServerTokens Full
            <VirtualHost *:80>
              SSLProtocol all \
                  -SSLv3
              ErrorLog "logs/error log"
            </VirtualHost>
            """, "httpd.conf", "apache");

        JsonRow Row(string name) => new(rows.First(r => r["name"]!.ToString() == name));

        Assert.Equal("Full", Row("servertokens").Value);
        Assert.True(Row("virtualhost").IsBlock);
        Assert.Equal(["*:80"], Row("virtualhost").Args);
        Assert.Equal("VirtualHost *:80", Row("sslprotocol").Context);
        Assert.Equal("all -SSLv3", Row("sslprotocol").Value);
        Assert.Equal(["logs/error log"], Row("errorlog").Args);
    }

    [Fact]
    public void Nonsense_is_a_parse_error_not_a_silent_empty_answer()
    {
        Assert.Throws<FormatException>(() => ConfigParsers.Directives("http { server { listen 80;", "nginx.conf", "nginx"));
        Assert.Throws<FormatException>(() => ConfigParsers.Directives("</VirtualHost>", "httpd.conf", "apache"));
    }

    private readonly record struct JsonRow(System.Text.Json.Nodes.JsonObject Row)
    {
        public string Context => Row["context"]!.ToString();
        public string Value => Row["value"]!.ToString();
        public bool IsBlock => (bool)Row["block"]!;
        public string[] Args => [.. Row["args"]!.AsArray().Select(a => a!.ToString())];
    }
}
