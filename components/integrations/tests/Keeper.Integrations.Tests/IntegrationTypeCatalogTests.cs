using Keeper.Integrations;

namespace Keeper.Integrations.Tests;

/// <summary>
/// Integration types as data: the built-in catalog, and the types a tenant adds - which can add a product without
/// code, but never replace a built-in type or name a protocol or sign-in Keeper has no code for.
/// </summary>
public sealed class IntegrationTypeCatalogTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-types-").FullName;

    public void Dispose()
    {
        IntegrationTypes.UseTenantFolder(Path.Combine(_dir, "none"));
        Directory.Delete(_dir, recursive: true);
    }

    private const string PaloAlto = """
        schema: keeper.integration-types/1
        types:
          - id: palo-alto
            description: Palo Alto PAN-OS XML API, show and get only
            protocols: [http]
            auth: [api-key-header]
            readPaths: ['/api/']
            readPosts: ['/api/']
        """;

    private static IReadOnlyList<IntegrationType> Tenant(string yaml) =>
        IntegrationTypeCatalog.Parse(yaml, "test.yaml", IntegrationTypes.BuiltIn);

    [Fact]
    public void The_built_in_catalog_loads_with_its_guards()
    {
        var all = IntegrationTypes.BuiltIn;

        Assert.Equal(38, all.Count);
        Assert.Equal(all.Count, all.Select(t => t.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(all, t => Assert.Null(t.Source));
        Assert.All(all.SelectMany(t => t.AuthKinds), kind => Assert.True(IntegrationTypes.SecretsFor.ContainsKey(kind), kind));
        Assert.DoesNotContain("/secrets/*", IntegrationTypes.Find("key-vault")!.ReadPaths);   // a secret's value is never a read
        Assert.Contains("GetMailboxLog", IntegrationTypes.Find("exchange-online")!.ReadCommand!.DeniedParameters);
        Assert.Contains("*.crm22.dynamics.com", IntegrationTypes.Find("dataverse")!.AllowedHosts);
        Assert.Equal("https://service.powerapps.com/", IntegrationTypes.Find("power-apps")!.Resource);
    }

    [Fact]
    public void A_tenant_adds_a_product_without_code()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "types"));
        File.WriteAllText(Path.Combine(_dir, "types", "palo-alto.yaml"), PaloAlto);

        IntegrationTypes.UseTenantFolder(Path.Combine(_dir, "types"));

        var type = IntegrationTypes.Find("palo-alto");
        Assert.NotNull(type);
        Assert.EndsWith("palo-alto.yaml", type.Source, StringComparison.Ordinal);
        Assert.True(type.Guarded);
        Assert.Equal(["/api/"], type.ReadPaths);
        Assert.Contains(IntegrationTypes.All, t => t.Id == "graph");   // the built-in ones stay

        IntegrationTypes.UseTenantFolder(Path.Combine(_dir, "missing"));
        Assert.Null(IntegrationTypes.Find("palo-alto"));                // a folder's types are replaced, not added to
    }

    [Theory]
    [InlineData("id: graph", "cannot replace")]
    [InlineData("protocols: [store]", "protocol 'store'")]
    [InlineData("protocols: [host]", "protocol 'host'")]
    [InlineData("protocols: [telnet]", "protocol 'telnet'")]
    [InlineData("auth: [kerberos-keytab]", "auth kind 'kerberos-keytab'")]
    [InlineData("readpaths: ['/api/']", "readpaths")]                 // a misspelt guard is an error, not "read anything"
    [InlineData("endpoint: http://fw.example.org", "https")]
    [InlineData("hosts: ['https://fw.example.org']", "host name")]
    [InlineData("readPosts: ['api/']", "must start with /")]
    [InlineData("id: Palo_Alto", "lower-case")]
    [InlineData("auth: [entra-certificate]", "needs hosts")]           // a Graph token to whatever host the endpoint names
    [InlineData("auth: [aws-access-key]", "needs hosts")]
    [InlineData("auth: [gcp-service-account]", "needs hosts")]
    [InlineData("hosts: ['*.com']", "two labels")]
    [InlineData("readPaths: ['/a']\n    readPaths: ['/b']", "duplicate")]
    public void What_a_tenant_type_may_not_say_is_said(string line, string expected)
    {
        // The line replaces the type's own line with that key, or is added to it.
        var key = line[..line.IndexOf(':', StringComparison.Ordinal)];
        var yaml = key == "id"
            ? PaloAlto.Replace("id: palo-alto", line, StringComparison.Ordinal)
            : string.Join('\n', PaloAlto.Split('\n').Where(l => !l.TrimStart().StartsWith(key + ":", StringComparison.Ordinal)))
                .Replace("  - id: palo-alto", "  - id: palo-alto\n    " + line, StringComparison.Ordinal);

        var ex = Assert.Throws<IntegrationException>(() => Tenant(yaml));

        Assert.Contains(expected, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void An_endpoint_must_be_on_the_type_s_own_hosts()
    {
        var yaml = PaloAlto + "\n    hosts: ['*.paloaltonetworks.com']\n    endpoint: 'https://evil.example.org'";

        Assert.Throws<IntegrationException>(() => Tenant(yaml));
    }

    [Fact]
    public void A_cloud_sign_in_behind_its_own_hosts_is_allowed()
    {
        var yaml = PaloAlto.Replace("auth: [api-key-header]", "auth: [entra-certificate]\n    hosts: ['*.contoso.example']", StringComparison.Ordinal);

        var type = Assert.Single(Tenant(yaml));

        Assert.False(type.AllowsHost("attacker.example"));
    }

    [Fact]
    public void An_empty_entry_is_said()
    {
        Assert.Throws<IntegrationException>(() => Tenant("schema: keeper.integration-types/1\ntypes:\n  -\n"));
    }

    [Fact]
    public void One_type_in_two_tenant_files_is_said()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "twice"));
        File.WriteAllText(Path.Combine(_dir, "twice", "a.yaml"), PaloAlto);
        File.WriteAllText(Path.Combine(_dir, "twice", "b.yaml"), PaloAlto);

        var ex = Assert.Throws<IntegrationException>(() => IntegrationTypes.UseTenantFolder(Path.Combine(_dir, "twice")));

        Assert.Contains("also defined in", ex.Message, StringComparison.Ordinal);
    }
}
