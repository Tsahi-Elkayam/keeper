using Keeper.Runners;
using Keeper.Runners.Cim;
using Keeper.Runners.Files;
using Keeper.Runners.Http;
using Keeper.Runners.Ldap;
using Keeper.Runners.Sql;
using Keeper.Runners.Tls;

namespace Keeper.Scan;

/// <summary>Every runner this build knows. Composed here, at build time - never loaded from a folder.</summary>
public static class Runners
{
    public static RunnerRegistry Registry() => new(
    [
        new LdapRunner(),
        new GraphRunner(),
        new HttpRunner(),
        new GraphQlRunner(),
        new SqlRunner(),
        new CimRunner(),
        new EventLogRunner(),
        new RegistryRunner(),
        new TlsRunner(),
        new FileRunner(),
        new StoreRunner(),
    ]);
}
