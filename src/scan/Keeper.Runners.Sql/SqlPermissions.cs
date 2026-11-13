using System.Text.RegularExpressions;

namespace Keeper.Runners.Sql;

/// <summary>
/// SQL Server never refuses a read for want of a view permission: it shows less. Without VIEW SERVER
/// STATE the dynamic management views show only the login's own sessions and requests; without VIEW ANY
/// DEFINITION the catalog views show only what the login owns or was granted. A query that reads them
/// with the permission missing is therefore partial, with the reason, never a clean answer.
/// </summary>
public static partial class SqlPermissions
{
    /// <summary>
    /// Who the server sees, and whether it may see all of the dynamic and the catalog views (1 = held). Azure
    /// SQL Database (engine edition 5) has no server permissions: there the database's VIEW DATABASE STATE and
    /// VIEW DEFINITION decide. A permission the server does not know counts as not held.
    /// </summary>
    public const string Probe =
        """
        SELECT SUSER_SNAME(),
               CASE WHEN SERVERPROPERTY('EngineEdition') = 5 THEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DATABASE STATE')
                    ELSE HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE') END,
               CASE WHEN SERVERPROPERTY('EngineEdition') = 5 THEN HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION')
                    ELSE HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION') END;
        """;

    /// <summary>Why this query's answer is incomplete for this login, or null when it can see everything it reads.</summary>
    public static string? Missing(string text, string login, bool serverState, bool anyDefinition)
    {
        var lacks = new List<string>();
        if (!serverState && DynamicViews().IsMatch(text))
            lacks.Add("VIEW SERVER STATE (sys.dm_ views show only its own sessions)");
        if (!anyDefinition && CatalogViews().IsMatch(text))
            lacks.Add("VIEW ANY DEFINITION (catalog views show only what it owns or was granted)");
        return lacks.Count == 0 ? null : $"read as {login}, which lacks {string.Join(" and ", lacks)}";
    }

    [GeneratedRegex(@"\bsys\s*\.\s*dm_", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DynamicViews();

    // Catalog views whose rows depend on metadata visibility: what the login owns or was granted. sys.databases
    // (VIEW ANY DATABASE is public's by default) and sys.configurations show every row, so they are not here.
    [GeneratedRegex(@"\bsys\s*\.\s*(server_principals|sql_logins|server_role_members|server_permissions|credentials|endpoints|linked_logins|servers|server_audits|server_audit_specifications|server_triggers|database_principals|database_permissions|database_role_members|database_audit_specifications|certificates|asymmetric_keys|symmetric_keys|master_key_passwords|objects|all_objects|tables|views|procedures|schemas|columns|indexes|triggers|sql_modules|synonyms|foreign_keys|assemblies|database_scoped_credentials)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CatalogViews();
}
