using Keeper.Rules;

namespace Keeper.Scan;

/// <summary>Where rule files come from: the generic ones shipped beside the binaries, then the tenant's own.</summary>
public static class RuleSources
{
    /// <summary>rules\ beside the binaries (the repo's rules\ folder is copied there by the build).</summary>
    public static string BuiltIn => Path.Combine(AppContext.BaseDirectory, "rules");

    public static RuleSet Load(string? tenantRules, IEnumerable<string>? extraFolders = null)
    {
        var folders = new List<(string, string)> { (BuiltIn, "builtin") };
        if (tenantRules is not null)
            folders.Add((tenantRules, "tenant"));
        foreach (var folder in extraFolders ?? [])
            folders.Add((folder, "extra"));
        return RuleLoader.LoadAll(folders, Runners.Registry().Validators);
    }
}
