using System.Security.AccessControl;
using System.Security.Principal;

namespace Keeper.Home;

/// <summary>
/// The Keeper home holds a map of the estate's weaknesses and its encrypted credentials, so it must
/// be readable by its owner only - the way ssh refuses a private key that others can read.
/// </summary>
public static class HomeSecurity
{
    /// <summary>Set KEEPER_ALLOW_SHARED_HOME=1 to accept a shared folder (and own that decision).</summary>
    public const string OverrideVariable = "KEEPER_ALLOW_SHARED_HOME";

    public static void EnsurePrivate(string folder, string what)
    {
        if (Environment.GetEnvironmentVariable(OverrideVariable) == "1" || !Directory.Exists(folder))
            return;

        var problem = Problem(folder);
        if (problem is not null)
            throw new SettingsException(
                $"{what} ({folder}) {problem}. Run 'keeper setup' to make it private, or set {OverrideVariable}=1 to accept it.");
    }

    /// <summary>Why the folder is not private, or null when it is.</summary>
    public static string? Problem(string folder)
    {
        if (OperatingSystem.IsWindows())
            return WindowsProblem(folder);

        var mode = File.GetUnixFileMode(folder);
        const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                    UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        return (mode & others) != 0 ? "is readable by other users (mode is not 700)" : null;
    }

    /// <summary>Owner-only: the current user, SYSTEM and Administrators; inheritance off.</summary>
    public static void MakePrivate(string folder)
    {
        Directory.CreateDirectory(folder);
        if (OperatingSystem.IsWindows())
        {
            MakePrivateWindows(folder);
            return;
        }
        File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? WindowsProblem(string folder)
    {
        var security = new DirectoryInfo(folder).GetAccessControl();
        var me = WindowsIdentity.GetCurrent().User;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid == me || IsTrustedSystem(sid))
                continue;
            if ((rule.FileSystemRights & (FileSystemRights.ReadData | FileSystemRights.Read)) != 0)
                return $"is readable by {Describe(sid)}";
        }
        return null;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void MakePrivateWindows(string folder)
    {
        var me = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("No current Windows user.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { me, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(folder).SetAccessControl(security);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsTrustedSystem(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
        sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
        sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string Describe(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }
}
