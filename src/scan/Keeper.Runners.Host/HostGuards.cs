using System.Text.RegularExpressions;

namespace Keeper.Runners.Host;

/// <summary>
/// What a host read may open. Keeper looks at configuration, never at secrets: a file that holds credentials or
/// keys is refused by its path (also after following a link) and by its content.
/// </summary>
public static class HostGuards
{
    public const long MaxFileBytes = 5L * 1024 * 1024;
    public const int MaxIncludeDepth = 8;
    public const int MaxFiles = 200;

    private static readonly string[] SecretFiles =
    [
        "/etc/shadow", "/etc/gshadow", "/etc/master.passwd", "/private/etc/master.passwd", "/etc/security/opasswd",
        "/etc/krb5.keytab", "/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets",
    ];

    private static readonly string[] SecretFolders =
    [
        "/.gnupg/", "/library/keychains/", "/ssl/private/", "/var/db/dslocal/", "/.ssh/id_", "/.aws/credentials", "/.kube/config",
        "/.docker/config.json", "/.netrc", "/.pgpass", "/.azure/", "/.config/gcloud/",
    ];

    // Folders whose files are credentials or keys: a folder read never opens one of them.
    private static readonly string[] SecretFolderMarkers =
    [
        "/.gnupg/", "/library/keychains/", "/ssl/private/", "/var/db/dslocal/", "/.ssh/", "/.aws/", "/.kube/", "/.docker/", "/.azure/",
        "/.config/gcloud/", "/etc/shadow.d/", "/proc/",
    ];

    private static readonly string[] SecretExtensions = [".key", ".pfx", ".p12", ".keytab", ".kdbx", ".jks", ".ppk"];

    private static readonly Regex ProcEnvironment = new(@"^/proc/[^/]+/(environ|mem|maps)$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Why a path may not be given to a host read when a rule is loaded, or null.</summary>
    public static string? PathProblem(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "path is required";
        if (!Path.IsPathRooted(path))
            return "path must be absolute";
        if (path.Replace('\\', '/').Split('/').Any(s => s == ".."))
            return "path must not contain ..";
        return IsSecretPath(path) ? "that path holds secrets (credentials or keys); host reads never open it" : null;
    }

    /// <summary>Why a folder may not be read when a rule is loaded, or null: absolute, no "..", and not a folder of secrets.</summary>
    public static string? FolderProblem(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder))
            return "folder is required";
        if (!Path.IsPathRooted(folder))
            return "folder must be absolute";
        if (folder.Replace('\\', '/').Split('/').Any(s => s == ".."))
            return "folder must not contain ..";
        var normal = folder.Replace('\\', '/').TrimEnd('/').ToLowerInvariant() + "/";
        return SecretFolderMarkers.Any(m => normal.Contains(m, StringComparison.Ordinal))
            ? "that folder holds secrets (credentials or keys); host reads never open it"
            : null;
    }

    public static bool IsSecretPath(string path)
    {
        var normal = path.Replace('\\', '/').ToLowerInvariant();
        var name = normal[(normal.LastIndexOf('/') + 1)..];
        return SecretFiles.Contains(normal, StringComparer.Ordinal)
            || SecretFolders.Any(f => f.EndsWith('/') ? normal.Contains(f, StringComparison.Ordinal) : normal.Contains(f, StringComparison.Ordinal) && !name.EndsWith(".pub", StringComparison.Ordinal))
            || SecretExtensions.Any(e => name.EndsWith(e, StringComparison.Ordinal))
            || ProcEnvironment.IsMatch(normal);
    }

    /// <summary>
    /// Why a file may not be read now, or null. Follows links first: a harmless name that points at a key is
    /// still the key. Sniffs the start of the file for a private key whatever it is called.
    /// </summary>
    public static string? ReadProblem(string path)
    {
        string final = path;
        try
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null && info.ResolveLinkTarget(returnFinalTarget: true) is { } target)
                final = target.FullName;
        }
        catch (IOException)
        {
            return "its link could not be followed";
        }
        if (IsSecretPath(final))
            return "it points at a file that holds secrets (credentials or keys); host reads never open it";
        if (!File.Exists(final))
            return null;
        var length = new FileInfo(final).Length;
        if (length > MaxFileBytes)
            return $"it is larger than {MaxFileBytes / (1024 * 1024)} MB";
        try
        {
            using var stream = new FileStream(final, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var head = new byte[(int)Math.Min(length, 4096)];
            stream.ReadExactly(head);
            if (System.Text.Encoding.ASCII.GetString(head).Contains("PRIVATE KEY-----", StringComparison.Ordinal))
                return "it holds a private key; host reads never open it";
        }
        catch (UnauthorizedAccessException)
        {
            return "it cannot be read by the account Keeper runs as";
        }
        return null;
    }
}
