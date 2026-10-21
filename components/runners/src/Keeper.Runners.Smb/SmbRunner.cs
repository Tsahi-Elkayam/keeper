using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Smb;

/// <summary>
/// smb: a Windows host's file shares, read in-process through the Windows API as the user Keeper runs as -
/// read: shares (every share: name, type, remark, and with acl: true its permissions), share-acl (one
/// share's permissions), or ntfs (the NTFS permissions of a path on the host, given as share\folder, e.g.
/// C$\ProgramData\App). Permissions come one row per entry: identity (a SID), type, rights, inherited. Per
/// target host; nothing is ever written.
/// </summary>
public sealed partial class SmbRunner : IRunner
{
    private static readonly string[] Reads = ["shares", "share-acl", "ntfs"];

    public string Protocol => "smb";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        var read = query.Text("read");
        if (read is null || !Reads.Contains(read))
            yield return $"read must be {string.Join(", ", Reads)}";
        if (read == "share-acl" && !IsShareName(query.Text("share")))
            yield return "share-acl needs share: the share's name (letters, digits, - _ . $)";
        if (read == "ntfs" && PathProblem(query.Text("path")) is { } problem)
            yield return problem;
        if (query.Text("acl") is not (null or "true" or "false"))
            yield return "acl must be true or false";
    }

    private static bool IsShareName(string? name) =>
        name is { Length: > 0 and <= 80 } && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '$' or ' ') && name.Trim('.').Length > 0;

    /// <summary>A path on the target host: share\folder... - never another host, a drive letter or a step up.</summary>
    public static string? PathProblem(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "ntfs needs path: share\\folder on the host, such as C$\\ProgramData";
        if (path.StartsWith('\\') || path.StartsWith('/') || path.Contains(':', StringComparison.Ordinal) || path.Contains('/', StringComparison.Ordinal))
            return "path is share\\folder on the target host - not a UNC path, a drive letter or another host";
        var parts = path.Split('\\');
        if (parts.Any(p => p is "" or "." or ".."))
            return "path must not have empty, . or .. parts";
        if (!IsShareName(parts[0]))
            return $"'{parts[0]}' is not a share name";
        if (path.Any(c => char.IsControl(c) || c is '*' or '?' or '"' or '<' or '>' or '|'))
            return "path has characters a path cannot have";
        return null;
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(RunnerResult.Failed("smb reads need Windows"));
        if (context.Connection.AuthKind != "negotiate")
            return Task.FromResult(RunnerResult.Failed("smb reads run as the Windows user Keeper runs as: the integration's auth must be negotiate"));
        // A plain host name only: host@SSL or host@8443 would go to the WebDAV redirector over HTTP, with this
        // user's credentials, and %, # or ? are no part of a host.
        var host = context.Target;
        if (string.IsNullOrWhiteSpace(host) || host.Trim('.').Length == 0
            || !host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_'))
            return Task.FromResult(RunnerResult.Failed("the target is not a plain host name"));
        return Task.Run(() => !OperatingSystem.IsWindows() ? RunnerResult.Failed("smb reads need Windows") : query.Text("read") switch
        {
            "shares" => Shares(host, query.Text("acl") == "true"),
            "share-acl" => ShareAcl(host, query.Text("share")!),
            _ => Ntfs(host, query.Text("path")!),
        }, cancellationToken);
    }

    private const uint SpecialShare = 0x80000000;
    private const int MaxPreferredLength = -1;
    private const int MoreData = 234;

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Shares(string host, bool withAcl)
    {
        var rows = new List<JsonObject>();
        var resume = 0;
        int status;
        do
        {
            status = NetShareEnum(host, 1, out var buffer, MaxPreferredLength, out var read, out _, ref resume);
            if (status is not (0 or MoreData))
                return RunnerResult.Failed($"{host}: the shares could not be listed ({Describe(status)})");
            try
            {
                var size = Marshal.SizeOf<ShareInfo1>();
                for (var i = 0; i < read; i++)
                {
                    var info = Marshal.PtrToStructure<ShareInfo1>(buffer + (i * size));
                    rows.Add(new JsonObject
                    {
                        ["host"] = host,
                        ["name"] = Marshal.PtrToStringUni(info.NetName),
                        ["type"] = ShareType(info.Type),
                        ["special"] = (info.Type & SpecialShare) != 0,
                        ["remark"] = Marshal.PtrToStringUni(info.Remark),
                    });
                }
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        while (status == MoreData);

        if (!withAcl)
            return RunnerResult.Ok(rows);
        // Each disk share's permissions beside it. Reading them needs admin rights on the host: a share that
        // cannot be read is unknown, never "no permissions".
        var problems = new List<string>();
        foreach (var share in rows.Where(r => r["type"]!.ToString() == "disk"))
        {
            var acl = ShareAcl(host, share["name"]!.ToString());
            if (acl.State == "failed")
            {
                problems.Add(acl.Reason!);
                continue;
            }
            share["path"] = acl.Rows.FirstOrDefault()?["path"]?.DeepClone();
            share["acl"] = new JsonArray([.. acl.Rows.Select(r => (JsonNode?)Entry(r))]);
        }
        return problems.Count == 0 ? RunnerResult.Ok(rows)
            : RunnerResult.Partial(rows, $"{problems.Count} share(s) without their permissions: {string.Join("; ", problems.Take(3))}");

        static JsonObject Entry(JsonObject r) => new()
        {
            ["identity"] = r["identity"]?.DeepClone(), ["account"] = r["account"]?.DeepClone(), ["type"] = r["type"]?.DeepClone(),
            ["rights"] = r["rights"]?.DeepClone(), ["mask"] = r["mask"]?.DeepClone(),
        };
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult ShareAcl(string host, string share)
    {
        var status = NetShareGetInfo(host, share, 502, out var buffer);
        if (status != 0)
            return RunnerResult.Failed($"{host}\\{share}: its permissions could not be read ({Describe(status)})");
        try
        {
            var info = Marshal.PtrToStructure<ShareInfo502>(buffer);
            var path = Marshal.PtrToStringUni(info.Path);
            if (info.SecurityDescriptor == IntPtr.Zero)
            {
                // No descriptor at all: everyone has full control.
                return RunnerResult.Ok([new JsonObject
                {
                    ["host"] = host, ["share"] = share, ["path"] = path, ["identity"] = "S-1-1-0", ["account"] = "Everyone", ["type"] = "allow",
                    ["rights"] = "FullControl", ["mask"] = 0x1F01FF, ["inherited"] = false, ["noDescriptor"] = true,
                }]);
            }
            var length = GetSecurityDescriptorLength(info.SecurityDescriptor);
            var bytes = new byte[length];
            Marshal.Copy(info.SecurityDescriptor, bytes, 0, length);
            RawSecurityDescriptor descriptor;
            try
            {
                descriptor = new RawSecurityDescriptor(bytes, 0);
            }
            catch (ArgumentException)
            {
                return RunnerResult.Failed($"{host}\\{share}: its permissions could not be read (a malformed descriptor)");
            }
            var rows = new List<JsonObject>();
            if (descriptor.DiscretionaryAcl is null)
            {
                rows.Add(new JsonObject
                {
                    ["identity"] = "S-1-1-0", ["account"] = "Everyone", ["type"] = "allow", ["rights"] = "FullControl", ["mask"] = 0x1F01FF,
                    ["inherited"] = false, ["noDescriptor"] = true,
                });
            }
            else
            {
                foreach (var ace in descriptor.DiscretionaryAcl.OfType<CommonAce>())
                    rows.Add(new JsonObject
                    {
                        ["identity"] = ace.SecurityIdentifier.Value, ["account"] = Account(ace.SecurityIdentifier),
                        ["type"] = ace.AceQualifier == AceQualifier.AccessDenied ? "deny" : "allow",
                        ["rights"] = ShareRights(ace.AccessMask), ["mask"] = ace.AccessMask, ["inherited"] = false,
                    });
            }
            foreach (var row in rows)
            {
                row["host"] = host;
                row["share"] = share;
                row["path"] = path;
                row["owner"] = descriptor.Owner?.Value;
            }
            return RunnerResult.Ok(rows);
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Ntfs(string host, string path)
    {
        var unc = $@"\\{host}\{path}";
        try
        {
            FileSystemSecurity security;
            if (Directory.Exists(unc))
                security = new DirectoryInfo(unc).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            else if (File.Exists(unc))
                security = new FileInfo(unc).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            else
                return RunnerResult.Failed($"{unc} is not there, or cannot be seen as this user");
            var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value;
            // A null DACL gives everyone every right, and lists no rule at all: said as itself, never as "nothing".
            if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
                return RunnerResult.Ok([new JsonObject
                {
                    ["host"] = host, ["path"] = path, ["owner"] = owner, ["identity"] = "S-1-1-0", ["account"] = "Everyone", ["type"] = "allow",
                    ["rights"] = "FullControl", ["mask"] = (int)FileSystemRights.FullControl, ["inherited"] = false, ["noDescriptor"] = true,
                }]);
            var rows = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>()
                .Select(rule => new JsonObject
                {
                    ["host"] = host, ["path"] = path, ["owner"] = owner,
                    ["identity"] = rule.IdentityReference.Value, ["account"] = Account((SecurityIdentifier)rule.IdentityReference),
                    ["type"] = rule.AccessControlType == AccessControlType.Deny ? "deny" : "allow",
                    ["rights"] = rule.FileSystemRights.ToString(), ["mask"] = (int)rule.FileSystemRights,
                    ["inherited"] = rule.IsInherited, ["inheritance"] = rule.InheritanceFlags.ToString(), ["propagation"] = rule.PropagationFlags.ToString(),
                })
                .ToList();
            return RunnerResult.Ok(rows);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PrivilegeNotHeldException or System.ComponentModel.Win32Exception or ArgumentException)
        {
            return RunnerResult.Failed($"{unc}: its permissions could not be read ({ex.Message})");
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> Accounts = new(StringComparer.Ordinal);

    /// <summary>
    /// The account's name where this machine can tell it (a domain account), else null: rules compare SIDs.
    /// Each SID is asked once per process - the same few groups appear on every share.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? Account(SecurityIdentifier sid) => Accounts.GetOrAdd(sid.Value, _ =>
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return null;
        }
    });

    private static string ShareType(uint type) => (type & 0xFF) switch
    {
        0 => "disk", 1 => "printer", 2 => "device", 3 => "ipc", _ => "other",
    };

    /// <summary>Share permissions as the Sharing dialog names them.</summary>
    private static string ShareRights(int mask) => mask switch
    {
        0x1F01FF => "FullControl",
        0x1301BF => "Change",
        0x1200A9 => "Read",
        _ => $"0x{mask:X}",
    };

    private static string Describe(int status) => status switch
    {
        5 => "access denied: this needs administrator rights on the host",
        53 => "the host could not be reached",
        67 => "no such share",
        1722 => "the host's RPC server is not answering",
        2310 => "no such share",
        _ => $"error {status}",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo1
    {
        public IntPtr NetName;
        public uint Type;
        public IntPtr Remark;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo502
    {
        public IntPtr NetName;
        public uint Type;
        public IntPtr Remark;
        public uint Permissions;
        public uint MaxUses;
        public uint CurrentUses;
        public IntPtr Path;
        public IntPtr Password;
        public uint Reserved;
        public IntPtr SecurityDescriptor;
    }

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetShareEnum(string serverName, int level, out IntPtr buffer, int preferredMaxLength, out int entriesRead, out int totalEntries, ref int resumeHandle);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetShareGetInfo(string serverName, string netName, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    [LibraryImport("advapi32.dll")]
    private static partial int GetSecurityDescriptorLength(IntPtr descriptor);
}
