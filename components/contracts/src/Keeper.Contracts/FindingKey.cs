using System.Security.Cryptography;
using System.Text;

namespace Keeper.Contracts;

public static class FindingKey
{
    /// <summary>
    /// The stable id of a finding: SHA-256 of instance|check|target, lower-cased. The instance is the
    /// integration that was scanned (two forests are two instances), so the same problem on the same
    /// target keeps the same key on every run, and twin estates never collide.
    /// </summary>
    public static string For(string instance, string checkId, string target) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{instance}|{checkId}|{target}".ToLowerInvariant())));
}
