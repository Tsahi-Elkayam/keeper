using System.Security.Cryptography;
using System.Text;

namespace Keeper.Core;

public static class FindingKey
{
    /// <summary>
    /// The stable id of a finding: SHA-256 of system|check|target, lower-cased. The same problem
    /// on the same target keeps the same key on every run.
    /// </summary>
    public static string For(string systemId, string checkId, string target) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{systemId}|{checkId}|{target}".ToLowerInvariant())));
}
