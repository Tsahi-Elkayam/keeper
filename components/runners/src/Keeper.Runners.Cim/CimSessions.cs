using System.Security;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace Keeper.Runners.Cim;

/// <summary>A WinRM (WSMan) CIM session to one host: Kerberos as the current user, or the integration's credential.</summary>
internal static class CimSessions
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CimSession Open(string host, RunnerContext context)
    {
        using var options = new WSManSessionOptions { Timeout = context.Timeout };
        var credential = context.Connection.WindowsCredential();
        if (credential is not null)
        {
            using var password = new SecureString();
            foreach (var c in credential.Password)
                password.AppendChar(c);
            options.AddDestinationCredentials(new CimCredential(PasswordAuthenticationMechanism.Kerberos, credential.Domain, credential.UserName, password));
        }
        return CimSession.Create(host, options);
    }
}
