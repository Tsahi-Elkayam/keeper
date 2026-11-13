# Connecting a Microsoft 365 tenant

Keeper reads Entra ID, Intune, Microsoft 365 and Defender through Microsoft Graph, as one app registration that
signs in with a certificate. Every permission it asks for is a Read permission. None of them reads mail, files,
BitLocker keys or LAPS passwords: the rules read settings and metadata only.

This takes about fifteen minutes. It needs an admin who can register an app and grant admin consent (Global
Administrator, or Privileged Role Administrator together with Application Administrator), and the Windows machine
that will run Keeper.

## 0. One Keeper home per tenant

Give each tenant its own Keeper home: its own today list, reports, trends and settings.

```powershell
$env:KEEPER_HOME = 'D:\Keeper\<tenant name>'
keeper setup --tenant <tenant name> --apply
```

A home can read several tenants, each under its own integration name (`--name`), and keeps their findings apart,
but its today list and reports then cover them together; `keeper connect` says so when it adds a second tenant.
It refuses to point an integration that has already scanned one tenant at another, because the two tenants'
findings would mix under the same keys. A tenant id typed wrong can be corrected before the first scan.

## 1. A certificate on the machine that runs Keeper

In PowerShell, as the Windows user that will run Keeper:

```powershell
$cert = New-SelfSignedCertificate -Subject 'CN=Keeper reader' -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeySpec Signature -KeyLength 2048 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(1)
Export-Certificate -Cert $cert -FilePath .\keeper-reader.cer | Out-Null
$cert.Thumbprint
```

The private key stays in this user's store and cannot be exported. Only `keeper-reader.cer` (the public part)
goes to the tenant. Note the thumbprint. Keeper reports the certificate's expiry like any other certificate.

## 2. The app registration

In the Entra admin center (entra.microsoft.com):

1. **Identity > Applications > App registrations > New registration.** Name it `Keeper reader`. Accounts in this
   organizational directory only. No redirect URI.
2. On its **Overview**, note the **Application (client) ID** and the **Directory (tenant) ID**.
3. **Certificates & secrets > Certificates > Upload certificate**, then choose `keeper-reader.cer`. Create no
   client secret.

## 3. The permissions

`keeper connect permissions` lists the Microsoft Graph **application** permissions the shipped rules need, one
per line. They come from the rules themselves: a rule that is added or changed updates the list.

```powershell
keeper connect permissions > permissions.txt
```

Grant them one of two ways.

**In the portal:** **API permissions > Add a permission > Microsoft Graph > Application permissions**. Tick each
permission in the list, then **Grant admin consent for <organization>**.

**With Microsoft Graph PowerShell** (`Install-Module Microsoft.Graph.Applications`). Assigning the roles directly is
the same as admin consent:

```powershell
Connect-MgGraph -TenantId '<tenant id>' -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'
$graph  = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$keeper = Get-MgServicePrincipal -Filter "appId eq '<application id>'"
foreach ($name in Get-Content .\permissions.txt) {
    $role = $graph.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { Write-Warning "${name}: no such application permission here"; continue }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $keeper.Id -PrincipalId $keeper.Id `
        -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null
}
```

A tenant may leave some permissions out, for example `MailboxSettings.Read` (users' inbox forwarding rules) or the
Defender ones when it has no Defender licence. Keeper then runs every other rule and names the ones it held back.

**Conditional Access.** A policy that covers workload identities can block the app's sign-in (AADSTS53003).
Exclude the app, or allow it from the address of the machine that runs Keeper.

## 4. Connect

```powershell
keeper connect microsoft --tenant <tenant id> --client-id <application id> --certificate <thumbprint>
```

This checks that the certificate and its private key are in the store, creates the integration (or updates it),
signs in once, and lists what the consent allows. It reads nothing from the tenant: the token's own claims say
which permissions were granted.

```
Certificate: CN=Keeper reader, valid until 2027-11-13
Integration microsoft: added.

Signed in to <tenant id> as Keeper reader (token until 14:05). Nothing was read from the tenant.

Ready to scan
  defender        5 of 5 rules
  entra         256 of 256 rules
  intune        124 of 124 rules
  m365           55 of 58 rules     (the rest record 'could not check' until the permissions below are granted)

Missing permissions (grant them to the app, then admin-consent; 'keeper connect check' again)
  MailboxSettings.Read                                2 rules: m365 2
  ReportSettings.Read.All                              1 rule: m365 1

Next: keeper run   (or keeper scan entra --plan to see what one scan costs first)
```

After an admin grants more permissions, `keeper connect check` signs in again and recounts. A sign-in that fails
says what to do: an unknown app id, a certificate the tenant does not hold, a wrong tenant id, a Conditional Access
block.

## 5. The first scan

Keeper reads gently by default: four hosts at once, ten requests a second, the server's Retry-After honoured on 429
and 503, and a host that keeps pushing back is left alone for the rest of the run. For Graph, that whole budget is
one host.

```powershell
keeper scan entra --plan       # what the scan would cost: reads, sign-ins, time. Nothing is sent.
keeper scan entra --test       # one rule, one read: proves the path end to end
keeper run                     # every system with an integration
```

To keep scans out of working hours, give the integration a window: `keeper integration set microsoft --option
window=20:00-06:00 --option window.days=Sun-Thu --reason "after hours"`. `keeper run` then skips the integration
outside the window, and says so.

## Not in this guide

Exchange Online, Azure Resource Manager and Power Platform answer on their own APIs, each with its own permissions,
for example Exchange.ManageAsApp plus the View-Only Organization Management role. They can sign in as the same app
and certificate, each as its own integration (`keeper integration add <id> --type exchange-online|azure|power-platform
--auth entra-certificate ...`). docs/backlog/microsoft-cloud.md lists what each needs. Entra Connect is read on its
server over CIM, not through Graph.
