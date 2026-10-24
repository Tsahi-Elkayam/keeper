<#
  A first run of Keeper on THIS Windows machine: its tests, a build, and a read of the machine itself
  (CIM, registry, event log) through the real binary. Everything it prints is also written to
  windows-smoke.log beside the repository, so one file shows what happened.

  Needs: the .NET 10 SDK (winget install Microsoft.DotNet.SDK.10). Run from PowerShell:
      powershell -ExecutionPolicy Bypass -File tools\windows-smoke.ps1
  Add -SkipTests to go straight to the live read.

  It only reads. It creates a throwaway Keeper home under %TEMP% and changes nothing on the machine.
#>
param(
    [string]$Repo = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipTests
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $Repo 'windows-smoke.log'
Start-Transcript -Path $log -Force | Out-Null

function Step($text) { Write-Host ""; Write-Host "==== $text" }

Step 'machine'
[Environment]::OSVersion.VersionString
(Get-CimInstance Win32_OperatingSystem).Caption
"architecture: $env:PROCESSOR_ARCHITECTURE"
"dotnet: $(dotnet --version)"
"user: $env:USERDOMAIN\$env:USERNAME"
"WinRM service: $((Get-Service WinRM -ErrorAction SilentlyContinue).Status)"

if (-not $SkipTests) {
    Step 'dotnet test (every test project; a failure here is a Windows problem to fix)'
    dotnet test (Join-Path $Repo 'Keeper.slnx') --nologo -v q
}

Step 'build the keeper binary'
$bin = Join-Path $Repo 'build\win-smoke'
dotnet build (Join-Path $Repo 'components\keeper\src\keeper') -o $bin --nologo -v q
Copy-Item (Join-Path $Repo 'rules') (Join-Path $bin 'rules') -Recurse -Force

$env:KEEPER_HOME = Join-Path $env:TEMP 'keeper-smoke-home'
Remove-Item $env:KEEPER_HOME -Recurse -Force -ErrorAction SilentlyContinue
function K { dotnet (Join-Path $bin 'keeper.dll') @args }

Step 'set up a private Keeper home (DPAPI protects its secrets)'
K setup --tenant smoke --apply

Step 'this machine as the only CIM target (the Windows packs normally find hosts in Active Directory)'
$me = $env:COMPUTERNAME
K integration add self --type cim --auth negotiate --endpoint $me --option "targets=$me" --option cimProtocol=auto --reason 'smoke test'
K qm run

Step 'scans: workstation pack, the CIS/Microsoft baseline, server pack (a client OS is expected to be unknown for server rules)'
foreach ($system in 'workstations', 'windows-baseline', 'windows-server') {
    Write-Host "--- $system"
    K scan $system --integration self
}

Step 'load and track'
K rules load
K qm run
K load
K qm run
K track
K qm run

Step 'what was found'
K misconfigured
K broken
K blind-spots

Step 'the interactive page'
K ui --out (Join-Path $Repo 'windows-smoke-ui.html')

Stop-Transcript
Write-Host ""
Write-Host "Done. Send windows-smoke.log (no secrets in it) to see what happened."
