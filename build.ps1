<#
.SYNOPSIS
    Builds Keeper into .\build\<runtime>: every keeper binary, side by side, with the rules.

.DESCRIPTION
    The repo holds source only. Binaries go to .\build\<runtime>\ (disposable); everything that
    belongs to a tenant - settings, deny-list, its own rules and queries, the store, scan output -
    lives in the Keeper home, outside the repo:

      $env:KEEPER_HOME if set (one folder per tenant), else %LOCALAPPDATA%\Keeper
        settings\   settings.json, denylist.txt, rules\*.yaml, queries\*.sql
        data\       keeper.db, spool\, runs\, builds\, imports\, backups\

    1. Refuses to run if the Keeper home is inside the repo, or if an old build\settings or
       build\data is still here (it prints how to move them; it never moves or deletes them).
    2. Leak check: scans the repo for the identifiers in <home>\settings\denylist.txt and stops
       if any are found.
    3. Validates every rule file in rules\.
    4. With -Test, runs the unit tests.
    5. Publishes every binary (components\*\src\keeper and keeper-*) into .\build\<runtime>
       (framework-dependent: needs the .NET 10 runtime where it runs), and replaces
       .\build\<runtime>\rules with the repo's rules\.

    Writes only to .\build\<runtime>. Never touches the Keeper home: 'keeper setup' creates it.
    Runs on Windows PowerShell 5.1.

.PARAMETER Runtime
    Target platform. win-x64 (default), win-arm64, osx-arm64 (Apple Silicon), osx-x64, linux-x64.
    A macOS build made on Windows is unsigned - see README.

.EXAMPLE
    .\build.ps1 -Test

.EXAMPLE
    .\build.ps1 -Runtime osx-arm64
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [ValidateSet('win-x64', 'win-arm64', 'osx-arm64', 'osx-x64', 'linux-x64')]
    [string]$Runtime = 'win-x64',

    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$out  = Join-Path (Join-Path $repo 'build') $Runtime

# $keeperHome, never $home - that is PowerShell's read-only automatic variable.
$keeperHome = if ($env:KEEPER_HOME) { $env:KEEPER_HOME } else { Join-Path $env:LOCALAPPDATA 'Keeper' }
$keeperHome = [IO.Path]::GetFullPath($keeperHome)
$denyList   = Join-Path (Join-Path $keeperHome 'settings') 'denylist.txt'

function Test-Under([string]$Path, [string]$Folder) {
    $sep = [IO.Path]::DirectorySeparatorChar
    $p = [IO.Path]::GetFullPath($Path).TrimEnd($sep) + $sep
    $f = [IO.Path]::GetFullPath($Folder).TrimEnd($sep) + $sep
    return $p.StartsWith($f, [StringComparison]::OrdinalIgnoreCase)
}

# 1. Tenant files stay out of the repo
if (Test-Under $keeperHome $repo) {
    throw "The Keeper home ($keeperHome) is inside the repo ($repo). Point KEEPER_HOME outside it."
}

$legacy = @('settings', 'data') | ForEach-Object { Join-Path (Join-Path $repo 'build') $_ } | Where-Object { Test-Path $_ }
if ($legacy) {
    Write-Host 'Tenant files from the old layout are still inside the repo:' -ForegroundColor Red
    foreach ($l in $legacy) { Write-Host "  $l" }
    Write-Host "Look at them, then move them to the Keeper home ($keeperHome) or delete them:"
    foreach ($l in $legacy) {
        $target = Join-Path $keeperHome (Split-Path $l -Leaf)
        if (Test-Path $target) { Write-Host "  $target already exists - merge by hand." -ForegroundColor Yellow }
        else { Write-Host "  New-Item -ItemType Directory -Force '$keeperHome' | Out-Null; Move-Item '$l' '$target'" }
    }
    throw 'Stopped: move the tenant files out of the repo first.'
}

# 2. Leak check
if (Test-Path $denyList) {
    $terms = @(Get-Content $denyList -Encoding UTF8 |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') })
    $skip  = '\\(build|bin|obj|artifacts|\.git|\.vs|TestResults)\\'
    $files = @(Get-ChildItem $repo -Recurse -File -Force |
        Where-Object { $_.FullName.Substring($repo.Length) -notmatch $skip })

    if ($terms.Count -gt 0 -and $files.Count -gt 0) {
        $hits = @($files | Select-String -Pattern $terms -SimpleMatch)
        if ($hits.Count -gt 0) {
            Write-Host 'LEAK CHECK FAILED - tenant identifiers found in the repo:' -ForegroundColor Red
            foreach ($hit in $hits) {
                Write-Host ('  {0}:{1}' -f $hit.Path.Substring($repo.Length + 1), $hit.LineNumber)
            }
            throw 'Remove them before building or committing.'
        }
    }
    Write-Host "Leak check: $($terms.Count) terms, $($files.Count) files, clean."
}
else {
    Write-Warning "Leak check NOT run: no deny-list at $denyList. 'keeper setup' writes a template - fill it in."
}

# 3. Every rule file loads, and ids are unique across them
$validator = Join-Path $repo 'components\scan\src\keeper-rules\keeper-rules.csproj'
& dotnet run --project $validator -c $Configuration --nologo -- validate (Join-Path $repo 'rules')
if ($LASTEXITCODE -ne 0) { throw "Rule validation failed (exit $LASTEXITCODE): fix the file:line:col above." }

# 4. Tests
if ($Test) {
    & dotnet test (Join-Path $repo 'Keeper.slnx') -c $Configuration --nologo
    if ($LASTEXITCODE -ne 0) { throw "Tests failed (exit $LASTEXITCODE)." }
}

# 5. Publish - every components\<c>\src\keeper or keeper-<name> folder is one binary
$bins = @(Get-ChildItem (Join-Path $repo 'components') -Directory |
    ForEach-Object { Get-ChildItem (Join-Path $_.FullName 'src') -Directory -ErrorAction SilentlyContinue } |
    Where-Object { ($_.Name -eq 'keeper' -or $_.Name -like 'keeper-*') -and (Test-Path (Join-Path $_.FullName "$($_.Name).csproj")) } |
    Sort-Object Name)
foreach ($bin in $bins) {
    & dotnet publish (Join-Path $bin.FullName "$($bin.Name).csproj") -c $Configuration -r $Runtime --self-contained false -o $out --nologo -v q
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish of $($bin.Name) for $Runtime failed (exit $LASTEXITCODE). Needs the .NET 10 SDK."
    }
}

# The build output is disposable: its rules\ is replaced, so a rule removed from the repo is gone here too.
$rulesOut = Join-Path $out 'rules'
if (Test-Path $rulesOut) { Remove-Item $rulesOut -Recurse }
Copy-Item (Join-Path $repo 'rules') $rulesOut -Recurse

Write-Host "Built into ${out}: $(($bins | ForEach-Object { $_.Name }) -join ', ')"
Write-Host "Keeper home: $keeperHome"
if (-not (Test-Path (Join-Path (Join-Path $keeperHome 'settings') 'settings.json'))) {
    Write-Host "No Keeper home yet. Next: & '$out\keeper.exe' setup --tenant <name>   (dry run; add --apply)"
}
