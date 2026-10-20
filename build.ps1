<#
.SYNOPSIS
    Builds Keeper into .\build\<runtime> and prepares the Keeper home.

.DESCRIPTION
    The repo holds source only. Binaries go to .\build\<runtime>\ (disposable); everything that
    belongs to a tenant - settings, deny-list, its own queries, the store, scan output - lives in
    the Keeper home, outside the repo:

      $env:KEEPER_HOME if set (one folder per tenant), else %LOCALAPPDATA%\Keeper
        settings\   settings.json, denylist.txt, queries\*.sql
        data\       keeper.db, spool\, runs\, backups\

    1. Refuses to run if the Keeper home is inside the repo, or if an old build\settings or
       build\data is still here (it prints how to move them; it never moves or deletes them).
    2. Leak check: scans the repo for the identifiers in <home>\settings\denylist.txt and stops
       if any are found.
    3. Publishes every binary (src\keeper-*) to .\build\<runtime> (framework-dependent: needs the
       .NET 10 runtime on the machine that runs it).
    4. Creates the Keeper home's settings.json and denylist.txt only if they do not exist, so a
       rebuild never overwrites a tenant's settings.

    Writes only to .\build\<runtime> and, for missing files, the Keeper home. Never deletes
    anything. Runs on Windows PowerShell 5.1.

.PARAMETER Runtime
    Target platform. win-x64 (default), win-arm64, osx-arm64 (Apple Silicon), osx-x64, linux-x64.
    A macOS build made on Windows is unsigned - see README.

.EXAMPLE
    .\build.ps1

.EXAMPLE
    .\build.ps1 -Runtime osx-arm64
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [ValidateSet('win-x64', 'win-arm64', 'osx-arm64', 'osx-x64', 'linux-x64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$out  = Join-Path (Join-Path $repo 'build') $Runtime

# $keeperHome, never $home - that is PowerShell's read-only automatic variable.
$keeperHome = if ($env:KEEPER_HOME) { $env:KEEPER_HOME } else { Join-Path $env:LOCALAPPDATA 'Keeper' }
$keeperHome = [IO.Path]::GetFullPath($keeperHome)
$settings   = Join-Path $keeperHome 'settings'
$denyList   = Join-Path $settings 'denylist.txt'

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
    Write-Host "Look at them, then move them to the Keeper home ($keeperHome):"
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
    $skip  = '\\(build|bin|obj|\.git|\.vs|TestResults)\\'
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
    Write-Warning "Leak check NOT run: no deny-list at $denyList. A template is created below - fill it in."
}

# 3. Build - every src\keeper-<name> folder is one binary
$bins = @(Get-ChildItem (Join-Path $repo 'src') -Directory -Filter 'keeper-*')
foreach ($bin in $bins) {
    & dotnet publish (Join-Path $bin.FullName "$($bin.Name).csproj") -c $Configuration -r $Runtime --self-contained false -o $out --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish of $($bin.Name) for $Runtime failed (exit $LASTEXITCODE). Needs the .NET 10 SDK."
    }
}

# 4. The Keeper home - created once, never overwritten
New-Item -ItemType Directory -Force -Path $settings | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $keeperHome 'data') | Out-Null

# The example is generic, so it is always refreshed.
Copy-Item (Join-Path $repo 'config\settings.example.json') $settings -Force

$real = Join-Path $settings 'settings.json'
if (Test-Path $real) {
    Write-Host "Kept existing $real"
}
else {
    Copy-Item (Join-Path $settings 'settings.example.json') $real
    Write-Host "Created $real from the example - edit it."
}

if (-not (Test-Path $denyList)) {
    Set-Content -Path $denyList -Encoding UTF8 -Value @(
        '# Leak check: one tenant identifier per line. build.ps1 stops if any appear in the repo.'
        '# Add your domains, tenant ID, hostname prefixes, IP prefixes, and people''s names.'
    )
    Write-Host "Created $denyList - add your identifiers."
}

Write-Host "Built into ${out}: $(($bins | ForEach-Object { $_.Name }) -join ', ')"
Write-Host "Keeper home: $keeperHome"
