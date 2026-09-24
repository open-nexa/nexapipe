#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the nexapipe desktop app (ui-desktop, Tauri 2) Windows installer locally.

.DESCRIPTION
    The Windows build in release.yml runs on a GitHub runner, and none of that
    environment exists locally: the signing key, ci-override.json and the step that puts
    crates/ at the workspace root are all missing. This script fills those gaps, so a
    single `./build_windows.ps1` produces the same installer here. Flow:

      1. Preflight      - confirm the ui-desktop submodule is initialised and that the
                          ../../crates/nexapipe-client path dependency exists
                          (src-tauri/Cargo.toml depends on it; without it cargo fails
                          with a baffling "failed to load manifest"), then check
                          node/npm/cargo and the rustup target.
      2. Frontend deps  - npm install (skipped when node_modules exists), then verify
                          that npx tauri really runs: package-lock.json only records the
                          Windows x64 native binaries, so a missing one turns into
                          "Cannot find native binding" halfway through the build. Probe
                          first, wipe and reinstall if it fails.
      3. Override       - write ui-desktop/.workbuddy/build-override.json (not tracked)
                          doing three things:
                          * bundle.resources: pick wintun/bin/<arch>/wintun.dll by
                            architecture - an arm64 bundle must never ship the amd64 DLL
                          * bundle.createUpdaterArtifacts: on only when both
                            TAURI_SIGNING_PRIVATE_KEY and TAURI_SIGNING_PRIVATE_KEY_PASSWORD
                            are set, otherwise the build fails outright with "no private
                            key" (tauri.conf.json ships it as true)
                          * build.beforeBuildCommand: always npm, never yarn
      4. Build          - npx tauri build --target <triple> --bundles <bundles>
                          --config <override>
      5. Summary        - print the path and size of the exe, the NSIS installer and the
                          updater artefacts (.nsis.zip + .sig).

    Differences from CI: --bundles defaults to nsis (CI uses nsis too; msi pulls in WiX
    and is slow) and updater signing is off by default. Set those two environment
    variables to reproduce the release output exactly.

.PARAMETER Arch
    Target architecture: amd64 (x86_64-pc-windows-msvc, default) or arm64
    (aarch64-pc-windows-msvc). Choosing arm64 on an x64 host is cross-compilation and
    needs the extra ARM64 MSVC toolchain; the script only warns about it.

.PARAMETER Bundles
    Bundle types passed to `tauri build --bundles`, default nsis. Several are allowed:
    -Bundles nsis,msi.

.PARAMETER Version
    Package version, e.g. 0.2.0 or 0.2.0-rc.1. CI derives it from the v* tag and syncs
    it into tauri.conf.json; locally it is injected through the override config instead,
    so the working tree stays clean. Without it the version from tauri.conf.json is used.

.PARAMETER NoBundle
    Build the exe only, skip packaging (--no-bundle). Fastest way to check a Rust change.

.PARAMETER DebugBuild
    Build with the debug profile (--debug). Much faster Rust build; output lands in
    target/<triple>/debug.

.PARAMETER SkipTypeCheck
    Build the frontend with `npx vite build` instead of `npm run build`, skipping
    vue-tsc --noEmit.

.PARAMETER SkipFrontend
    Skip the frontend build entirely (beforeBuildCommand is cleared). dist/ must already
    be current, otherwise the previous frontend gets packaged.

.PARAMETER SkipInstall
    Skip npm install even when node_modules does not exist.

.PARAMETER ForceInstall
    Force npm install even when node_modules exists.

.PARAMETER NoSign
    Do not create updater artefacts even when TAURI_SIGNING_PRIVATE_KEY is set.

.PARAMETER Clean
    Delete ui-desktop/dist and target/<triple>/<profile>/bundle before building, so a
    leftover installer is not mistaken for a new one. Nothing else in target is touched
    (no full rebuild).

.PARAMETER Open
    Open the artefact directory in Explorer when the build finishes.

.PARAMETER Check
    Preflight only: print the resolved paths, toolchain versions and the build command
    that would run, then exit.

.EXAMPLE
    ./build_windows.ps1
    NSIS installer for the host amd64 - the usual call.

.EXAMPLE
    ./build_windows.ps1 -NoBundle -DebugBuild
    Debug exe only, no packaging, after a Rust change.

.EXAMPLE
    ./build_windows.ps1 -Arch arm64 -Open
    Cross-build the arm64 installer (needs the ARM64 MSVC toolchain) and open the output
    directory afterwards.

.EXAMPLE
    ./build_windows.ps1 -Check
    Environment health check.
#>
[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')]
    [string]   $Arch = 'amd64',
    [string[]] $Bundles = @('nsis'),
    [ValidatePattern('^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$')]
    [string]   $Version,
    [switch]   $NoBundle,
    [switch]   $DebugBuild,
    [switch]   $SkipTypeCheck,
    [switch]   $SkipFrontend,
    [switch]   $SkipInstall,
    [switch]   $ForceInstall,
    [switch]   $NoSign,
    [switch]   $Clean,
    [switch]   $Open,
    [switch]   $Check
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants that must agree with the rest of the repo
# ---------------------------------------------------------------------------
$TargetTriples = @{ amd64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }
$Triple  = $TargetTriples[$Arch]
$CargoProfile = if ($DebugBuild) { 'debug' } else { 'release' }

# ---------------------------------------------------------------------------
# Paths (all derived from the script location, so any cwd works)
# ---------------------------------------------------------------------------
$RepoRoot    = $PSScriptRoot
$DesktopDir  = [IO.Path]::Combine($RepoRoot, 'ui-desktop')
$SrcTauriDir = [IO.Path]::Combine($DesktopDir, 'src-tauri')
# src-tauri/Cargo.toml depends on ../../crates/nexapipe-client: two levels above
# src-tauri is exactly the repository root. CI puts crates/ there with a
# sparse-checkout, locally it comes from the submodule layout.
$ClientCrate = [IO.Path]::Combine($RepoRoot, 'crates', 'nexapipe-client', 'Cargo.toml')
# The generated override goes under ui-desktop/.workbuddy: that directory is already
# ignored by ui-desktop/.gitignore, so it never pollutes git status.
$OverrideDir = [IO.Path]::Combine($DesktopDir, '.workbuddy')
$OverrideFile = [IO.Path]::Combine($OverrideDir, 'build-override.json')
$ProfileDir  = [IO.Path]::Combine($SrcTauriDir, 'target', $Triple, $CargoProfile)
$BundleDir   = [IO.Path]::Combine($ProfileDir, 'bundle')

# ---------------------------------------------------------------------------
# Output helpers (same shape as run_android.ps1)
# ---------------------------------------------------------------------------
function Write-Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Bad  { param([string]$m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Stop-Script {
    param([string]$m)
    Write-Bad $m
    exit 1
}

# ---------------------------------------------------------------------------
# Native command wrappers
#
# Native commands cannot be called directly here for the same reason as in
# run_android.ps1: with $ErrorActionPreference set to Stop, PowerShell 5.1 promotes
# whatever a native command writes to stderr into a terminating NativeCommandError, and
# cargo/npm send all their progress and warnings to stderr. Assigning the preference
# inside a function is function-scoped, so these wrappers see "Continue" while the rest
# of the script keeps fail-fast cmdlet behaviour. Success is judged from the exit code.
# ---------------------------------------------------------------------------
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]   $Label,
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $Arguments
    )
    Write-Host "  `> $Exe $($Arguments -join ' ')" -ForegroundColor DarkGray
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { Stop-Script "$Label failed (exit code $code)" }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $Arguments
    )
    $ErrorActionPreference = 'Continue'
    $output = & $Exe @Arguments 2>&1
    $lines = @()
    if ($output) { $lines = @($output | ForEach-Object { "$_" }) }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Lines = $lines }
}

function Resolve-CommandPath {
    param([Parameter(Mandatory)][string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    return $cmd.Source
}

function Test-TauriNativeBinding {
    # When the platform native binary of @tauri-apps/cli is missing, `npx tauri --version`
    # fails outright.
    $npx = Resolve-CommandPath 'npx'
    if (-not $npx) { return $false }
    $r = Invoke-NativeCapture -Exe $npx -Arguments @('tauri', '--version')
    return ($r.ExitCode -eq 0)
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
Write-Step "Preflight (arch=$Arch, target=$Triple, profile=$CargoProfile)"

if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($DesktopDir, 'package.json')))) {
    Stop-Script "$DesktopDir\package.json not found - the ui-desktop submodule is probably not initialised: git submodule update --init --recursive"
}
if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($SrcTauriDir, 'Cargo.toml')))) {
    Stop-Script "$SrcTauriDir\Cargo.toml not found - same cause, initialise the submodules first"
}
Write-Ok "ui-desktop is in place"

if (-not (Test-Path -LiteralPath $ClientCrate)) {
    $hint = "src-tauri/Cargo.toml refers to it through ../../crates/nexapipe-client; CI sparse-checks it out from open-nexa/nexapipe, locally put crates/ under $RepoRoot\crates"
    Stop-Script "path dependency $ClientCrate is missing - $hint"
}
Write-Ok "path dependency crates/nexapipe-client present"

$wintunDll = [IO.Path]::Combine($SrcTauriDir, 'wintun', 'bin', $Arch, 'wintun.dll')
if (-not (Test-Path -LiteralPath $wintunDll)) {
    Stop-Script "$wintunDll not found - download it from https://www.wintun.net/ and drop it there (build.rs copies it next to the exe)"
}
Write-Ok "wintun.dll ($Arch) present"

$node = Resolve-CommandPath 'node'
$npm  = Resolve-CommandPath 'npm'
$car  = Resolve-CommandPath 'cargo'
if (-not $node) { Stop-Script 'node not found on PATH' }
if (-not $npm)  { Stop-Script 'npm not found on PATH' }
if (-not $car)  { Stop-Script 'cargo not found on PATH (install rustup first)' }

$nodeVer = (Invoke-NativeCapture -Exe $node -Arguments @('--version')).Lines[0]
if ($nodeVer -match 'v(\d+)') {
    $major = [int]$Matches[1]
    if ($major -lt 18) { Stop-Script "node $nodeVer is too old; CI uses 24 and 18 is the minimum" }
}
$npmVer = (Invoke-NativeCapture -Exe $npm -Arguments @('--version')).Lines[0]
$carVer = (Invoke-NativeCapture -Exe $car -Arguments @('--version')).Lines[0]
Write-Ok "node $nodeVer / npm $npmVer / $carVer"

# rustup target: install it when missing. This is not the whole cross toolchain (Windows
# arm64 also needs the ARM64 MSVC build tools), but it at least prepares the Rust side.
$rustup = Resolve-CommandPath 'rustup'
if ($rustup) {
    $installed = (Invoke-NativeCapture -Exe $rustup -Arguments @('target', 'list', '--installed')).Lines
    if ($installed -notcontains $Triple) {
        if ($Check) {
            Write-Warn "rustup target $Triple is not installed (a real build runs: rustup target add $Triple)"
        } else {
            Write-Warn "rustup target $Triple is not installed, adding it..."
            Invoke-Native -Label "rustup target add $Triple" -Exe $rustup -Arguments @('target', 'add', $Triple)
        }
    } else {
        Write-Ok "rustup target $Triple installed"
    }
} else {
    Write-Warn 'rustup not found on PATH; cannot check or install the target. If the build reports "target not installed", handle it yourself'
}

# Windows arm64 cross-compilation reminder
if ($Arch -eq 'arm64' -and $env:PROCESSOR_ARCHITECTURE -ne 'ARM64') {
    Write-Warn 'building arm64 on an x64 host also needs the ARM64 MSVC build tools of Visual Studio, otherwise linking fails'
}

# Updater signing: the two variables must be set together; setting only one is an error
# in CI as well.
$signingEnabled = $false
if (-not $NoSign) {
    $keySet  = -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY)
    $passSet = -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)
    if ($keySet -and $passSet) {
        $signingEnabled = $true
    } elseif ($keySet -or $passSet) {
        Stop-Script 'TAURI_SIGNING_PRIVATE_KEY and TAURI_SIGNING_PRIVATE_KEY_PASSWORD must be set together or left empty together'
    }
}
if ($signingEnabled) {
    Write-Ok 'signing key found, updater artefacts will be created (createUpdaterArtifacts = true)'
} else {
    Write-Warn 'no signing key: createUpdaterArtifacts off, installer only (set those two variables for updater artefacts)'
}

# ---------------------------------------------------------------------------
# Assemble the build command and the override config
# ---------------------------------------------------------------------------
$beforeBuild = 'npm run build'
if ($SkipTypeCheck) { $beforeBuild = 'npx vite build' }
if ($SkipFrontend)  { $beforeBuild = '' }

$tauriArgs = @('tauri', 'build', '--target', $Triple)
if ($NoBundle) {
    $tauriArgs += '--no-bundle'
} else {
    $tauriArgs += @('--bundles') + $Bundles
}
if ($DebugBuild) { $tauriArgs += '--debug' }
$tauriArgs += @('--config', $OverrideFile)

$override = @{
    build  = @{ beforeBuildCommand = $beforeBuild }
    bundle = @{
        createUpdaterArtifacts = $signingEnabled
        # Arrays are replaced wholesale, so only the DLL of the current architecture is
        # listed.
        resources             = @("wintun/bin/$Arch/wintun.dll")
    }
}
# Mirrors what CI syncs into tauri.conf.json before building (release.yml,
# "Sync version into tauri.conf.json"): --config deep-merges, so the packaged
# version can be overridden without touching the tracked file. The key is only
# added when set - ConvertTo-Json would otherwise emit "version": null and the
# merge would blank out the version from tauri.conf.json.
if ($Version) { $override['version'] = $Version }
$overrideJson = $override | ConvertTo-Json -Depth 4

Write-Step 'Build plan'
Write-Host "  working dir : $DesktopDir"
Write-Host "  version     : $(if ($Version) { $Version } else { '(from tauri.conf.json)' })"
Write-Host "  frontend    : $(if ($beforeBuild) { $beforeBuild } else { '(frontend build skipped)' })"
Write-Host "  override    : $OverrideFile"
Write-Host "  updater sign: $signingEnabled"
Write-Host "  command     : npx $($tauriArgs -join ' ')"

if ($Check) {
    Write-Ok 'preflight finished (-Check, nothing was built)'
    exit 0
}

# ---------------------------------------------------------------------------
# Frontend dependencies
# ---------------------------------------------------------------------------
Push-Location -LiteralPath $DesktopDir
try {
    $nodeModules = [IO.Path]::Combine($DesktopDir, 'node_modules')
    $needInstall = $ForceInstall -or (-not (Test-Path -LiteralPath $nodeModules))
    if ($SkipInstall) {
        Write-Step 'Skipping npm install (-SkipInstall)'
    } elseif ($needInstall) {
        Write-Step 'Installing frontend dependencies'
        Invoke-Native -Label 'npm install' -Exe $npm -Arguments @('install', '--no-audit', '--no-fund')
    } else {
        Write-Step 'node_modules exists, skipping npm install (-ForceInstall to rerun)'
    }

    if (-not (Test-TauriNativeBinding)) {
        if ($SkipInstall) {
            Stop-Script 'npx tauri --version failed: the @tauri-apps/cli native binary is missing, drop -SkipInstall to reinstall'
        }
        Write-Warn 'npx tauri is unusable (missing platform native binary); wiping node_modules and reinstalling once'
        Remove-Item -LiteralPath $nodeModules -Recurse -Force -ErrorAction Stop
        Invoke-Native -Label 'npm install (retry)' -Exe $npm -Arguments @('install', '--no-audit', '--no-fund')
        if (-not (Test-TauriNativeBinding)) { Stop-Script 'npx tauri is still unusable after reinstalling' }
    }
    $npxExe = Resolve-CommandPath 'npx'
    if (-not $npxExe) { Stop-Script 'npx not found on PATH, the node installation is incomplete' }
    $tauriVer = (Invoke-NativeCapture -Exe $npxExe -Arguments @('tauri', '--version')).Lines[0]
    Write-Ok "tauri CLI $tauriVer"

    # -----------------------------------------------------------------------
    # Clean (optional)
    # -----------------------------------------------------------------------
    if ($Clean) {
        Write-Step 'Cleaning old artefacts'
        foreach ($p in @([IO.Path]::Combine($DesktopDir, 'dist'), $BundleDir)) {
            if (Test-Path -LiteralPath $p) {
                Write-Host "  removing $p"
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
            }
        }
    }

    # -----------------------------------------------------------------------
    # Override config
    # -----------------------------------------------------------------------
    Write-Step 'Writing the override config'
    if (-not (Test-Path -LiteralPath $OverrideDir)) {
        New-Item -ItemType Directory -Path $OverrideDir -Force | Out-Null
    }
    [IO.File]::WriteAllText($OverrideFile, $overrideJson + "`n", (New-Object Text.UTF8Encoding($false)))
    Write-Ok "wrote $OverrideFile"
    Write-Host "  contents:" -ForegroundColor DarkGray
    ($overrideJson -split "`n") | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    # -----------------------------------------------------------------------
    # Build
    # -----------------------------------------------------------------------
    Write-Step 'Building (the first build compiles the whole Rust dependency tree and can take ten minutes or more)'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Native -Label 'tauri build' -Exe $npxExe -Arguments $tauriArgs
    $sw.Stop()
    Write-Ok "build finished in $([int]$sw.Elapsed.TotalMinutes)m $($sw.Elapsed.Seconds)s"

    # -----------------------------------------------------------------------
    # Artefact summary
    # -----------------------------------------------------------------------
    Write-Step 'Artefacts'
    $artifacts = @()
    if (Test-Path -LiteralPath $ProfileDir) {
        # The main exe (nexa.exe) and the service exe (nexa-service.exe)
        $artifacts += Get-ChildItem -LiteralPath $ProfileDir -Filter '*.exe' -File -ErrorAction SilentlyContinue
    }
    if ((Test-Path -LiteralPath $BundleDir) -and -not $NoBundle) {
        $artifacts += Get-ChildItem -LiteralPath $BundleDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.exe', '.msi', '.zip', '.sig') }
    }
    if (-not $artifacts) {
        Write-Warn "no artefacts found, check $ProfileDir"
    } else {
        foreach ($f in ($artifacts | Sort-Object FullName)) {
            $size = '{0:N1} MB' -f ($f.Length / 1MB)
            Write-Host ("  {0,-10} {1}" -f $size, $f.FullName)
        }
    }
} finally {
    Pop-Location
}

if ($Open) {
    $dir = if (Test-Path -LiteralPath $BundleDir) { $BundleDir } else { $ProfileDir }
    Write-Step "Opening $dir"
    Start-Process 'explorer.exe' -ArgumentList $dir
}

Write-Host "`nDone." -ForegroundColor Green
exit 0
