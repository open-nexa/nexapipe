#Requires -Version 5.1
<#
.SYNOPSIS
    本地构建 nexapipe 桌面端（ui-desktop，Tauri 2）的 Windows 安装包。

.DESCRIPTION
    release.yml 里的 Windows 构建是在 GitHub Runner 上跑的，本地没有那份环境：签名私钥、
    ci-override.json、把 crates/ 拷到工作区根目录的步骤全都没有。这个脚本补齐这些，
    让 `./build_windows.ps1` 一条命令就能在本机产出同样的安装包。流程：

      1. 预检     - 确认 ui-desktop 子模块已初始化、../../crates/nexapipe-client 这个 path
                    依赖存在（src-tauri/Cargo.toml 依赖它，缺了 cargo 会报莫名其妙的
                    "failed to load manifest"），检查 node/npm/cargo 和 rustup target。
      2. 前端依赖 - npm install（node_modules 已存在时跳过），并验证 npx tauri 真的能跑：
                    package-lock.json 只记录了 Windows x64 的原生二进制，装漏了会在构建
                    中途抛 "Cannot find native binding"，所以这里先探一次，失败就清掉重装。
      3. 覆盖配置 - 生成 ui-desktop/.workbuddy/build-override.json（不进版本库），做三件事：
                    · bundle.resources 按架构选 wintun/bin/<arch>/wintun.dll，
                      arm64 包里绝不能装 amd64 的 DLL；
                    · bundle.createUpdaterArtifacts 仅在同时设置了 TAURI_SIGNING_PRIVATE_KEY
                      和 TAURI_SIGNING_PRIVATE_KEY_PASSWORD 时打开，否则构建会因为
                      "no private key" 直接失败（tauri.conf.json 里它是 true）；
                    · build.beforeBuildCommand 固定用 npm，不依赖 yarn。
      4. 构建     - npx tauri build --target <triple> --bundles <bundles> --config <override>。
      5. 汇总     - 打印 exe / NSIS 安装包 / 更新包（.nsis.zip + .sig）的路径和大小。

    和 CI 的区别：默认 --bundles nsis（CI 也是 nsis，msi 会额外拉 WiX，慢），默认不开
    更新包签名。想完全复刻发布产物就设好那两个环境变量再跑。

.PARAMETER Arch
    目标架构：amd64（x86_64-pc-windows-msvc，默认）或 arm64（aarch64-pc-windows-msvc）。
    在本机 x64 上选 arm64 属于交叉编译，需要额外的 ARM64 MSVC 工具链，脚本只做提醒。

.PARAMETER Bundles
    传给 `tauri build --bundles` 的包类型，默认 nsis。可传多个：-Bundles nsis,msi。

.PARAMETER NoBundle
    只编译 exe，不打安装包（--no-bundle）。改 Rust 代码后快速验证时最快。

.PARAMETER DebugBuild
    用 debug profile 构建（--debug）。Rust 编译快得多，产物放在 target/<triple>/debug。

.PARAMETER SkipTypeCheck
    前端构建跑 `npx vite build` 而不是 `npm run build`，跳过 vue-tsc --noEmit。

.PARAMETER SkipFrontend
    完全跳过前端构建（beforeBuildCommand 置空）。dist/ 必须已经是最新内容，否则打包进去
    的是上一版前端。

.PARAMETER SkipInstall
    跳过 npm install，即使 node_modules 不存在。

.PARAMETER ForceInstall
    强制重跑 npm install（node_modules 已存在也跑）。

.PARAMETER NoSign
    即使设置了 TAURI_SIGNING_PRIVATE_KEY 也不生成更新包。

.PARAMETER Clean
    构建前删除 ui-desktop/dist 与 target/<triple>/<profile>/bundle，避免残留的旧安装包
    被当成新产物。不会动 target 里其它内容（不触发全量重编）。

.PARAMETER Open
    构建结束后用资源管理器打开产物目录。

.PARAMETER Check
    只做预检：打印解析出的路径、工具链版本和将要执行的构建命令，然后退出。

.EXAMPLE
    ./build_windows.ps1
    本机 amd64 的 NSIS 安装包，最常见的用法。

.EXAMPLE
    ./build_windows.ps1 -NoBundle -DebugBuild
    改 Rust 后只编一个 debug exe，跳过打包。

.EXAMPLE
    ./build_windows.ps1 -Arch arm64 -Open
    交叉编译 arm64 安装包（需 ARM64 MSVC 工具链），完成后打开产物目录。

.EXAMPLE
    ./build_windows.ps1 -Check
    环境体检。
#>
[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')]
    [string]   $Arch = 'amd64',
    [string[]] $Bundles = @('nsis'),
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
# 常量：必须和仓库其它地方保持一致
# ---------------------------------------------------------------------------
$TargetTriples = @{ amd64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }
$Triple  = $TargetTriples[$Arch]
$CargoProfile = if ($DebugBuild) { 'debug' } else { 'release' }

# ---------------------------------------------------------------------------
# 路径（全部由脚本位置推导，任意 cwd 下都能跑）
# ---------------------------------------------------------------------------
$RepoRoot    = $PSScriptRoot
$DesktopDir  = [IO.Path]::Combine($RepoRoot, 'ui-desktop')
$SrcTauriDir = [IO.Path]::Combine($DesktopDir, 'src-tauri')
# src-tauri/Cargo.toml 依赖 ../../crates/nexapipe-client：相对 src-tauri 上两级，正好是
# 仓库根目录。CI 靠 sparse-checkout 把 crates/ 摆到那里，本地就靠子模块布局。
$ClientCrate = [IO.Path]::Combine($RepoRoot, 'crates', 'nexapipe-client', 'Cargo.toml')
# 生成的覆盖配置放在 ui-desktop/.workbuddy 下：该目录已被 ui-desktop/.gitignore 忽略，
# 不会污染 git status。
$OverrideDir = [IO.Path]::Combine($DesktopDir, '.workbuddy')
$OverrideFile = [IO.Path]::Combine($OverrideDir, 'build-override.json')
$ProfileDir  = [IO.Path]::Combine($SrcTauriDir, 'target', $Triple, $CargoProfile)
$BundleDir   = [IO.Path]::Combine($ProfileDir, 'bundle')

# ---------------------------------------------------------------------------
# 输出辅助（与 run_android.ps1 同一套写法）
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
# 原生命令封装
#
# 不能直接调用原生命令的原因和 run_android.ps1 里一样：$ErrorActionPreference 为 Stop 时，
# PowerShell 5.1 会把原生命令写到 stderr 的内容升级成 NativeCommandError，而 cargo/npm
# 的进度与警告全走 stderr。函数内赋值只在该函数作用域生效，所以这里用 Continue，
# 脚本其余部分仍是 fail-fast。成功与否只看 exit code。
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
    # @tauri-apps/cli 的平台原生二进制缺失时，npx tauri --version 会直接失败。
    $npx = Resolve-CommandPath 'npx'
    if (-not $npx) { return $false }
    $r = Invoke-NativeCapture -Exe $npx -Arguments @('tauri', '--version')
    return ($r.ExitCode -eq 0)
}

# ---------------------------------------------------------------------------
# 预检
# ---------------------------------------------------------------------------
Write-Step "预检 (arch=$Arch, target=$Triple, profile=$CargoProfile)"

if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($DesktopDir, 'package.json')))) {
    Stop-Script "找不到 $DesktopDir\package.json —— ui-desktop 子模块多半没初始化：git submodule update --init --recursive"
}
if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($SrcTauriDir, 'Cargo.toml')))) {
    Stop-Script "找不到 $SrcTauriDir\Cargo.toml —— 同上，先初始化子模块"
}
Write-Ok "ui-desktop 已就位"

if (-not (Test-Path -LiteralPath $ClientCrate)) {
    $hint = "src-tauri/Cargo.toml 通过 ../../crates/nexapipe-client 引用它；CI 用 sparse-checkout 从 open-nexa/nexapipe 拉，本地请把 crates/ 放到 $RepoRoot\crates"
    Stop-Script "缺少 path 依赖 $ClientCrate —— $hint"
}
Write-Ok "path 依赖 crates/nexapipe-client 存在"

$wintunDll = [IO.Path]::Combine($SrcTauriDir, 'wintun', 'bin', $Arch, 'wintun.dll')
if (-not (Test-Path -LiteralPath $wintunDll)) {
    Stop-Script "缺少 $wintunDll —— 从 https://www.wintun.net/ 下载后放到该目录（build.rs 会把它拷到 exe 旁边）"
}
Write-Ok "wintun.dll ($Arch) 存在"

$node = Resolve-CommandPath 'node'
$npm  = Resolve-CommandPath 'npm'
$car  = Resolve-CommandPath 'cargo'
if (-not $node) { Stop-Script 'PATH 里没有 node' }
if (-not $npm)  { Stop-Script 'PATH 里没有 npm' }
if (-not $car)  { Stop-Script 'PATH 里没有 cargo（先装 rustup）' }

$nodeVer = (Invoke-NativeCapture -Exe $node -Arguments @('--version')).Lines[0]
if ($nodeVer -match 'v(\d+)') {
    $major = [int]$Matches[1]
    if ($major -lt 18) { Stop-Script "node $nodeVer 太旧，CI 用 22，最低要求 18" }
}
$npmVer = (Invoke-NativeCapture -Exe $npm -Arguments @('--version')).Lines[0]
$carVer = (Invoke-NativeCapture -Exe $car -Arguments @('--version')).Lines[0]
Write-Ok "node $nodeVer / npm $npmVer / $carVer"

# rustup target：缺了就装上。这不是交叉编译工具链的全部（Windows arm64 还需要 ARM64 MSVC
# build tools），但至少把 rust 侧准备好。
$rustup = Resolve-CommandPath 'rustup'
if ($rustup) {
    $installed = (Invoke-NativeCapture -Exe $rustup -Arguments @('target', 'list', '--installed')).Lines
    if ($installed -notcontains $Triple) {
        if ($Check) {
            Write-Warn "rustup target $Triple 未安装（正式构建时会自动 rustup target add）"
        } else {
            Write-Warn "rustup target $Triple 未安装，正在添加…"
            Invoke-Native -Label "rustup target add $Triple" -Exe $rustup -Arguments @('target', 'add', $Triple)
        }
    } else {
        Write-Ok "rustup target $Triple 已安装"
    }
} else {
    Write-Warn 'PATH 里没有 rustup，无法检查/安装 target；若构建报 "target not installed" 请自行处理'
}

# Windows arm64 交叉编译提醒
if ($Arch -eq 'arm64' -and $env:PROCESSOR_ARCHITECTURE -ne 'ARM64') {
    Write-Warn '在 x64 主机上构建 arm64：还需要 Visual Studio 的 ARM64 MSVC build tools，否则链接阶段会失败'
}

# 更新包签名：两个环境变量必须成对出现，只设一个 CI 也是直接报错
$signingEnabled = $false
if (-not $NoSign) {
    $keySet  = -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY)
    $passSet = -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)
    if ($keySet -and $passSet) {
        $signingEnabled = $true
    } elseif ($keySet -or $passSet) {
        Stop-Script 'TAURI_SIGNING_PRIVATE_KEY 与 TAURI_SIGNING_PRIVATE_KEY_PASSWORD 必须同时设置或同时留空'
    }
}
if ($signingEnabled) {
    Write-Ok '检测到签名私钥，将生成更新包（createUpdaterArtifacts = true）'
} else {
    Write-Warn '无签名私钥：createUpdaterArtifacts 关闭，只出安装包（要更新包请设那两个环境变量）'
}

# ---------------------------------------------------------------------------
# 组装构建命令与覆盖配置
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

$overrideJson = @{
    build  = @{ beforeBuildCommand = $beforeBuild }
    bundle = @{
        createUpdaterArtifacts = $signingEnabled
        # 数组是整体替换，所以只列当前架构的 DLL
        resources             = @("wintun/bin/$Arch/wintun.dll")
    }
} | ConvertTo-Json -Depth 4

Write-Step '构建计划'
Write-Host "  工作目录   : $DesktopDir"
Write-Host "  前端命令   : $(if ($beforeBuild) { $beforeBuild } else { '(跳过前端构建)' })"
Write-Host "  覆盖配置   : $OverrideFile"
Write-Host "  更新包签名 : $signingEnabled"
Write-Host "  命令       : npx $($tauriArgs -join ' ')"

if ($Check) {
    Write-Ok '预检结束（-Check，未构建）'
    exit 0
}

# ---------------------------------------------------------------------------
# 前端依赖
# ---------------------------------------------------------------------------
Push-Location -LiteralPath $DesktopDir
try {
    $nodeModules = [IO.Path]::Combine($DesktopDir, 'node_modules')
    $needInstall = $ForceInstall -or (-not (Test-Path -LiteralPath $nodeModules))
    if ($SkipInstall) {
        Write-Step '跳过 npm install (-SkipInstall)'
    } elseif ($needInstall) {
        Write-Step '安装前端依赖'
        Invoke-Native -Label 'npm install' -Exe $npm -Arguments @('install', '--no-audit', '--no-fund')
    } else {
        Write-Step 'node_modules 已存在，跳过 npm install（-ForceInstall 可强制重装）'
    }

    if (-not (Test-TauriNativeBinding)) {
        if ($SkipInstall) {
            Stop-Script 'npx tauri --version 失败：@tauri-apps/cli 的原生二进制缺失，去掉 -SkipInstall 重装依赖'
        }
        Write-Warn 'npx tauri 不可用（缺平台原生二进制），清空 node_modules 重装一次'
        Remove-Item -LiteralPath $nodeModules -Recurse -Force -ErrorAction Stop
        Invoke-Native -Label 'npm install (retry)' -Exe $npm -Arguments @('install', '--no-audit', '--no-fund')
        if (-not (Test-TauriNativeBinding)) { Stop-Script '重装后 npx tauri 仍不可用' }
    }
    $npxExe = Resolve-CommandPath 'npx'
    if (-not $npxExe) { Stop-Script 'PATH 里没有 npx，node 安装不完整' }
    $tauriVer = (Invoke-NativeCapture -Exe $npxExe -Arguments @('tauri', '--version')).Lines[0]
    Write-Ok "tauri CLI $tauriVer"

    # -----------------------------------------------------------------------
    # 清理（可选）
    # -----------------------------------------------------------------------
    if ($Clean) {
        Write-Step '清理旧产物'
        foreach ($p in @([IO.Path]::Combine($DesktopDir, 'dist'), $BundleDir)) {
            if (Test-Path -LiteralPath $p) {
                Write-Host "  删除 $p"
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
            }
        }
    }

    # -----------------------------------------------------------------------
    # 覆盖配置
    # -----------------------------------------------------------------------
    Write-Step '生成覆盖配置'
    if (-not (Test-Path -LiteralPath $OverrideDir)) {
        New-Item -ItemType Directory -Path $OverrideDir -Force | Out-Null
    }
    [IO.File]::WriteAllText($OverrideFile, $overrideJson + "`n", (New-Object Text.UTF8Encoding($false)))
    Write-Ok "已写入 $OverrideFile"
    Write-Host "  覆盖配置内容:" -ForegroundColor DarkGray
    ($overrideJson -split "`n") | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    # -----------------------------------------------------------------------
    # 构建
    # -----------------------------------------------------------------------
    Write-Step '构建（首次会编译整个 Rust 依赖树，可能十几分钟）'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Native -Label 'tauri build' -Exe $npxExe -Arguments $tauriArgs
    $sw.Stop()
    Write-Ok "构建完成，用时 $([int]$sw.Elapsed.TotalMinutes) 分 $($sw.Elapsed.Seconds) 秒"

    # -----------------------------------------------------------------------
    # 产物汇总
    # -----------------------------------------------------------------------
    Write-Step '产物'
    $artifacts = @()
    if (Test-Path -LiteralPath $ProfileDir) {
        # 主程序 exe（nexa.exe）与服务 exe（nexa-service.exe）
        $artifacts += Get-ChildItem -LiteralPath $ProfileDir -Filter '*.exe' -File -ErrorAction SilentlyContinue
    }
    if ((Test-Path -LiteralPath $BundleDir) -and -not $NoBundle) {
        $artifacts += Get-ChildItem -LiteralPath $BundleDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.exe', '.msi', '.zip', '.sig') }
    }
    if (-not $artifacts) {
        Write-Warn "没找到产物，检查 $ProfileDir"
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
    Write-Step "打开 $dir"
    Start-Process 'explorer.exe' -ArgumentList $dir
}

Write-Host "`n完成。" -ForegroundColor Green
exit 0
