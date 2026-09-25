<#
.SYNOPSIS
    Pre-flight check for the release APK signing secrets, so that wrong values
    are not pasted into GitHub Secrets.

.DESCRIPTION
    Does three things:
     1. Checks whether the *.jks.base64 file itself is suitable for a GitHub
        Secret (single line, no BOM, no whitespace);
     2. Decodes it in memory, verifies that the file header is a keystore and
        computes its sha256;
     3. Calls keytool with the password/alias and actually reads the keystore
        once, confirming that the three password secrets are correct.

    The "sha256 / byte count" printed here can be compared directly with the
    "keystore verification" section of the CI log: when both match, the value
    stored in the GitHub Secret is exactly the same key as the local one.

.PARAMETER Base64File
    Path to the base64 file; defaults to
    ~/.nexapipe-signing/nexapipe-release.jks.base64

.PARAMETER PasswordFile
    Path to the password file; defaults to
    ~/.nexapipe-signing/keystore-password.txt

.PARAMETER Alias
    Key alias; defaults to nexapipe

.PARAMETER ShowValue
    Also prints the base64 content verbatim (it is long); only needed when
    pasting it by hand.
#>
[CmdletBinding()]
param(
    [string]$Base64File = "$env:USERPROFILE\.nexapipe-signing\nexapipe-release.jks.base64",
    [string]$PasswordFile = "$env:USERPROFILE\.nexapipe-signing\keystore-password.txt",
    [string]$Alias = "nexapipe",
    [switch]$ShowValue
)

$ErrorActionPreference = "Stop"

function Write-Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Bad  { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Step { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }

function Find-Keytool {
    $cmd = Get-Command keytool -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("$(if ($env:JAVA_HOME) { "$env:JAVA_HOME\bin\keytool.exe" })",
                     "C:\Program Files\openjdk\bin\keytool.exe",
                     "C:\Program Files\Java\jdk*\bin\keytool.exe")) {
        if (-not $p) { continue }
        $hit = Get-Item $p -ErrorAction SilentlyContinue
        if ($hit) { return $hit.FullName }
    }
    return $null
}

Write-Host "nexapipe signing secrets pre-flight check" -ForegroundColor White

# ---- 1. Input file ---------------------------------------------------------
Write-Step "Checking the base64 file"
if (-not (Test-Path -LiteralPath $Base64File)) {
    Write-Bad "Not found: $Base64File"
    exit 1
}
$fi = Get-Item -LiteralPath $Base64File
Write-Ok ("File: {0} ({1} bytes)" -f $fi.FullName, $fi.Length)

$raw = [IO.File]::ReadAllBytes($Base64File)
$problems = @()
if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) {
    $problems += "The file has a UTF-8 BOM, which may be pasted into the GitHub Secret along with the content"
}
$text = [Text.Encoding]::ASCII.GetString($raw)
$crlf = ($text -split "`n").Count - 1
if ($crlf -gt 3) {
    $problems += "The content is wrapped over $($crlf+1) lines and may be truncated when pasted (CI tolerates newlines now, but a single line is still recommended)"
}
$b64 = $text -replace '\s', ''
$b64 = $b64.Trim([char]0x22, [char]0x60, [char]0x27)
if ($b64 -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
    $problems += "Contains non-base64 characters; something else may have been mixed in when pasting"
}
# Sanity-check the leading characters of $b64
if ($b64.Length -eq 0) { Write-Bad "The file is empty"; exit 1 }

if ($problems.Count) {
    foreach ($p in $problems) { Write-Warn $p }
} else {
    Write-Ok "The content is a clean single-line base64 string"
}
Write-Ok ("Length after cleanup: {0} characters, first 8: '{1}'" -f $b64.Length, $b64.Substring(0, [Math]::Min(8, $b64.Length)))
if ($b64 -notlike "MII*") {
    Write-Warn "The base64 of a standard PKCS12 keystore usually starts with 'MII'; this one does not, please double-check the file"
}

# ---- 2. Decode + structural check ------------------------------------------
Write-Step "Decoding and verifying the keystore structure"
try {
    $bytes = [Convert]::FromBase64String($b64)
} catch {
    Write-Bad "base64 decoding failed: $($_.Exception.Message)"
    exit 1
}
$magic = ($bytes[0..3] | ForEach-Object { $_.ToString("x2") }) -join ''
$sha = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLower()

Write-Ok ("Decoded {0} bytes, file header 0x{1}" -f $bytes.Length, $magic)
Write-Ok ("sha256 {0}" -f $sha)

$magicOk = $magic.StartsWith("3082") -or $magic.StartsWith("30") -or $magic -eq "feedfeed"
if (-not $magicOk) {
    Write-Bad "File header 0x$magic is not a keystore (expected 0x3082... PKCS12 / 0x30... DER / 0xfeedfeed JKS)"
    Write-Host "       The decoded content starts with:" -ForegroundColor DarkGray
    $preview = [Text.Encoding]::ASCII.GetString($bytes[0..([Math]::Min(47, $bytes.Length - 1))])
    Write-Host ("       {0}" -f ($preview -replace '[^\x20-\x7e]', '.')) -ForegroundColor DarkGray
    exit 1
}
if ($bytes.Length -lt 1000) { Write-Bad "Only $($bytes.Length) bytes, obviously incomplete"; exit 1 }

# ---- 3. Verify the password/alias with keytool -----------------------------
Write-Step "Verifying the password and alias with keytool"
$keytool = Find-Keytool
if (-not $keytool) {
    Write-Warn "keytool not found, skipping this step (add the JDK bin directory to PATH and run again)"
} else {
    $pw = $null
    if (Test-Path -LiteralPath $PasswordFile) {
        $pw = ([IO.File]::ReadAllText($PasswordFile)).Trim()
    }
    if (-not $pw) {
        Write-Warn "Cannot read the password file $PasswordFile, skipping (use -PasswordFile to specify one)"
    } else {
        $tmp = Join-Path $env:TEMP ("nexapipe-preflight-{0}.jks" -f ([Guid]::NewGuid().ToString("N").Substring(0, 8)))
        [IO.File]::WriteAllBytes($tmp, $bytes)
        try {
            $out = & $keytool -list -keystore $tmp -storepass $pw -alias $Alias 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "keytool read succeeded: alias $Alias exists and the password is correct"
                if ($out -match 'SHA256:\s*([0-9A-F:]+)') {
                    Write-Ok ("Certificate fingerprint SHA256: {0}" -f $Matches[1])
                }
            } else {
                Write-Bad "keytool failed (wrong password or alias):"
                $out | ForEach-Object { Write-Host "       $_" -ForegroundColor DarkGray }
                exit 1
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---- 4. Compare against CI -------------------------------------------------
Write-Step "Fill in the GitHub Secret and compare"
Write-Host @"
  1) Open https://github.com/open-nexa/nexapipe/settings/secrets/actions
     Edit RELEASE_KEYSTORE_BASE64; the pasted content must be identical,
     character for character, to the output of this command.
     Opening the file with notepad and pressing Ctrl+A / Ctrl+C is recommended,
     so that terminal line wrapping or a prompt is not mixed in:

         notepad "$($fi.FullName)"

  2) The other three secrets:
         RELEASE_KEYSTORE_PASSWORD = contents of keystore-password.txt
         RELEASE_KEY_ALIAS         = $Alias
         RELEASE_KEY_PASSWORD      = contents of keystore-password.txt

  3) Go to Actions, run the workflow and check "signing_only"; the result
     appears in about 1 minute.
     The sha256 in the "keystore verification" section of the log must equal:

         $sha
"@ -ForegroundColor Gray

if ($ShowValue) {
    Write-Step "Raw base64 content"
    Write-Host $b64
}
