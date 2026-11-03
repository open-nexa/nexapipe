#!/usr/bin/env bash
#
# run_android.sh — one-shot Android debug loop for nexapipe: build the Rust
# cdylib, drop it into ui-android, install the debug APK, launch the app and
# capture logcat.
#
# Mirrors run_android.ps1 locally on macOS/Linux. The flow is the same plus
# preflight checks:
#
#   1. Preflight  - locate cargo-ndk, adb, the SDK and the NDK; verify a device
#                   is usable. Fails here instead of three minutes into a build.
#   2. Rust build - cargo-ndk builds crates/nexapipe-client for the triple behind
#                   --abi (aarch64-linux-android by default) with the features the
#                   app needs, then the .so is copied to
#                   ui-android/app/src/main/jniLibs/<abi>/. The file must stay
#                   named libnexapipe_client.so: that is what IrohProxy.kt loads.
#   3. Verify     - the copy is confirmed by size/mtime, and the fresh .so is
#                   scanned for the JNI entry points the app calls. A .so built
#                   without the tun-proxy feature has no nativeStartTunProxy and
#                   the VPN dies with UnsatisfiedLinkError, which is otherwise
#                   only visible on device.
#   4. Install    - gradlew :app:installDebug.
#   5. Launch     - clear the log buffer, start com.nexa.pipe/.MainActivity,
#                   then run a short smoke check over the buffer (native library
#                   load, Rust panic).
#   6. Log        - stream logcat for the app's tags into a log file until
#                   Ctrl+C.
#
# Every stage can be skipped, so the script doubles as "build only"
# (--build-only) or "just stream the logs" (--skip-rust --skip-install
# --skip-launch). Note that establishing the VPN itself still needs a manual
# tap: Android shows a VpnService.prepare dialog that no adb command can
# accept.
#
# Usage:
#   ./run_android.sh                              # full loop on the single attached device
#   ./run_android.sh --restart --serial emulator-5554
#   ./run_android.sh --abi x86_64 --serial emulator-5554   # emulator with x86_64 image
#   ./run_android.sh --build-only                 # just rebuild and verify the .so
#   ./run_android.sh --skip-rust --skip-install --skip-launch  # only stream logcat
#   ./run_android.sh --check                      # preflight only, print resolved toolchain
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SERIAL=""
ABI="arm64-v8a"
FEATURES="jni,local-proxy,tun-proxy"
LOG_FILE=""
SKIP_RUST=false
SKIP_INSTALL=false
SKIP_LAUNCH=false
RESTART=false
NO_LOG=false
BUILD_ONLY=false
CHECK_ONLY=false

# ---------------------------------------------------------------------------
# Constants that must agree with the rest of the repo
# ---------------------------------------------------------------------------
# "Android ABI -> cargo triple". The app builds one APK per ABI (the splits
# block in build.gradle.kts); this script builds and installs the one named by
# --abi, which is also the jniLibs subdirectory it lands in.
abi_to_triple() {
    case "$1" in
        arm64-v8a) printf 'aarch64-linux-android' ;;
        x86_64)    printf 'x86_64-linux-android' ;;
        *)         return 1 ;;
    esac
}

SO_FILE_NAME="libnexapipe_client.so"   # IrohProxy.kt: System.loadLibrary("nexapipe_client")
# Same minSdk as ui-android's build.gradle.kts and release-apk.yml (MIN_SDK).
# cargo-ndk needs it explicitly: its own default is 21, which would produce a
# .so built against an older API level than the one CI ships.
MIN_SDK=26
APP_ID="com.nexa.pipe"
ACTIVITY="com.nexa.pipe/.MainActivity"

# Log tags: the Kotlin classes plus the Rust side, which initialises
# android_logger with the tag "NexaVpnService" in jni.rs.
LOG_TAGS=(NexaVpnService IrohProxy VpnViewModel PermissionManager)

# JNI entry points the app needs. This is the exact list release-apk.yml
# verifies with llvm-nm after building the .so; keeping it identical here
# means a local build that passes this check cannot be missing a symbol the
# release build is checked for. nativeStartTunProxy/nativeStopTunProxy only
# exist when the crate is compiled with the tun-proxy feature.
REQUIRED_SYMBOLS=(
    Java_com_nexa_pipe_IrohProxy_nativeInit
    Java_com_nexa_pipe_IrohProxy_nativeSetDnsServers
    Java_com_nexa_pipe_IrohProxy_nativeSetDnsOverride
    Java_com_nexa_pipe_IrohProxy_nativeSetRelayConfig
    Java_com_nexa_pipe_IrohProxy_nativeSetTwoFactor
    Java_com_nexa_pipe_IrohProxy_nativeStartIroh
    Java_com_nexa_pipe_IrohProxy_nativeStartProxy
    Java_com_nexa_pipe_IrohProxy_nativePreconnect
    Java_com_nexa_pipe_IrohProxy_nativeStopProxy
    Java_com_nexa_pipe_IrohProxy_nativeAddNode
    Java_com_nexa_pipe_IrohProxy_nativeStartTunProxy
    Java_com_nexa_pipe_IrohProxy_nativeStopTunProxy
    Java_com_nexa_pipe_IrohProxy_nativeDestroy
)

# ---------------------------------------------------------------------------
# Output helpers (same shape as build_dmg.sh / build_deb.sh)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_GRAY=$'\033[90m'
else
    C_RESET=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_GRAY=""
fi

step() { printf '\n%s== %s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
ok()   { printf '  %s[OK]%s   %s\n'   "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '  %s[WARN]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*"; }
bad()  { printf '  %s[FAIL]%s %s\n'  "$C_RED"    "$C_RESET" "$*"; }
info() { printf '  %s%s%s\n'         "$C_GRAY"   "$*"       "$C_RESET"; }
die()  { bad "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
run_android.sh - one-shot Android debug loop for nexapipe

Options:
  --serial <id>          adb device serial. Only needed when more than one device
                          is attached.
  --abi <arm64-v8a|x86_64>  Which ABI to build and install (default: arm64-v8a).
                          arm64-v8a for every phone; x86_64 for emulator images.
  --features <list>      Comma-separated cargo features for nexapipe-client.
                          Default: jni,local-proxy,tun-proxy
  --log-file <path>      Where the logcat capture is written; overwritten on
                          every run. Default: <repo>/nexa_vpn_log.txt
  --skip-rust            Keep the existing target/<target>/release/*.so, do not rebuild.
  --skip-install         Do not run gradlew installDebug.
  --skip-launch          Do not start the activity (smoke check skipped as well).
  --restart              Force-stop the app before launching (cold start).
  --no-log               Do not start the logcat streaming step.
  --build-only           Shorthand for --skip-install --skip-launch --no-log.
  --check                Preflight only: print the resolved toolchain and device.
  -h, --help             Show this help and exit.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)        SERIAL="$2"; shift 2 ;;
        --abi)           ABI="$2"; shift 2 ;;
        --features)      FEATURES="$2"; shift 2 ;;
        --log-file)      LOG_FILE="$2"; shift 2 ;;
        --skip-rust)     SKIP_RUST=true; shift ;;
        --skip-install)  SKIP_INSTALL=true; shift ;;
        --skip-launch)   SKIP_LAUNCH=true; shift ;;
        --restart)       RESTART=true; shift ;;
        --no-log)        NO_LOG=true; shift ;;
        --build-only)    BUILD_ONLY=true; shift ;;
        --check)         CHECK_ONLY=true; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "Unknown option: $1" ;;
    esac
done

if $BUILD_ONLY; then
    SKIP_INSTALL=true
    SKIP_LAUNCH=true
    NO_LOG=true
fi

# ---------------------------------------------------------------------------
# Paths (derived from the script location, so the script works from any cwd)
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$REPO_ROOT/ui-android"
JNI_LIB_DIR="$ANDROID_DIR/app/src/main/jniLibs/$ABI"
RUST_TARGET="$(abi_to_triple "$ABI")" || die "Invalid --abi: $ABI (use arm64-v8a|x86_64)"
SO_SOURCE="$REPO_ROOT/target/$RUST_TARGET/release/$SO_FILE_NAME"
SO_DEST="$JNI_LIB_DIR/$SO_FILE_NAME"
GRADLE_WRAPPER="$ANDROID_DIR/gradlew"
NDK_CONFIG_FILE="$REPO_ROOT/.cargo/config.toml"
LOCAL_PROPS="$ANDROID_DIR/local.properties"
if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="$REPO_ROOT/nexa_vpn_log.txt"
fi

# ---------------------------------------------------------------------------
# Native command wrapper: centralises exit-code checking so the rest of the
# script can use fail-fast `set -e` without every cargo/gradle/adb invocation
# needing its own `|| die`.
# ---------------------------------------------------------------------------
run_native() {
    local label="$1"; shift
    info "\$ $*"
    "$@"
    local code=$?
    if [[ $code -ne 0 ]]; then
        die "$label failed (exit code $code)"
    fi
}

# Capture stdout+stderr of a command into the named variable without aborting
# on failure (set +e around the call). Returns the command's exit code.
capture_native() {
    local _out_var="$1"; shift
    local _tmp
    set +e
    _tmp="$("$@" 2>&1)"
    local _code=$?
    set -e
    printf -v "$_out_var" '%s' "$_tmp"
    return $_code
}

# ---------------------------------------------------------------------------
# Toolchain discovery
# ---------------------------------------------------------------------------

# Android Studio writes local.properties; its sdk.dir is the most reliable
# pointer on a developer machine.
resolve_android_sdk() {
    local candidates=()
    [[ -n "${ANDROID_HOME:-}" ]]       && candidates+=("$ANDROID_HOME")
    [[ -n "${ANDROID_SDK_ROOT:-}" ]]   && candidates+=("$ANDROID_SDK_ROOT")

    if [[ -f "$LOCAL_PROPS" ]]; then
        local sdk_dir
        sdk_dir="$(sed -n 's/^sdk\.dir=//p' "$LOCAL_PROPS" | head -n1)"
        if [[ -n "$sdk_dir" ]]; then
            # Undo the java-properties escaping Android Studio writes:
            # backslash-escaped :, =, space and \ itself.
            sdk_dir="${sdk_dir//\\\\/\\}"
            sdk_dir="${sdk_dir//\\:/:}"
            sdk_dir="${sdk_dir//\\=/=}"
            sdk_dir="${sdk_dir//\\ / }"
            candidates+=("$sdk_dir")
        fi
    fi

    for c in ${candidates[@]+"${candidates[@]}"}; do
        if [[ -n "$c" && -d "$c" ]]; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

# The NDK used for the C parts (ring is compiled through the cc crate) should
# be the same one .cargo/config.toml pins as the linker for this target;
# mixing two NDKs is a classic confusing link failure. So the pin wins when it
# is installed.
#
# Sets NDK_HOME to the resolved path, NDK_NOTE to a human-readable description
# for the caller to print, and NDK_WARN to a warning message (empty when none).
# Returns non-zero on failure.
resolve_ndk_home() {
    local sdk_root="$1"
    NDK_HOME=""
    NDK_NOTE=""
    NDK_WARN=""

    local pinned_ndk=""
    local pinned_linker=""
    if [[ -f "$NDK_CONFIG_FILE" ]]; then
        pinned_linker="$(sed -n 's/^[[:space:]]*linker[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$NDK_CONFIG_FILE" | head -n1)"
        if [[ -n "$pinned_linker" ]]; then
            if [[ "$pinned_linker" =~ /ndk/([^/]+)/ ]]; then
                pinned_ndk="${BASH_REMATCH[1]}"
            fi
        fi
    fi

    local from_env="${ANDROID_NDK_HOME:-}"
    if [[ -n "$from_env" && -d "$from_env" ]]; then
        local env_version
        env_version="$(basename "$from_env")"
        if [[ -n "$pinned_ndk" && "$env_version" != "$pinned_ndk" ]]; then
            NDK_WARN="ANDROID_NDK_HOME=$env_version differs from the NDK $pinned_ndk pinned in .cargo/config.toml"
        fi
        NDK_NOTE="NDK $env_version (ANDROID_NDK_HOME)"
        NDK_HOME="$from_env"
        return 0
    fi

    if [[ -n "$pinned_ndk" ]]; then
        local pinned_dir="$sdk_root/ndk/$pinned_ndk"
        if [[ -d "$pinned_dir" ]]; then
            if [[ -n "$pinned_linker" && ! -e "$pinned_linker" ]]; then
                NDK_WARN="The linker pinned in .cargo/config.toml is missing: $pinned_linker"
            fi
            NDK_NOTE="NDK $pinned_ndk (pinned by .cargo/config.toml)"
            NDK_HOME="$pinned_dir"
            return 0
        fi
        NDK_WARN="NDK $pinned_ndk is pinned in .cargo/config.toml but not installed; using the newest one below"
    fi

    local ndk_root="$sdk_root/ndk"
    local newest=""
    local newest_ver=""
    if [[ -d "$ndk_root" ]]; then
        local dir ver
        while IFS= read -r dir; do
            [[ -d "$dir" ]] || continue
            ver="$(basename "$dir")"
            # Sort by version: compare as dotted numbers.
            if [[ -z "$newest_ver" ]] || \
               printf '%s\n%s\n' "$ver" "$newest_ver" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1 | grep -qx "$newest_ver"; then
                newest="$dir"
                newest_ver="$ver"
            fi
        done < <(find "$ndk_root" -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    fi
    if [[ -z "$newest" ]]; then
        die "No NDK found under $ndk_root. Install one with the SDK manager or set ANDROID_NDK_HOME."
    fi
    NDK_NOTE="NDK $newest_ver"
    NDK_WARN="Using NDK $newest_ver; consider pinning it in .cargo/config.toml so CC and the linker match"
    NDK_HOME="$newest"
}

resolve_adb() {
    local sdk_root="$1"
    if [[ -n "$sdk_root" && -x "$sdk_root/platform-tools/adb" ]]; then
        printf '%s' "$sdk_root/platform-tools/adb"
        return 0
    fi
    if command -v adb >/dev/null 2>&1; then
        command -v adb
        return 0
    fi
    return 1
}

get_connected_devices() {
    local adb="$1"
    local output
    capture_native output "$adb" devices || true
    # Print serial + state for each attached device.
    awk '/^[^[:space:]]+[[:space:]]+(device|offline|unauthorized|no permissions)[[:space:]]*$/ {print $1, $2}' <<<"$output"
}

select_device() {
    local adb="$1" requested="$2"

    local devices
    devices="$(get_connected_devices "$adb")"
    local usable
    usable="$(awk '$2=="device"{print $1}' <<<"$devices")"

    if [[ -n "$requested" ]]; then
        local match
        match="$(awk -v r="$requested" '$1==r{print $1" "$2}' <<<"$devices")"
        if [[ -z "$match" ]]; then
            local list
            list="$(awk '{print $1" ["$2"]"}' <<<"$devices" | tr '\n' ',' | sed 's/,$//')"
            [[ -z "$list" ]] && list="none"
            die "Device '$requested' is not attached (attached: $list)"
        fi
        local state
        state="$(awk -v r="$requested" '$1==r{print $2}' <<<"$devices")"
        if [[ "$state" != "device" ]]; then
            die "Device '$requested' is in state '$state'; unlock it / accept the debugging prompt and retry"
        fi
        printf '%s' "$requested"
        return 0
    fi

    local usable_count
    usable_count="$(grep -c . <<<"$usable" 2>/dev/null || true)"
    if [[ "$usable_count" -eq 1 ]]; then
        printf '%s' "$usable"
        return 0
    fi
    if [[ "$usable_count" -gt 1 ]]; then
        die "More than one usable device; pass --serial one of: $(echo "$usable" | tr '\n' ',' | sed 's/,$//')"
    fi

    local detail
    detail="$(awk '{print $1" ["$2"]"}' <<<"$devices" | tr '\n' ',' | sed 's/,$//')"
    [[ -z "$detail" ]] && detail="no device detected"
    cat >&2 <<EOF
$(bad "No usable adb device ($detail).")
         - physical device: enable USB debugging, plug it in, accept the RSA prompt
         - emulator: start an image whose ABI you pass with --abi (x86_64 or arm64-v8a)
         To only build the cdylib without a device, run: ./run_android.sh --build-only
EOF
    exit 1
}

# ---------------------------------------------------------------------------
# .so validation
# ---------------------------------------------------------------------------
# `strings` extracts printable sequences from the binary; the dynamic symbol
# table contains the JNI entry-point names verbatim, so a simple grep over the
# strings output is enough to tell whether the .so was built with the right
# features. llvm-nm from the NDK would be the alternative.
get_missing_exports() {
    local so_path="$1"
    shift
    local symbols=("$@")
    local extracted
    extracted="$(strings "$so_path" 2>/dev/null || true)"
    local missing=()
    for s in "${symbols[@]}"; do
        if ! grep -qx "$s" <<<"$extracted" 2>/dev/null; then
            missing+=("$s")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        printf '%s\n' "${missing[@]}"
        return 1
    fi
    return 0
}

get_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        die "neither shasum nor sha256sum is available"
    fi
}

get_logcat_filters() {
    local specs=()
    for t in "${LOG_TAGS[@]}"; do
        specs+=("${t}:V")
    done
    # Crashes and process kills are not tagged with our names; keep those two
    # useful and silence everything else with *:S.
    specs+=("AndroidRuntime:E")
    specs+=("ActivityManager:W")
    specs+=("*:S")
    printf '%s\n' "${specs[@]}"
}

# ===========================================================================
# 1. Preflight
# ===========================================================================
printf '%snexapipe android debug loop%s\n' "" ""

step "Preflight"

command -v cargo    >/dev/null 2>&1 || die "cargo not found on PATH"
command -v cargo-ndk >/dev/null 2>&1 || die "cargo-ndk not found; install it with: cargo install cargo-ndk"

CARGO="$(command -v cargo)"
CARGO_NDK="$(command -v cargo-ndk)"

SDK_ROOT="$(resolve_android_sdk)" || die "Android SDK not found (set ANDROID_HOME or add sdk.dir to ui-android/local.properties)"
resolve_ndk_home "$SDK_ROOT"
ADB="$(resolve_adb "$SDK_ROOT")"

ok "cargo      : $CARGO"
ok "cargo-ndk  : $CARGO_NDK"
ok "SDK        : $SDK_ROOT"
ok "NDK        : $NDK_HOME"
[[ -n "$NDK_NOTE" ]] && info "$NDK_NOTE"
[[ -n "$NDK_WARN" ]] && warn "$NDK_WARN"
# On macOS, /usr/libexec/java_home finds the JDK even when JAVA_HOME is unset.
# gradlew needs JAVA_HOME to locate the JVM; auto-detect it rather than fail.
if [[ -z "${JAVA_HOME:-}" ]]; then
    if [[ -x /usr/libexec/java_home ]]; then
        JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || true)"
    fi
fi
if [[ -n "${JAVA_HOME:-}" ]]; then
    export JAVA_HOME
    ok "JAVA_HOME  : $JAVA_HOME"
else
    warn "JAVA_HOME is not set; gradlew may refuse to start"
fi

# cargo-ndk resolves the NDK from the environment, so make the choice explicit.
export ANDROID_NDK_HOME="$NDK_HOME"
export NDK_HOME="$NDK_HOME"
export ANDROID_HOME="$SDK_ROOT"

# need_device is 1 when any of install/launch/log is not skipped.
need_device=0
$SKIP_INSTALL || need_device=1
$SKIP_LAUNCH  || need_device=1
$NO_LOG       || need_device=1

DEVICE=""
if [[ -n "$ADB" ]]; then
    ok "adb        : $ADB"
else
    if $CHECK_ONLY; then
        warn "adb not found under $SDK_ROOT/platform-tools"
    else
        die "adb not found; install the platform-tools package of the SDK"
    fi
fi

if [[ -n "$ADB" ]]; then
    if $CHECK_ONLY; then
        devices_out="$(get_connected_devices "$ADB")"
        if [[ -n "$devices_out" ]]; then
            while IFS=' ' read -r serial state; do
                ok "device     : $serial [$state]"
            done <<<"$devices_out"
        else
            warn "no adb device attached"
        fi
    elif [[ "$need_device" -ne 0 ]]; then
        DEVICE="$(select_device "$ADB" "$SERIAL")"
        ok "device     : $DEVICE"
    fi
fi

if $CHECK_ONLY; then
    step "Reusing the last build"
    if [[ -f "$SO_SOURCE" ]]; then
        local_so_size="$(stat -f%z "$SO_SOURCE" 2>/dev/null || stat -c%s "$SO_SOURCE" 2>/dev/null || echo "?")"
        local_so_mtime="$(stat -f%Sm "$SO_SOURCE" 2>/dev/null || stat -c%y "$SO_SOURCE" 2>/dev/null || echo "?")"
        ok "target .so : $(basename "$SO_SOURCE"), $local_so_size bytes, $local_so_mtime"
        missing_syms=""
        if get_missing_exports "$SO_SOURCE" "${REQUIRED_SYMBOLS[@]}" 2>/dev/null; then
            ok "all required JNI entry points present"
        else
            missing_syms="$(get_missing_exports "$SO_SOURCE" "${REQUIRED_SYMBOLS[@]}" 2>/dev/null || true)"
            warn "missing exports: $(echo "$missing_syms" | tr '\n' ' ')"
            warn "rebuild with --features jni,local-proxy,tun-proxy"
        fi
    else
        warn "no build yet at $SO_SOURCE"
    fi
    if [[ -f "$SO_DEST" ]]; then
        ok "jniLibs    : $SO_DEST"
    else
        warn "jniLibs empty ($SO_DEST); the APK would have no native library"
    fi
    echo ""
    exit 0
fi

# ===========================================================================
# 2. Build the Rust cdylib
# ===========================================================================
if ! $SKIP_RUST; then
    step "Building the client cdylib ($RUST_TARGET, features: $FEATURES)"
    # Run from the repo root so the root .cargo/config.toml (target linker)
    # applies.
    info "\$ cd $REPO_ROOT"
    # --package, not -p: after "build" every argument is forwarded to cargo,
    # but the short -p would be ambiguous with cargo-ndk's own --platform
    # option. --platform $MIN_SDK matches CI (release-apk.yml builds with
    # --platform 26).
    run_native 'cargo ndk build' \
        "$CARGO" ndk --target "$RUST_TARGET" --platform "$MIN_SDK" \
        build --release --package nexapipe-client --features "$FEATURES"
    ok "cargo ndk build finished"
else
    step "Skipping the Rust build (--skip-rust); reusing $SO_SOURCE"
    [[ -f "$SO_SOURCE" ]] || die "No existing .so at $SO_SOURCE, drop --skip-rust"
fi

[[ -f "$SO_SOURCE" ]] || die "cargo reported success but $SO_SOURCE does not exist"

src_size="$(stat -f%z "$SO_SOURCE" 2>/dev/null || stat -c%s "$SO_SOURCE" 2>/dev/null)"
src_mtime="$(stat -f%m "$SO_SOURCE" 2>/dev/null || stat -c%Y "$SO_SOURCE" 2>/dev/null)"
ok "$(basename "$SO_SOURCE"): $src_size bytes, $(date -r "$src_mtime" 2>/dev/null || date -d @"$src_mtime" 2>/dev/null)"

# ===========================================================================
# 3. Validate the .so and copy it in
# ===========================================================================
step "Validating the cdylib"
missing_syms=""
if get_missing_exports "$SO_SOURCE" "${REQUIRED_SYMBOLS[@]}" 2>/dev/null; then
    :
else
    missing_syms="$(get_missing_exports "$SO_SOURCE" "${REQUIRED_SYMBOLS[@]}" 2>/dev/null || true)"
    bad "Missing JNI entry points: $(echo "$missing_syms" | tr '\n' ' ')"
    info "The app would fail with UnsatisfiedLinkError at runtime."
    info "Rebuild with the default features (jni,local-proxy,tun-proxy); tun-proxy is what"
    info "compiles the TUN entry points."
    exit 1
fi
ok "all required JNI entry points present"
ok "sha256 $(get_sha256 "$SO_SOURCE")"

mkdir -p "$JNI_LIB_DIR"
cp "$SO_SOURCE" "$SO_DEST"
dst_size="$(stat -f%z "$SO_DEST" 2>/dev/null || stat -c%s "$SO_DEST" 2>/dev/null)"
# The copy is verified rather than assumed: a wrong or partially written .so
# would only surface as a confusing crash on the device.
if [[ "$dst_size" != "$src_size" ]]; then
    die "Copy verification failed: $SO_DEST ($dst_size bytes) != source ($src_size bytes)"
fi
ok "installed into $JNI_LIB_DIR"

# ===========================================================================
# 4. Install the debug APK
# ===========================================================================
if ! $SKIP_INSTALL; then
    step "gradlew :app:installDebug"
    [[ -x "$GRADLE_WRAPPER" ]] || die "gradlew not found at $GRADLE_WRAPPER (is ui-android checked out in this repository?)"
    # -Pabi keeps the build to the one APK this device can run; without it
    # assembleDebug produces one per ABI and installDebug has more than one
    # candidate to put on it.
    install_output=""
    if capture_native install_output \
        "$GRADLE_WRAPPER" -p "$ANDROID_DIR" :app:installDebug "-Pabi=$ABI"; then
        :
    else
        # INSTALL_FAILED_UPDATE_INCOMPATIBLE happens when the on-device package was
        # signed with a different key (a release build, or a debug build from
        # another machine). Uninstall and retry once instead of leaving the loop
        # stuck on a signing mismatch the user has to resolve by hand.
        if echo "$install_output" | grep -q 'INSTALL_FAILED_UPDATE_INCOMPATIBLE'; then
            warn "signature mismatch — uninstalling $APP_ID and retrying"
            run_native 'adb uninstall' "$ADB" -s "$DEVICE" uninstall "$APP_ID"
            run_native 'gradlew installDebug (retry)' \
                "$GRADLE_WRAPPER" -p "$ANDROID_DIR" :app:installDebug "-Pabi=$ABI"
        else
            bad "gradlew installDebug failed:"
            echo "$install_output" | tail -n 20 | sed 's/^/         /'
            # INSTALL_FAILED_USER_RESTRICTED is a MIUI/HyperOS and some OEMs'
            # system-level block on USB installs — adb cannot bypass it.
            if echo "$install_output" | grep -q 'INSTALL_FAILED_USER_RESTRICTED'; then
                echo ""
                warn "INSTALL_FAILED_USER_RESTRICTED — the device blocked the install."
                info "On Xiaomi/MIUI/HyperOS: Settings → Developer options → enable"
                info "  \"USB 安装\" (USB install) and \"USB 调试 (安全设置)\"."
                info "On other OEMs: look for a similar \"install via USB\" toggle."
            fi
            exit 1
        fi
    fi
    ok "installed $APP_ID on $DEVICE"
else
    step "Skipping the APK install (--skip-install)"
fi

# ===========================================================================
# 5. Clear the buffer, launch, smoke check
# ===========================================================================
if ! $SKIP_LAUNCH; then
    step "Launching $ACTIVITY"

    # Clear before the launch, not after: the original script cleared
    # afterwards and threw away exactly the start-up lines that matter (native
    # library load, proxy start).
    if ! $NO_LOG; then
        run_native 'logcat -c' "$ADB" -s "$DEVICE" logcat -c
        ok "log buffer cleared"
    fi

    if $RESTART; then
        run_native 'am force-stop' "$ADB" -s "$DEVICE" shell am force-stop "$APP_ID"
        sleep 0.5
        ok "app force-stopped for a cold start"
    fi

    launch_output=""
    capture_native launch_output "$ADB" -s "$DEVICE" shell am start -W -n "$ACTIVITY" || true
    while IFS= read -r line; do
        info "$line"
    done <<<"$launch_output"
    if echo "$launch_output" | grep -qE 'Error(:| type)'; then
        die "am start failed for $ACTIVITY"
    fi
    ok "activity started"

    if ! $NO_LOG; then
        step "Start-up smoke check"
        # Poll the buffer instead of sleeping blindly: the process needs a
        # moment to load the library, and a missing symbol shows up within the
        # first second.
        local_failure='RUST PANIC|UnsatisfiedLinkError|Failed to load native library|No implementation found for|FATAL EXCEPTION'
        deadline=$(( $(date +%s) + 15 ))
        loaded=""
        buffer=""
        while [[ $(date +%s) -lt $deadline ]]; do
            mapfile -t filters < <(get_logcat_filters)
            dump_output=""
            capture_native dump_output "$ADB" -s "$DEVICE" logcat -d -v brief "${filters[@]}" || true
            buffer="$dump_output"
            if echo "$buffer" | grep -qE "$local_failure"; then
                loaded="false"
                break
            fi
            if echo "$buffer" | grep -q 'Native library loaded successfully'; then
                loaded="true"
                break
            fi
            sleep 0.7
        done

        pid_output=""
        capture_native pid_output "$ADB" -s "$DEVICE" shell pidof "$APP_ID" || true
        app_pid="$(echo "$pid_output" | tr -d '[:space:]')"

        if [[ "$loaded" == "false" ]]; then
            bad "the app logged a start-up failure:"
            echo "$buffer" | grep -E "$local_failure" | tail -n 15 | while IFS= read -r line; do
                printf '%s         %s%s\n' "$C_RED" "$line" "$C_RESET"
            done
        elif [[ "$loaded" == "true" ]]; then
            ok "native library loaded (pid $app_pid)"
        else
            warn "no 'Native library loaded' line in the buffer - the app was probably already running; try --restart"
        fi
        if [[ -z "$app_pid" ]]; then
            warn "$APP_ID is not running; check the capture below for the crash reason"
        fi
    fi
else
    step "Skipping the launch (--skip-launch)"
fi

# ===========================================================================
# 6. Stream logcat
# ===========================================================================
if $NO_LOG; then
    step "Done (--no-log)"
    exit 0
fi
if [[ -z "$DEVICE" ]]; then
    die "Cannot capture logs without a device"
fi

step "Capturing logcat -> $LOG_FILE"
info "Tags: $(IFS=','; echo "${LOG_TAGS[*]}") (+ AndroidRuntime:E, ActivityManager:W)"
info "Press Ctrl+C to stop. Accept the VpnService.prepare dialog on the device to"
info "actually bring the tunnel up - adb cannot tap it for you."
info "Follow the file live in another window with:"
info "    tail -f \"$LOG_FILE\""

mapfile -t log_args < <(get_logcat_filters)
# The file is overwritten on every run, so truncate first.
: > "$LOG_FILE"
run_native 'logcat' "$ADB" -s "$DEVICE" logcat -v time "${log_args[@]}" >> "$LOG_FILE"

echo ""
ok "capture stopped; $(wc -c < "$LOG_FILE") bytes in $LOG_FILE"
