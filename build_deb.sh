#!/usr/bin/env bash
#
# build_deb.sh - build the nexapipe desktop app (ui-desktop, Tauri 2) Debian package.
#
# This is the Linux counterpart of build_windows.ps1. The Linux jobs in
# ui-desktop/.github/workflows/release.yml run on GitHub runners that already have the
# webkit/appindicator packages, the updater signing key and a crates/ checkout; locally
# none of that exists. This script fills the gaps so one command produces the same .deb:
#
#   1. Preflight  - ui-desktop submodule present; ../../crates/nexapipe-client path
#                   dependency present (src-tauri/Cargo.toml points at it and cargo fails
#                   with a misleading "failed to load manifest" without it); node/npm/cargo
#                   on PATH; rustup target installed; Tauri's Linux system packages present.
#   2. Frontend   - npm install (skipped when node_modules exists), then a probe of
#                   `npx tauri --version`. package-lock.json was generated on Windows x64
#                   and only records that platform's native binaries, so a missing
#                   @tauri-apps/cli native binding otherwise surfaces as "Cannot find
#                   native binding" halfway through the build. On failure node_modules and
#                   the lockfile are wiped and reinstalled once.
#   3. Override   - writes ui-desktop/.workbuddy/build-override.json (git-ignored) with:
#                   * bundle.resources = []          - wintun.dll is Windows only; a
#                     missing resource path aborts the bundle step
#                   * bundle.createUpdaterArtifacts  - enabled only when
#                     TAURI_SIGNING_PRIVATE_KEY and TAURI_SIGNING_PRIVATE_KEY_PASSWORD are
#                     both set (tauri.conf.json ships it as true and the build then fails
#                     with "no private key")
#                   * build.beforeBuildCommand       - always npm, never yarn
#   4. Build      - npx tauri build --target <triple> --bundles <bundles> --config <override>
#   5. Summary    - path and size of every .deb / .rpm / .AppImage / .sig produced, plus
#                   dpkg-deb metadata for each .deb.
#
# Difference from CI: the default bundle is deb only (CI builds deb rpm appimage) and
# updater signing is off unless both signing variables are exported. Export those and pass
# --bundles deb,rpm,appimage to reproduce the release artefacts exactly.
#
# Usage:
#   ./build_deb.sh                        # amd64 .deb, the common case
#   ./build_deb.sh --no-bundle --debug    # just the release/debug binary, no packaging
#   ./build_deb.sh --arch arm64           # cross-build for arm64 (needs a cross toolchain)
#   ./build_deb.sh --install-deps         # let the script apt-get install what is missing
#   ./build_deb.sh --check                # environment check only, prints the build plan
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ARCH=""
BUNDLES="deb"
NO_BUNDLE=false
DEBUG_BUILD=false
SKIP_TYPE_CHECK=false
SKIP_FRONTEND=false
SKIP_INSTALL=false
FORCE_INSTALL=false
NO_SIGN=false
CLEAN=false
INSTALL_DEPS=false
SKIP_DEPS=false
CHECK_ONLY=false

# ---------------------------------------------------------------------------
# Output helpers (same shape as build_windows.ps1 / run_android.ps1)
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

usage() {
    cat <<'EOF'
build_deb.sh - build the nexapipe desktop Debian package (Tauri 2)

Options:
  --arch <amd64|arm64>   Target architecture (default: the host architecture).
  --bundles <list>       Comma-separated bundle types, default "deb"
                         (also available: rpm, appimage).
  --no-bundle            Build the binary only, skip packaging.
  --debug                Use the debug cargo profile (much faster Rust build).
  --skip-type-check      Frontend build runs "npx vite build", skipping vue-tsc.
  --skip-frontend        Do not rebuild the frontend at all; dist/ must be current.
  --skip-install         Skip npm install even when node_modules is missing.
  --force-install        Run npm install even when node_modules exists.
  --no-sign              Never create updater artefacts, even with a signing key set.
  --clean                Delete ui-desktop/dist and the bundle output before building.
  --install-deps         apt-get install the missing system packages (needs sudo).
  --skip-deps            Do not check the system packages at all.
  --check                Preflight only: print the resolved paths, toolchain and the
                         build command, then exit.
  -h, --help             Show this help.

Environment:
  TAURI_SIGNING_PRIVATE_KEY            Updater signing key (minisign).
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD   Password for that key.
  Both must be set together or both empty; only then are updater artefacts produced.

Examples:
  ./build_deb.sh
  ./build_deb.sh --no-bundle --debug
  ./build_deb.sh --arch arm64 --bundles deb
  ./build_deb.sh --install-deps --clean
  ./build_deb.sh --check
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)           ARCH="${2:-}"; shift 2 ;;
        --bundles)        BUNDLES="${2:-}"; shift 2 ;;
        --no-bundle)      NO_BUNDLE=true; shift ;;
        --debug)          DEBUG_BUILD=true; shift ;;
        --skip-type-check) SKIP_TYPE_CHECK=true; shift ;;
        --skip-frontend)  SKIP_FRONTEND=true; shift ;;
        --skip-install)   SKIP_INSTALL=true; shift ;;
        --force-install)  FORCE_INSTALL=true; shift ;;
        --no-sign)        NO_SIGN=true; shift ;;
        --clean)          CLEAN=true; shift ;;
        --install-deps)   INSTALL_DEPS=true; shift ;;
        --skip-deps)      SKIP_DEPS=true; shift ;;
        --check)          CHECK_ONLY=true; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "Unknown option: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Architecture / target triple
# ---------------------------------------------------------------------------
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) HOST_ARCH="amd64" ;;
    aarch64|arm64) HOST_ARCH="arm64" ;;
esac
if [[ -z "$ARCH" ]]; then ARCH="$HOST_ARCH"; fi
case "$ARCH" in
    amd64) TRIPLE="x86_64-unknown-linux-gnu" ;;
    arm64) TRIPLE="aarch64-unknown-linux-gnu" ;;
    *)     die "Unsupported --arch '$ARCH' (expected amd64 or arm64)" ;;
esac
CARGO_PROFILE="release"
if $DEBUG_BUILD; then CARGO_PROFILE="debug"; fi

# ---------------------------------------------------------------------------
# Paths (all derived from the script location, so any cwd works)
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$REPO_ROOT/ui-desktop"
SRC_TAURI_DIR="$DESKTOP_DIR/src-tauri"
# src-tauri/Cargo.toml depends on ../../crates/nexapipe-client: two levels above
# src-tauri is exactly the repository root. CI copies crates/ there, locally it comes
# from the submodule layout.
CLIENT_CRATE="$REPO_ROOT/crates/nexapipe-client/Cargo.toml"
# The generated override lands in ui-desktop/.workbuddy, which ui-desktop/.gitignore
# already ignores, so it never shows up in git status.
OVERRIDE_DIR="$DESKTOP_DIR/.workbuddy"
OVERRIDE_FILE="$OVERRIDE_DIR/build-override.json"
PROFILE_DIR="$SRC_TAURI_DIR/target/$TRIPLE/$CARGO_PROFILE"
BUNDLE_DIR="$PROFILE_DIR/bundle"

printf '%snexapipe desktop .deb build (arch=%s, target=%s, profile=%s)%s\n' \
    "$C_GREEN" "$ARCH" "$TRIPLE" "$CARGO_PROFILE" "$C_RESET"

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------
step "Preflight"

[[ -f "$DESKTOP_DIR/package.json" ]] \
    || die "$DESKTOP_DIR/package.json not found - the ui-desktop submodule is probably not initialised: git submodule update --init --recursive"
[[ -f "$SRC_TAURI_DIR/Cargo.toml" ]] \
    || die "$SRC_TAURI_DIR/Cargo.toml not found - same cause, initialise the submodules first"
ok "ui-desktop is in place"

[[ -f "$CLIENT_CRATE" ]] \
    || die "path dependency $CLIENT_CRATE is missing - src-tauri/Cargo.toml refers to ../../crates/nexapipe-client; put crates/ under $REPO_ROOT"
ok "path dependency crates/nexapipe-client present"

command -v node  >/dev/null 2>&1 || die "node not found on PATH"
command -v npm   >/dev/null 2>&1 || die "npm not found on PATH"
command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH (install rustup first)"

NODE_VER="$(node --version)"
NPM_VER="$(npm --version)"
CARGO_VER="$(cargo --version)"
if [[ "$NODE_VER" =~ ^v([0-9]+) ]]; then
    (( ${BASH_REMATCH[1]} >= 18 )) || die "node $NODE_VER is too old; CI uses 24 and 18 is the minimum"
fi
ok "node $NODE_VER / npm $NPM_VER / $CARGO_VER"

# Tauri v2 needs webkit2gtk-4.1, which is why CI pins ubuntu-22.04.
declare -A APT_FOR_MODULE=(
    [webkit2gtk-4.1]="libwebkit2gtk-4.1-dev"
    [ayatana-appindicator3-0.1]="libayatana-appindicator3-dev"
    [librsvg-2.0]="librsvg2-dev"
    [xdo]="libxdo-dev"
    [openssl]="libssl-dev"
)
declare -A APT_FOR_TOOL=(
    [patchelf]="patchelf"
    [file]="file"
    [dpkg-deb]="dpkg"
    [rpm]="rpm"
    [xdg-open]="xdg-utils"
)

check_system_deps() {
    local -a missing=()
    local mod tool
    for mod in "${!APT_FOR_MODULE[@]}"; do
        pkg-config --exists "$mod" 2>/dev/null || missing+=("${APT_FOR_MODULE[$mod]}")
    done
    for tool in patchelf file dpkg-deb; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("${APT_FOR_TOOL[$tool]}")
    done
    # Only the bundles that were asked for need their extra tooling: rpm for .rpm and
    # /usr/bin/xdg-open for the AppImage (tauri-plugin-opener hard-fails without it).
    if ! $NO_BUNDLE; then
        case ",$BUNDLES," in
            *,rpm,*)      command -v rpm >/dev/null 2>&1 || missing+=("rpm") ;;
            *,appimage,*) command -v xdg-open >/dev/null 2>&1 || missing+=("xdg-utils") ;;
        esac
    fi
    (( ${#missing[@]} > 0 )) && printf '%s\n' "${missing[@]}"
    return 0
}

if $SKIP_DEPS; then
    warn "system package check skipped (--skip-deps)"
else
    MISSING=()
    mapfile -t MISSING < <(check_system_deps)
    if (( ${#MISSING[@]} > 0 )); then
        if $INSTALL_DEPS; then
            step "Installing missing system packages"
            if ! command -v apt-get >/dev/null 2>&1; then
                die "apt-get not found; install these by hand: ${MISSING[*]}"
            fi
            info "sudo apt-get install -y --no-install-recommends ${MISSING[*]}"
            sudo apt-get update
            sudo apt-get install -y --no-install-recommends "${MISSING[@]}"
        else
            bad "missing system packages: ${MISSING[*]}"
            info "install them with:"
            info "  sudo apt-get update && sudo apt-get install -y --no-install-recommends ${MISSING[*]}"
            info "or rerun this script with --install-deps (uses sudo), or --skip-deps to ignore"
            exit 1
        fi
    else
        ok "Tauri Linux system packages present"
    fi
fi

# rustup target: add it when missing. This is not the whole cross toolchain (aarch64
# also needs a cross linker such as aarch64-linux-gnu-gcc), but it covers the Rust side.
if command -v rustup >/dev/null 2>&1; then
    if rustup target list --installed | grep -qx "$TRIPLE"; then
        ok "rustup target $TRIPLE installed"
    elif $CHECK_ONLY; then
        warn "rustup target $TRIPLE is not installed (a real build runs: rustup target add $TRIPLE)"
    else
        warn "rustup target $TRIPLE is not installed, adding it..."
        rustup target add "$TRIPLE"
    fi
else
    warn "rustup not found on PATH; cannot check or install the target"
fi

if [[ "$ARCH" != "$HOST_ARCH" ]]; then
    warn "cross-building $ARCH on a $HOST_ARCH host: you also need a cross toolchain"
    warn "(for arm64: gcc-aarch64-linux-gnu plus a linker setting in .cargo/config.toml)"
fi

# ---------------------------------------------------------------------------
# Updater signing: the two variables must be set together, anything else is an error
# ---------------------------------------------------------------------------
SIGNING_ENABLED=false
if ! $NO_SIGN; then
    KEY_SET=false;  [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]] && KEY_SET=true
    PASS_SET=false; [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" ]] && PASS_SET=true
    if $KEY_SET && $PASS_SET; then
        SIGNING_ENABLED=true
    elif $KEY_SET || $PASS_SET; then
        die "TAURI_SIGNING_PRIVATE_KEY and TAURI_SIGNING_PRIVATE_KEY_PASSWORD must be set together or left empty together"
    fi
fi
if $SIGNING_ENABLED; then
    ok "signing key found, updater artefacts will be created (createUpdaterArtifacts = true)"
else
    warn "no signing key: createUpdaterArtifacts off, packages only (export both TAURI_SIGNING_* variables for updater artefacts)"
fi

# ---------------------------------------------------------------------------
# Build plan
# ---------------------------------------------------------------------------
BEFORE_BUILD="npm run build"
if $SKIP_TYPE_CHECK; then BEFORE_BUILD="npx vite build"; fi
if $SKIP_FRONTEND;   then BEFORE_BUILD=""; fi

TAURI_ARGS=(tauri build --target "$TRIPLE")
if $NO_BUNDLE; then
    TAURI_ARGS+=(--no-bundle)
else
    TAURI_ARGS+=(--bundles "$BUNDLES")
fi
if $DEBUG_BUILD; then TAURI_ARGS+=(--debug); fi
TAURI_ARGS+=(--config "$OVERRIDE_FILE")

step "Build plan"
printf '  %-18s %s\n' "working dir:"  "$DESKTOP_DIR"
printf '  %-18s %s\n' "frontend cmd:" "${BEFORE_BUILD:-(frontend build skipped)}"
printf '  %-18s %s\n' "override:"     "$OVERRIDE_FILE"
printf '  %-18s %s\n' "bundles:"      "$($NO_BUNDLE && echo '(none, --no-bundle)' || echo "$BUNDLES")"
printf '  %-18s %s\n' "updater sign:" "$SIGNING_ENABLED"
printf '  %-18s %s\n' "command:"      "npx ${TAURI_ARGS[*]}"

if $CHECK_ONLY; then
    ok "preflight finished (--check, nothing was built)"
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. Frontend dependencies
# ---------------------------------------------------------------------------
cd "$DESKTOP_DIR"

if $SKIP_INSTALL; then
    step "Skipping npm install (--skip-install)"
elif $FORCE_INSTALL || [[ ! -d node_modules ]]; then
    step "Installing frontend dependencies"
    npm install --no-audit --no-fund
else
    step "node_modules exists, skipping npm install (--force-install to rerun)"
fi

if ! npx tauri --version >/dev/null 2>&1; then
    if $SKIP_INSTALL; then
        die "npx tauri --version failed: the @tauri-apps/cli native binary is missing, drop --skip-install"
    fi
    warn "npx tauri is unusable (missing platform native binary); wiping node_modules and reinstalling once"
    rm -rf node_modules package-lock.json
    npm install --no-audit --no-fund
    npx tauri --version >/dev/null 2>&1 || die "npx tauri is still unusable after reinstalling"
fi
ok "tauri CLI $(npx tauri --version 2>/dev/null | head -n1)"

# ---------------------------------------------------------------------------
# 3. Clean (optional)
# ---------------------------------------------------------------------------
if $CLEAN; then
    step "Cleaning old artefacts"
    for p in "$DESKTOP_DIR/dist" "$BUNDLE_DIR"; do
        if [[ -e "$p" ]]; then info "removing $p"; rm -rf "$p"; fi
    done
fi

# ---------------------------------------------------------------------------
# 4. Override config
# ---------------------------------------------------------------------------
step "Writing the override config"
mkdir -p "$OVERRIDE_DIR"
# Arrays are replaced wholesale by --config, so the Windows-only wintun.dll resource is
# dropped here; keeping it would abort the bundle step on a missing path.
cat > "$OVERRIDE_FILE" <<EOF
{
  "build": {
    "beforeBuildCommand": "$BEFORE_BUILD"
  },
  "bundle": {
    "createUpdaterArtifacts": $SIGNING_ENABLED,
    "resources": []
  }
}
EOF
ok "wrote $OVERRIDE_FILE"
while IFS= read -r line; do info "  $line"; done < "$OVERRIDE_FILE"

# ---------------------------------------------------------------------------
# 5. Build
# ---------------------------------------------------------------------------
step "Building (the first build compiles the whole Rust dependency tree and takes a while)"
START=$(date +%s)
npx "${TAURI_ARGS[@]}"
END=$(date +%s)
ok "build finished in $(( (END - START) / 60 ))m $(( (END - START) % 60 ))s"

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
step "Artefacts"
FOUND=0
if [[ -d "$PROFILE_DIR" ]]; then
    while IFS= read -r f; do
        FOUND=1
        printf '  %8.1f MB  %s\n' "$(awk -v s="$(stat -c %s "$f")" 'BEGIN{print s/1048576}')" "$f"
    done < <(find "$PROFILE_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.AppImage' -o -name '*.sig' \) 2>/dev/null | sort)
fi
if [[ -d "$BUNDLE_DIR" ]] && ! $NO_BUNDLE; then
    while IFS= read -r f; do
        FOUND=1
        printf '  %8.1f MB  %s\n' "$(awk -v s="$(stat -c %s "$f")" 'BEGIN{print s/1048576}')" "$f"
    done < <(find "$BUNDLE_DIR" -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.AppImage' -o -name '*.sig' -o -name '*.tar.gz' \) 2>/dev/null | sort)
fi
if (( FOUND == 0 )); then
    warn "no artefacts found, check $PROFILE_DIR"
fi

# Show the Debian metadata of every .deb, which is the quickest way to confirm the
# package name, version and architecture are what you expect.
if command -v dpkg-deb >/dev/null 2>&1 && [[ -d "$BUNDLE_DIR" ]]; then
    while IFS= read -r deb; do
        step "Debian metadata: $(basename "$deb")"
        dpkg-deb -f "$deb" Package Version Architecture Maintainer Installed-Size 2>/dev/null | sed 's/^/  /'
    done < <(find "$BUNDLE_DIR" -type f -name '*.deb' 2>/dev/null | sort)
fi

printf '\n%sDone.%s\n' "$C_GREEN" "$C_RESET"
