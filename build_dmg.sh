#!/usr/bin/env bash
#
# build_dmg.sh — build the nexa desktop app (Tauri 2) macOS DMG locally.
#
# Mirrors build_deb.sh / build_windows.ps1 locally: fills the gaps that CI
# handles via github runners but a macOS laptop still needs.
#
# What it does:
#   1. Preflight  - ui-desktop submodule present, crates/ path dependency
#                   reachable, node/npm/cargo on PATH, rustup macOS target,
#                   Tauri macOS deps (Xcode CLI tools) present.
#   2. Frontend   - npm install (skipped when node_modules exists), then a probe
#                   of the local @tauri-apps/cli; wipe & reinstall on failure.
#   3. Override   - write .workbuddy/build-override.json that:
#                   * enables only macOS bundle target (app dmg), drops
#                     Windows/Linux ones so the build does not waste time
#                   * disables updater signing unless both signing vars set
#                   * forces npm for the frontend build
#   4. Build      - tauri build --target <triple> --bundles app,dmg
#   5. Summary    - print produced .app / .dmg / .sig paths and sizes.
#
# Usage:
#   ./build_dmg.sh                     # host native arch, release profile
#   ./build_dmg.sh --debug             # debug profile — quicker, not distributable
#   ./build_dmg.sh --arch arm64        # explicit target triple suffix
#   ./build_dmg.sh --bundles app,dmg   # Tauri bundle targets (default app,dmg)
#   ./build_dmg.sh --check             # environment check only, prints plan
#   ./build_dmg.sh --open              # open the artefact dir in Finder
#   ./build_dmg.sh --clean             # remove dist/ + bundle output before build
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ARCH=""
BUNDLES="app,dmg"
RELEASE=false
NO_BUNDLE=false
DEBUG_BUILD=false
SKIP_TYPE_CHECK=false
SKIP_FRONTEND=false
SKIP_INSTALL=false
FORCE_INSTALL=false
NO_SIGN=false
CLEAN=false
CHECK_ONLY=false
OPEN=false

# ---------------------------------------------------------------------------
# Output helpers (same shape as build_deb.sh / build_windows.ps1)
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
build_dmg.sh - build the nexa desktop macOS DMG (Tauri 2)

Options:
  --arch <amd64|arm64>  Target macOS architecture (default: host).
  --bundles <list>       Comma-separated Tauri bundle targets, default "app,dmg".
  --release              Build the Rust code in release mode (already the default).
  --debug                Build the Rust code in debug mode: much faster, bigger binary.
  --no-bundle            Build the binary only, skip packaging.
  --skip-type-check      Frontend build runs `npx vite build`, skipping vue-tsc.
  --skip-frontend        Do not rebuild the frontend at all; dist/ must be current.
  --skip-install         Skip npm install even when node_modules is missing.
  --force-install        Run npm install even when node_modules exists.
  --no-sign              Never create updater artefacts, even with a signing key.
  --clean                Delete ui-desktop/dist and the bundle output before building.
  --check                Preflight only: print the resolved paths, versions, plan.
  --open                 Open the artefact directory in Finder when the build finishes.
  -h, --help             Show this help and exit.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)       ARCH="$2"; shift 2 ;;
        --bundles)    BUNDLES="$2"; shift 2 ;;
        --release)    RELEASE=true; shift ;;
        --no-bundle)  NO_BUNDLE=true; shift ;;
        --debug)      DEBUG_BUILD=true; shift ;;
        --skip-type-check) SKIP_TYPE_CHECK=true; shift ;;
        --skip-frontend)   SKIP_FRONTEND=true; shift ;;
        --skip-install)    SKIP_INSTALL=true; shift ;;
        --force-install)   FORCE_INSTALL=true; shift ;;
        --no-sign)         NO_SIGN=true; shift ;;
        --clean)           CLEAN=true; shift ;;
        --check)           CHECK_ONLY=true; shift ;;
        --open)            OPEN=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1"; ;;
    esac
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$ROOT_DIR/ui-desktop"
TAURI_DIR="$DESKTOP_DIR/src-tauri"
BUNDLE_DIR="$TAURI_DIR/target"
PROFILE_DIR="$BUNDLE_DIR"
OVERRIDE_DIR="$DESKTOP_DIR/.workbuddy"
OVERRIDE_FILE="$OVERRIDE_DIR/build-override.json"

# The Tauri CLI as installed in ui-desktop, addressed by absolute path.
#
# Not `npx tauri`: npx resolves the executable from the *current* directory, so
# invoking it while sitting anywhere else (the repo root, say) fails with
# "could not determine executable to run" even though the CLI is perfectly
# healthy. That false negative is what used to make this script wipe
# node_modules, reinstall, probe from the same wrong directory and then die
# claiming the CLI was broken after a reinstall.
TAURI_BIN="$DESKTOP_DIR/node_modules/.bin/tauri"

# Whether the locally installed Tauri CLI can actually be executed.
tauri_cli_works() {
    [[ -x "$TAURI_BIN" ]] && "$TAURI_BIN" --version >/dev/null 2>&1
}

# Its version string, empty when it cannot be run (never fails the script).
tauri_cli_version() {
    "$TAURI_BIN" --version 2>/dev/null | head -n 1
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
step "Preflight"

[[ -d "$DESKTOP_DIR/.git" ]]                || die "ui-desktop submodule not initialised (run: git submodule update --init --recursive)"
[[ -f "$TAURI_DIR/Cargo.toml" ]]            || die "src-tauri/Cargo.toml missing"
[[ -f "$TAURI_DIR/tauri.conf.json" ]]       || die "src-tauri/tauri.conf.json missing"

# Everything past this point — the CLI probe, npm install and the build — expects
# to run inside ui-desktop. The paths above are absolute, so entering it here is
# safe and means the probe sees the same tree the build will.
cd "$DESKTOP_DIR"

command -v node    >/dev/null || die "node not on PATH"
command -v npm     >/dev/null || die "npm not on PATH"
command -v cargo   >/dev/null || die "cargo not on PATH"
command -v xcodebuild >/dev/null || warn "xcodebuild not found — Tauri macOS bundle may fail without Xcode CLI tools"

# macOS target triple
HOST_CPU="$(uname -m)"
case "$HOST_CPU" in
    arm64) HOST_TRIPLE="aarch64-apple-darwin" ;;
    x86_64) HOST_TRIPLE="x86_64-apple-darwin" ;;
    *) die "unsupported macOS host CPU: $HOST_CPU" ;;
esac

if [[ -z "$ARCH" ]]; then
    TARGET_TRIPLE="$HOST_TRIPLE"
else
    case "$ARCH" in
        amd64) TARGET_TRIPLE="x86_64-apple-darwin" ;;
        arm64) TARGET_TRIPLE="aarch64-apple-darwin" ;;
        *) die "Invalid --arch: $ARCH (use amd64|arm64)" ;;
    esac
fi

# Rustup target
if ! rustup target list --installed 2>/dev/null | grep -q "$TARGET_TRIPLE"; then
    warn "rustup target $TARGET_TRIPLE not installed — attempting to install"
    rustup target add "$TARGET_TRIPLE" || warn "could not install target; build may fail"
fi

# Tauri CLI probe. A fresh checkout legitimately has no node_modules, so an
# unusable CLI is not fatal here — install once and re-probe.
if ! tauri_cli_works; then
    if $SKIP_INSTALL; then
        die "Tauri CLI not runnable at $TAURI_BIN, drop --skip-install to let the script install it"
    fi
    warn "Tauri CLI not runnable yet — installing frontend dependencies"
    npm install --no-audit --no-fund
    tauri_cli_works || die "Tauri CLI still not runnable after installing ($TAURI_BIN)"
fi
ok "tauri CLI $(tauri_cli_version)"

# `tauri build` builds release unless told otherwise, so PROFILE has to match the
# flag we actually pass below — mismatch made the artefact scan look in the other
# profile's bundle directory and report a build that had just succeeded as empty.
if $DEBUG_BUILD && $RELEASE; then
    die "--debug and --release are mutually exclusive"
fi
PROFILE="release"
$DEBUG_BUILD && PROFILE="debug"

SIGNING_ENABLED="false"
if [[ "$NO_SIGN" != "true" ]] && [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]] && [[ -n "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" ]]; then
    SIGNING_ENABLED="true"
fi

BEFORE_BUILD="npm run build"
if $SKIP_TYPE_CHECK; then BEFORE_BUILD="npx vite build"; fi
if $SKIP_FRONTEND; then BEFORE_BUILD=""; fi

TAURI_ARGS=(build --target "$TARGET_TRIPLE")
if $NO_BUNDLE; then
    TAURI_ARGS+=(--no-bundle)
else
    TAURI_ARGS+=(--bundles "$BUNDLES")
fi
# `tauri build` has no `--release` flag — release *is* its default, only `--debug`
# is accepted. The old `$RELEASE && TAURI_ARGS+=(--release)` therefore made every
# `./build_dmg.sh --release` run die with "unexpected argument '--release'".
if $DEBUG_BUILD; then
    TAURI_ARGS+=(--debug)
fi
TAURI_ARGS+=(--config "$OVERRIDE_FILE")

step "Build plan"
printf '  %-18s %s\n' "working dir:"  "$DESKTOP_DIR"
printf '  %-18s %s\n' "target triple:" "$TARGET_TRIPLE"
printf '  %-18s %s\n' "profile:"       "$PROFILE"
printf '  %-18s %s\n' "frontend cmd:"  "${BEFORE_BUILD:-(frontend build skipped)}"
printf '  %-18s %s\n' "override:"      "$OVERRIDE_FILE"
printf '  %-18s %s\n' "bundles:"       "$($NO_BUNDLE && echo '(none, --no-bundle)' || echo "$BUNDLES")"
printf '  %-18s %s\n' "updater sign:"  "$SIGNING_ENABLED"
printf '  %-18s %s\n' "command:"       "$TAURI_BIN ${TAURI_ARGS[*]}"

if $CHECK_ONLY; then
    ok "preflight finished (--check, nothing was built)"
    exit 0
fi

# ---------------------------------------------------------------------------
# Frontend dependencies (cwd is already ui-desktop, see preflight)
# ---------------------------------------------------------------------------
if $SKIP_INSTALL; then
    step "Skipping npm install (--skip-install)"
elif $FORCE_INSTALL || [[ ! -d node_modules ]]; then
    step "Installing frontend dependencies"
    npm install --no-audit --no-fund
else
    step "node_modules exists, skipping npm install (--force-install to rerun)"
fi

if ! tauri_cli_works; then
    if $SKIP_INSTALL; then
        die "Tauri CLI not runnable at $TAURI_BIN, drop --skip-install to let the script install it"
    fi
    warn "Tauri CLI not runnable — wiping node_modules and reinstalling once"
    # package-lock.json is deliberately left alone: it is the record of the tree
    # that is supposed to resolve, and regenerating it would paper over the very
    # mismatch this branch exists to repair.
    rm -rf node_modules
    npm install --no-audit --no-fund
    tauri_cli_works || die "Tauri CLI still not runnable after reinstalling ($TAURI_BIN)"
fi
ok "tauri CLI $(tauri_cli_version)"

# ---------------------------------------------------------------------------
# Clean (optional)
# ---------------------------------------------------------------------------
if $CLEAN; then
    step "Cleaning old artefacts"
    for p in "$DESKTOP_DIR/dist" "$TAURI_DIR/target/$TARGET_TRIPLE/$PROFILE/bundle"; do
        if [[ -e "$p" ]]; then info "removing $p"; rm -rf "$p"; fi
    done
fi

# ---------------------------------------------------------------------------
# Override config — macOS-only: drop Windows wintun resource and updater signing
# unless the user exported signing env vars.
# ---------------------------------------------------------------------------
step "Writing the override config"
mkdir -p "$OVERRIDE_DIR"
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
# Build
# ---------------------------------------------------------------------------
step "Building (the first build compiles the whole Rust dependency tree and can take ten minutes or more)"
START=$(date +%s)
"$TAURI_BIN" "${TAURI_ARGS[@]}"
END=$(date +%s)
ok "build finished in $(( (END - START) / 60 ))m $(( (END - START) % 60 ))s"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "Artefacts"
ARTIFACT_DIR="$TAURI_DIR/target/$TARGET_TRIPLE/$PROFILE/bundle"
if $NO_BUNDLE; then
    info "no bundles requested (--no-bundle)"
    info "binary: $TAURI_DIR/target/$TARGET_TRIPLE/$PROFILE/nexa"
else
    FOUND=0
    if [[ -d "$ARTIFACT_DIR" ]]; then
        # `.app` is a directory, so it has to be matched by name alone and pruned
        # to stop find walking into it — the old `-type f -name '*.app'` could
        # never match, which is why an app-only build reported itself as empty.
        while IFS= read -r f; do
            FOUND=1
            printf '  %8s MB  %s\n' "$(du -sm "$f" 2>/dev/null | cut -f1)" "$f"
        done < <(find "$ARTIFACT_DIR" -maxdepth 3 \
            \( -name '*.dmg' -o -name '*.tar.gz' -o -name '*.sig' -o -name '*.app' \) \
            -prune 2>/dev/null | sort)
    fi
    if (( FOUND == 0 )); then
        warn "no artefacts found, check $ARTIFACT_DIR"
    fi
fi

$OPEN && {
    if [[ -d "$ARTIFACT_DIR" ]]; then
        step "Opening $ARTIFACT_DIR"
        open "$ARTIFACT_DIR"
    fi
}

printf '\n%sDone.%s\n' "$C_GREEN" "$C_RESET"
