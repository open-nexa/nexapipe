#!/usr/bin/env bash
# Verify that the generated Debian packages carry the service upgrade lifecycle.
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-src-tauri/target}"
PACKAGE_NAME="nexa"
SERVICE_UNIT="nexa-service.service"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "::error::dpkg-deb is required to verify Debian maintainer scripts"
    exit 1
}

mapfile -t debs < <(find "$TARGET_DIR" -type f -path '*/bundle/deb/*.deb' | sort)
if (( ${#debs[@]} == 0 )); then
    echo "::error::no Debian bundles found under $TARGET_DIR"
    exit 1
fi

fail() {
    echo "::error::$1"
    exit 1
}

require_text() {
    local file="$1"
    local text="$2"
    grep -Fq "$text" "$file" || fail "$(basename "$file") is missing: $text"
}

for deb in "${debs[@]}"; do
    echo "Verifying $(basename "$deb")"
    [[ "$(dpkg-deb -f "$deb" Package)" == "$PACKAGE_NAME" ]] \
        || fail "unexpected Debian package name in $(basename "$deb")"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    dpkg-deb -e "$deb" "$work"

    for script in preinst postinst prerm postrm; do
        path="$work/$script"
        [[ -f "$path" ]] || fail "$(basename "$deb") has no $script"
        [[ -x "$path" ]] || fail "$(basename "$deb") has a non-executable $script"
        sh -n "$path" || fail "$(basename "$deb") has invalid shell syntax in $script"
    done

    # Upgrade: stop the running service before unpacking and restore its previous state.
    require_text "$work/preinst" 'systemctl is-active --quiet "$SERVICE"'
    require_text "$work/preinst" 'systemctl is-activating --quiet "$SERVICE"'
    require_text "$work/preinst" 'systemctl stop "$SERVICE"'
    require_text "$work/postinst" 'systemctl daemon-reload'
    require_text "$work/postinst" 'systemctl restart "$SERVICE"'
    require_text "$work/postinst" 'systemctl try-restart "$SERVICE"'

    # Remove: stop/disable the optional service and clean up its unit file.
    require_text "$work/prerm" 'systemctl stop "$SERVICE"'
    require_text "$work/prerm" 'systemctl disable "$SERVICE"'
    require_text "$work/postrm" 'remove|purge'
    require_text "$work/postrm" 'systemctl daemon-reload'

    rm -rf "$work"
    trap - EXIT
done

echo "Debian service lifecycle verification passed for ${#debs[@]} package(s)"
