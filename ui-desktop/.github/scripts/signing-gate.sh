#!/usr/bin/env bash
# Checks the signing material of one desktop platform and decides whether that
# platform may be published.
#
# Usage: signing-gate.sh <macos|windows> [allow-unsigned-list]
#
#   allow-unsigned-list   the platforms that may be published unsigned, on
#                         purpose, as a comma-separated list (the workflow's
#                         "allow_unsigned" dispatch input). A platform in the
#                         list is published **unsigned**: the signing material
#                         is not handed to the bundler at all, so the artifact
#                         is exactly what the name says it is.
#
# The values a platform needs, and where they live:
#
#   macos    APPLE_CERTIFICATE            secret   base64 of the Developer ID .p12
#            APPLE_CERTIFICATE_PASSWORD   secret   the password of that .p12
#            APPLE_SIGNING_IDENTITY       variable "Developer ID Application: … (TEAMID)"
#            APPLE_APP_SPECIFIC_PASSWORD  secret   app-specific password for notarization
#            APPLE_ID                     variable the Apple ID email
#            APPLE_TEAM_ID                 variable the team id
#   windows  WINDOWS_CERTIFICATE          secret   base64 of the Authenticode .pfx
#            WINDOWS_CERTIFICATE_PASSWORD  secret   the password of that .pfx
#
# Linux is not in this list on purpose: a deb/rpm/AppImage carries no code
# signature in this repository, and Linux has no equivalent of Gatekeeper or
# SmartScreen that refuses an unsigned file.
#
# A missing value is a failure and not a warning: an unsigned macOS app and an
# unsigned Windows installer are both refused by the operating system, and the
# person who installs one is told nothing about why. The failure names the
# exact values that are missing, the way the Android keystore step does.
#
# The decision is printed as KEY=VALUE lines and, when GITHUB_OUTPUT is set,
# written there as well:
#
#   SIGNING_READY=true|false      the signing material is complete
#   SIGNING_UNSIGNED=true|false   the platform is published unsigned on purpose
#
# Exit code: 0 when the platform may be published (signed, or explicitly
# opted out), 1 when the material is missing and the platform is not opted out.
set -euo pipefail

platform="${1:-}"
allow="${2:-}"

fail() {
    echo "::error::$1"
    exit 1
}

case "$platform" in
    macos)
        required=(
            "APPLE_CERTIFICATE (base64 of the Developer ID .p12)"
            "APPLE_CERTIFICATE_PASSWORD (the password of that .p12)"
            "APPLE_SIGNING_IDENTITY (variable: Developer ID Application: <name> (<TEAMID>))"
            "APPLE_APP_SPECIFIC_PASSWORD (an app-specific password for notarization)"
            "APPLE_ID (variable: the Apple ID email)"
            "APPLE_TEAM_ID (variable: the team id)"
        )
        ;;
    windows)
        required=(
            "WINDOWS_CERTIFICATE (base64 of the Authenticode .pfx)"
            "WINDOWS_CERTIFICATE_PASSWORD (the password of that .pfx)"
        )
        ;;
    *)
        fail "unknown platform '$platform' (expected macos or windows)"
        ;;
esac

# The opt-out list is validated here, so that a typo in it fails the run
# instead of silently publishing a platform nobody meant to publish unsigned.
opted_out=false
if [ -n "$allow" ]; then
    for entry in ${allow//,/ }; do
        case "$entry" in
            macos | windows) ;;
            *) fail "allow_unsigned lists '$entry', which is not a desktop platform (macos, windows)" ;;
        esac
        if [ "$entry" = "$platform" ]; then
            opted_out=true
        fi
    done
fi

missing=()
for entry in "${required[@]}"; do
    name="${entry%% *}"
    if [ -z "${!name:-}" ]; then
        missing+=("$entry")
    fi
done

ready=false
unsigned=false
if [ "${#missing[@]}" -eq 0 ]; then
    ready=true
    echo "the $platform signing material is complete"
elif [ "$opted_out" = true ]; then
    unsigned=true
    echo "::warning::$platform would be published UNSIGNED on purpose, because allow_unsigned lists it. The missing material is: ${missing[*]}"
else
    echo "::error::the $platform signing material is incomplete, so this release would publish an unsigned artifact. Missing: ${missing[*]}"
    echo "::error::configure the value(s) named above, or re-run this workflow with allow_unsigned=$platform to publish $platform unsigned on purpose."
fi

echo "SIGNING_READY=$ready"
echo "SIGNING_UNSIGNED=$unsigned"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "signing_ready=$ready"
        echo "signing_unsigned=$unsigned"
    } >> "$GITHUB_OUTPUT"
fi

if [ "$ready" = false ] && [ "$unsigned" = false ]; then
    exit 1
fi
