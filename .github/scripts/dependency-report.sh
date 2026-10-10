#!/usr/bin/env bash
#
# Prints a markdown report of every dependency that has a newer version available
# and writes it to stdout. Run by .github/workflows/dependency-report.yml, which
# posts the result into one issue that is refreshed every week.
#
# Dependabot's version-update PRs are disabled (open-pull-requests-limit: 0 in
# .github/dependabot.yml); this script is what replaces them.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Rust: `cargo update --dry-run` reports what the resolver would move. It never
# writes Cargo.lock, so the working tree stays clean. The "Updating x vA -> vB"
# lines go to stderr, hence the 2>&1.
# ---------------------------------------------------------------------------
rust_rows() {
    local dir="$1"
    (cd "$dir" && cargo update --dry-run 2>&1) |
        sed -nE 's/^[[:space:]]*Updating ([^[:space:]]+) v([^[:space:]]+) -> v([^[:space:]]+)$/| \1 | \2 | \3 |/p'
}

# ---------------------------------------------------------------------------
# npm: `npm outdated --json` reads the installed tree, so the caller has to run
# npm ci first. Exit code 1 just means "something is outdated".
# ---------------------------------------------------------------------------
npm_rows() {
    local dir="$1"
    local json
    json="$(cd "$dir" && npm outdated --json 2>/dev/null || true)"
    [ -z "$json" ] && return 0
    printf '%s' "$json" |
        # current is missing when the package is not installed yet; wanted is the
        # version the lockfile asks for, which is the next best thing.
        jq -r 'to_entries[] | "| \(.key) | \(.value.current // .value.wanted // "-") | \(.value.latest) |"' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# GitHub Actions: compare the major version a workflow pins against the newest
# release of that action. Only a newer *major* is reported, because @v4 style
# refs float to the latest patch on their own, and because a release tag such as
# v4.2.2 is not comparable to the v4 shorthand. Actions pinned to a commit SHA
# are skipped on purpose: they are pinned deliberately.
# ---------------------------------------------------------------------------
actions_rows() {
    local pins
    pins="$(grep -rhoE 'uses: [A-Za-z0-9._-]+/[A-Za-z0-9._-]+@v[0-9][A-Za-z0-9._-]*' .github/workflows/*.yml 2>/dev/null | sort -u)"
    [ -z "$pins" ] && return 0

    local pin repo used latest used_major latest_major
    while IFS= read -r pin; do
        [ -z "$pin" ] && continue
        repo="${pin#uses: }"
        used="${repo#*@}"
        repo="${repo%@*}"

        latest="$(gh api "repos/${repo}/releases/latest" --jq '.tag_name' 2>/dev/null || true)"
        [ -z "$latest" ] && continue

        used_major="${used#v}"
        used_major="${used_major%%.*}"
        latest_major="${latest#v}"
        latest_major="${latest_major%%.*}"

        # Both have to be plain numbers before they can be compared.
        case "$used_major$latest_major" in
        *[!0-9]*) continue ;;
        esac
        [ -z "$used_major" ] || [ -z "$latest_major" ] && continue

        if [ "$latest_major" -gt "$used_major" ]; then
            printf '| `%s` | %s | %s |\n' "$repo" "$used" "$latest"
        fi
    done <<<"$pins"
}

emit_section() {
    local heading="$1" rows="$2"
    printf '### %s\n\n' "$heading"
    if [ -n "$rows" ]; then
        printf '| dependency | locked | latest |\n| --- | --- | --- |\n'
        printf '%s\n' "$rows"
    else
        printf 'Nothing to update.\n'
    fi
    printf '\n'
}

root_rust="$(rust_rows .)"
tauri_rust="$(rust_rows ui-desktop/src-tauri)"
npm="$(npm_rows ui-desktop)"
actions="$(actions_rows)"

printf '# Weekly dependency report\n\n'
printf 'Generated %s (UTC) from `%s`' "$(date -u '+%Y-%m-%d %H:%M')" "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    printf ' by [%s](%s/%s/actions/runs/%s)' \
        "run ${GITHUB_RUN_ID}" \
        "${GITHUB_SERVER_URL:-https://github.com}" \
        "$GITHUB_REPOSITORY" \
        "$GITHUB_RUN_ID"
fi
printf '.\n\n'

cat <<'NOTE'
Dependabot's version-update PRs are off (`open-pull-requests-limit: 0` in
`.github/dependabot.yml`); this issue is the weekly replacement, and it is
rewritten in place rather than filed again. Security updates are unaffected:
those still arrive as their own PRs.

Covered here: the root Cargo workspace, `ui-desktop/src-tauri`, the npm packages
and the version-pinned GitHub Actions. Not covered: the Android Gradle
dependencies and the Docker base images, which only get security updates.

NOTE

emit_section "Rust - root workspace (Cargo.lock)" "$root_rust"
emit_section "Rust - ui-desktop/src-tauri (Cargo.lock)" "$tauri_rust"
emit_section "npm - ui-desktop" "$npm"
emit_section "GitHub Actions" "$actions"
