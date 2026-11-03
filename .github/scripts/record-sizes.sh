#!/usr/bin/env bash
# Record what the artifacts weigh.
#
#   .github/scripts/record-sizes.sh <label> <path>...
#
# Nothing in the pipeline weighed what it produced: the server archives, the
# desktop bundles, the APKs and the native library were all built and
# published without anybody writing down what they weighed. So "this change
# cost 1.2 MB" was not a sentence anybody could say about a release, and the
# size work had no number to be measured against.
#
# The sizes go into the job's step summary, where the reader of a release can
# see them, and into a file that is uploaded as an artifact, so the numbers
# outlive the run they were taken in.
#
# The paths are directories, walked for the files inside them. A path that
# does not exist is skipped rather than an error: a job that produces nothing
# on one platform is not a failure, it is a platform with nothing to publish.
#
# Usage:
#   .github/scripts/record-sizes.sh "server archives" dist
set -euo pipefail

LABEL="${1:-artifacts}"
shift || true

# The sizes are written here as well as into the summary: the summary is
# where a person reads them, and the file is where the next release reads
# them from.
REPORT="${SIZE_REPORT:-sizes.txt}"
: > "$REPORT"

# The total, and the table.
TOTAL=0
ROWS=""

for target in "$@"; do
  [ -e "$target" ] || continue
  while IFS= read -r file; do
    # The report is not one of the things it is reporting on.
    [ "$file" = "$REPORT" ] && continue
    size="$(wc -c < "$file" | tr -d '[:space:]')"
    TOTAL=$((TOTAL + size))
    ROWS="${ROWS}| \`$file\` | $((size / 1024)) KiB |"$'\n'
    printf '%s\t%s\n' "$file" "$size" >> "$REPORT"
  done < <(find "$target" -type f | sort)
done

if [ -z "$ROWS" ]; then
  echo "::warning::no artifact was found to weigh"
  exit 0
fi

{
  echo "### $LABEL"
  echo
  echo "| artifact | size |"
  echo "|---|---|"
  printf '%s' "$ROWS"
  echo
  echo "**Total: $((TOTAL / 1024)) KiB**"
  echo
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

echo "$LABEL: $((TOTAL / 1024)) KiB across the artifacts"
