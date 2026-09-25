#!/usr/bin/env bash
# secure-uploader — SIMULATED coverage uploader used as the protected artifact.
#
# It plays the role of the Codecov Bash Uploader in this academic prototype.
# It performs NO network activity: it only locates a coverage report and
# prints what a real uploader would send. It is never executed by the tests
# or the demo; it is only hashed, signed and verified.

set -euo pipefail

UPLOADER_VERSION="__VERSION__"
REPORT_FILE="${1:-coverage.xml}"
UPLOAD_ENDPOINT="https://coverage.vendor.example/upload/v4"   # placeholder, never contacted

log() { printf '[secure-uploader %s] %s\n' "$UPLOADER_VERSION" "$*"; }

find_report() {
  if [[ -f "$REPORT_FILE" ]]; then
    printf '%s' "$REPORT_FILE"
  else
    find . -maxdepth 3 -name 'coverage*.xml' -print -quit
  fi
}

main() {
  local report
  report="$(find_report)"
  if [[ -z "$report" ]]; then
    log "no coverage report found"
    exit 0
  fi
  local lines
  lines="$(wc -l < "$report")"
  log "found report: $report ($lines lines)"
  # Only the coverage report and the commit SHA are ever transmitted.
  # Environment variables and git remotes are deliberately NOT collected.
  log "would upload report for commit ${GIT_COMMIT:-unknown} to $UPLOAD_ENDPOINT (dry run)"
}

main "$@"
