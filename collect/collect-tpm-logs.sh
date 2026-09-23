#!/usr/bin/env bash
# Collect Tenable Patch Management client logs on Linux or macOS into a bundle that
# tenable-patch-mcp reads directly:  <HOST>/PatchClient/logs/...
#
#   sudo ./collect-tpm-logs.sh [days] [output_dir]
#
# days: only files modified in the last N days (0 = everything, the default).
# Read-only apart from a temporary staging folder that is removed afterwards.
set -euo pipefail

DAYS="${1:-0}"
OUT="${2:-$PWD}"
HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%d-%H%M)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC="/opt/tenable/patchclient/logs"
DEST="$WORK/$HOST/PatchClient/logs"
mkdir -p "$DEST"

if [[ -d "$SRC" ]]; then
  if [[ "$DAYS" -gt 0 ]]; then
    (cd "$SRC" && find . -type f \( -mtime "-$DAYS" -o -name revision.properties \) -print0 |
      while IFS= read -r -d '' file; do
        mkdir -p "$DEST/$(dirname "$file")"
        cp -p "$file" "$DEST/$file"
      done)
  else
    cp -Rp "$SRC/." "$DEST/"
  fi
else
  echo "warning: $SRC not found" >&2
fi

# macOS installation log
if [[ -f /opt/tenable/logs/adaptiva.log ]]; then
  mkdir -p "$WORK/$HOST/AdaptivaSetupLogs"
  cp -p /opt/tenable/logs/adaptiva.log "$WORK/$HOST/AdaptivaSetupLogs/adaptiva-install.log"
fi

# Linux service journal (short-iso timestamps, which the server parses)
if command -v journalctl >/dev/null 2>&1; then
  if [[ "$DAYS" -gt 0 ]]; then
    journalctl -u adaptivaclientd.service --since "$DAYS days ago" --no-pager -o short-iso \
      > "$DEST/AdaptivaClientdService.log" 2>/dev/null || true
  else
    journalctl -u adaptivaclientd.service --no-pager -o short-iso \
      > "$DEST/AdaptivaClientdService.log" 2>/dev/null || true
  fi
fi

mkdir -p "$OUT"
BUNDLE="$OUT/TPM-Logs-$HOST-$STAMP.tar.gz"
tar -czf "$BUNDLE" -C "$WORK" "$HOST"
echo "Bundle: $BUNDLE"
