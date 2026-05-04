#!/usr/bin/env bash
# Privacy guard for fallen-gardenia blog.
# Default: scan staged files (pre-commit). Pass --all to scan tracked files.
#
# Real identity strings live in scripts/.privacy-deny.local (gitignored),
# so they are never committed.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"
self="scripts/privacy-check.sh"
denyfile="scripts/.privacy-deny.local"

mode="staged"
[[ "${1:-}" == "--all" ]] && mode="all"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
amber() { printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

if [[ ! -f "$denyfile" ]]; then
  red "[FAIL] $denyfile not found. Create it with one regex per line (gitignored)."
  exit 1
fi

# Load deny patterns (skip blanks/comments).
mapfile -t deny_patterns < <(grep -vE '^\s*(#|$)' "$denyfile")
if [[ ${#deny_patterns[@]} -eq 0 ]]; then
  red "[FAIL] $denyfile has no patterns."
  exit 1
fi

# --- list of files to scan ---
if [[ "$mode" == "staged" ]]; then
  mapfile -d '' -t files < <(git diff --cached --name-only -z --diff-filter=ACMR)
else
  mapfile -d '' -t files < <(git ls-files -z)
fi

# Filter: skip vendored / self / deny file.
keep=()
for f in "${files[@]:-}"; do
  [[ -z "$f" ]] && continue
  case "$f" in
    themes/*) continue ;;
    "$self") continue ;;
    "$denyfile") continue ;;
  esac
  keep+=("$f")
done
files=("${keep[@]:-}")

if [[ ${#files[@]} -eq 0 ]]; then
  green "[privacy] no files to scan."
  exit 0
fi

fail=0
warn=0

for f in "${files[@]}"; do
  case "$f" in
    *.jpg|*.jpeg|*.png|*.gif|*.webp|*.heic|*.heif|*.tiff|*.mp4|*.mov|*.pdf|*.zip|*.tar|*.gz)
      if command -v exiftool >/dev/null 2>&1; then
        meta=$(exiftool -s -Author -Artist -Creator -OwnerName -GPSPosition -GPSLatitude -GPSLongitude -CameraSerialNumber -SerialNumber -HostComputer -UserComment "$f" 2>/dev/null || true)
        if [[ -n "$meta" ]]; then
          red "[FAIL] EXIF metadata in $f:"
          echo "$meta"
          fail=1
        fi
      else
        amber "[WARN] $f looks like media but exiftool is not installed — cannot verify EXIF cleanliness. Install with: sudo apt install libimage-exiftool-perl"
        warn=1
      fi
      continue
      ;;
  esac

  if file --mime-encoding -b "$f" 2>/dev/null | grep -q binary; then
    continue
  fi

  for p in "${deny_patterns[@]}"; do
    if grep -nIEH "$p" "$f" >/dev/null 2>&1; then
      red "[FAIL] deny-list match in $f:"
      grep -nIEH --color=never "$p" "$f" | head -5
      fail=1
    fi
  done

  # Generic email — warn only (excluding known-safe noreply/example).
  emails=$(grep -nIEHo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" 2>/dev/null \
           | grep -vE 'noreply\.github\.com|users\.noreply\.github\.com|example\.(com|org|net)' || true)
  if [[ -n "$emails" ]]; then
    amber "[WARN] email-like strings in $f:"
    echo "$emails" | head -5
    warn=1
  fi

  # Public IPv4 (rough): exclude private + loopback + link-local + 0/8 + 255.
  pubips=$(grep -nIEHo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$f" 2>/dev/null \
           | grep -vE '\b(0|10|127|169\.254|172\.(1[6-9]|2[0-9]|3[01])|192\.168|255)\.' || true)
  if [[ -n "$pubips" ]]; then
    amber "[WARN] public-IPv4 in $f:"
    echo "$pubips" | head -3
    warn=1
  fi

  # MAC addresses
  if grep -nIEH '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$f" >/dev/null 2>&1; then
    red "[FAIL] MAC address in $f"
    grep -nIEH --color=never '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$f" | head -3
    fail=1
  fi

  # Non-UTC timezone offsets in dates (e.g. "2026-05-04T13:37:29+10:00").
  # Excludes UTC representations (+00:00 / +0000 / Z).
  tzhits=$(grep -nIEHo '[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:?[0-9]{2}' "$f" 2>/dev/null \
           | grep -vE '[+-]00:?00' || true)
  if [[ -n "$tzhits" ]]; then
    red "[FAIL] non-UTC timezone offset in $f:"
    echo "$tzhits" | head -3
    fail=1
  fi
done

# Note: commit timestamp TZ is normalised to UTC by the post-commit hook
# (.git/hooks/post-commit), so we no longer block on the TZ env here. The
# scan above for non-UTC offsets in tracked file content still applies.

# --- Git identity sanity check ---
gn=$(git config user.name || true)
ge=$(git config user.email || true)
if [[ "$ge" != *"users.noreply.github.com" ]]; then
  red "[FAIL] git user.email is '$ge' — must be a GitHub noreply address."
  fail=1
fi
# Run user.name through deny-list too.
for p in "${deny_patterns[@]}"; do
  if printf '%s' "$gn" | grep -qE "$p"; then
    red "[FAIL] git user.name '$gn' matches deny-list pattern '$p'."
    fail=1
  fi
done
if [[ -z "$gn" ]]; then
  red "[FAIL] git user.name is empty."
  fail=1
fi

echo
if [[ $fail -ne 0 ]]; then
  red "[privacy] BLOCKED: $fail issue(s) detected."
  exit 1
fi
if [[ $warn -ne 0 ]]; then
  amber "[privacy] WARN: review warnings above. Commit allowed."
fi
green "[privacy] OK"
exit 0
