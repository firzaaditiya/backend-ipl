#!/usr/bin/env bash
# Safe FIM-IPL attack simulator. It creates marker-only PHP files; it never
# executes commands, contacts a C2, or touches a real webroot by default.
set -euo pipefail

TARGET="${1:?usage: $0 <test-directory> [--spread] [--count N] [--symlink]}"
MODE="setup"
COUNT=20
SYMLINK=no
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --spread) MODE=spread ;;
    --count) COUNT="${2:?--count requires a number}"; shift ;;
    --symlink) SYMLINK=yes ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || (( COUNT < 1 || COUNT > 200 )); then
  echo "count must be between 1 and 200" >&2; exit 2
fi
[[ -f "$TARGET/wp-config.php" ]] && { echo "refusing a directory containing wp-config.php" >&2; exit 1; }

VICTIM="$TARGET/wp-content/plugins/victim-plugin/functions.php"
DECOY="$TARGET/wp-content/plugins/victim-plugin/readme.txt"
mkdir -p "$(dirname "$VICTIM")"

if [[ "$MODE" == setup ]]; then
  printf '%s\n' '<?php' '// clean victim file' 'function victim_hello() { return "hello"; }' > "$VICTIM"
  printf '%s\n' 'decoy used to test DELETED detection' > "$DECOY"
  echo "setup complete: $TARGET"
  echo "initialize the baseline, then run with --spread"
  exit 0
fi

# Existing-file modification and a new webshell-shaped marker.
printf '%s\n' '<?php // harmless simulated webshell marker' 'echo "[SIM] created";' > "$TARGET/wp-admin-load.php"
printf '%s\n' '// harmless simulated SEO marker' >> "$VICTIM"

if [[ "$MODE" == spread ]]; then
  dirs=(wp-content/uploads/2026/01/cache wp-content/uploads/2026/02/cache wp-content/plugins/cache wp-content/themes/victim/inc wp-admin/includes/cache)
  names=(index.php cache.php avatar.php.jpg .htaccess db.php)
  for ((i=1; i<=COUNT; i++)); do
    dir="${TARGET}/${dirs[$((i % ${#dirs[@]}))]}/bundle-$(printf '%03d' "$i")"
    mkdir -p "$dir"
    printf '<?php // harmless spread marker %s\necho "[SIM] spread-%s";\n' "$i" "$i" > "$dir/${names[$((i % ${#names[@]}))]}"
    (( i % 2 == 0 )) && touch -t 202301050314.07 "$dir/${names[$((i % ${#names[@]}))]}"
  done
  printf '%s\n' '# harmless simulated root rule marker' > "$TARGET/.htaccess"
  printf '%s\n' '<?php // harmless unreadable marker' > "$TARGET/wp-content/uploads/unreadable-backdoor.php"
  chmod 000 "$TARGET/wp-content/uploads/unreadable-backdoor.php"
  rm -f "$DECOY"
  if [[ "$SYMLINK" == yes ]]; then
    ln -s /etc/hostname "$TARGET/wp-content/uploads/link-to-system" 2>/dev/null || echo 'symlink unavailable; continuing'
  fi
fi
echo "simulation complete; wait for one scan cycle and verify the ledger"
