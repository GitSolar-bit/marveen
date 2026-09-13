#!/bin/bash
# Contract tests for the morning briefing's same-day dedup stamp.
# Run: bash scripts/__tests__/morning-stamp-gate.test.sh
#
# Bug being locked out (observed 2026-09-13): the stamp recorded "the process
# exited 0", not "the owner got the briefing". The 07:27 run refused its own
# task (its config dir carried no channel allowlist, so the reply tool rejected
# the owner's chat_id), printed an explanation, exited 0 -- and stamped the day
# as delivered. The guard then suppressed every retry and the owner got nothing.
#
# Fix under test: the run must print MORNING_SENT_OK on its own line, which it
# is told to do ONLY after a reply tool call actually succeeded. No sentinel
# means no stamp, so the next trigger tries again.
#
# Hermetic: `claude` is a stub on PATH, and the script runs against a throwaway
# INSTALL_DIR, so nothing is sent and the real store/ is untouched.

set -u

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
assert_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TODAY="$(date +%F)"

# Builds a throwaway install with a `claude` stub that behaves as asked, runs
# the briefing, and echoes the resulting stamp content ("<none>" if unstamped).
# $1: stub stdout, $2: stub exit code
run_case() {
  local stub_out="$1" stub_rc="$2"
  local dir="$TMP/inst.$RANDOM"
  mkdir -p "$dir/scripts" "$dir/store" "$dir/bin"
  cp "$REPO/scripts/morning-briefing.sh" "$dir/scripts/"
  printf 'ALLOWED_CHAT_ID=1234\n' > "$dir/.env"
  { echo '#!/bin/bash'
    printf 'cat <<'"'"'STUBEOF'"'"'\n%s\nSTUBEOF\n' "$stub_out"
    echo "exit $stub_rc"
  } > "$dir/bin/claude"
  chmod +x "$dir/bin/claude"
  # CLAUDE_BIN, not PATH: the script exports its own minimal PATH, so a
  # prepended stub dir is discarded and the real binary would run instead.
  CLAUDE_BIN="$dir/bin/claude" bash "$dir/scripts/morning-briefing.sh" >/dev/null 2>&1
  cat "$dir/store/.morning-last-sent" 2>/dev/null || echo "<none>"
}

echo "morning-briefing stamp gate"

assert_eq "sentinel present -> stamped" \
  "$TODAY" "$(run_case 'Elkuldve.
MORNING_SENT_OK' 0)"

assert_eq "refusal without sentinel -> NOT stamped (the 2026-09-13 bug)" \
  "<none>" "$(run_case 'A reply tool elutasitotta a chat_id-t, nem kuldtem semmit.' 0)"

assert_eq "sentinel only as part of a longer line -> NOT stamped" \
  "<none>" "$(run_case 'Nem sikerult, ezert nem irom ki hogy MORNING_SENT_OK volna.' 0)"

assert_eq "nonzero exit with sentinel -> NOT stamped" \
  "<none>" "$(run_case 'MORNING_SENT_OK' 1)"

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
