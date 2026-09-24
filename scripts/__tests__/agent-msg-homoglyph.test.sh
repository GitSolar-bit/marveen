#!/usr/bin/env bash
# MSGGATE924 -- the mandated send route must not carry invisible letters.
#
# WHAT THIS GUARDS. A Cyrillic letter inside a Hungarian word is invisible and
# breaks every later search for that word: the text looks right and matches
# nothing. Measured 2026-09-24 across three agents: two had built a private
# wrapper with this check, independently, because both had been bitten; the
# third had none. And no CLAUDE.md prescribes those wrappers -- they all name
# scripts/agent-msg.sh, which had no check at all. The predictable result: the
# agent who WROTE such a wrapper called this script directly all day, with the
# checker run BESIDE it in a separate command rather than in front of it. One
# message went out contaminated while the checker printed "NEM KULDOM EL" next
# to it. A rule that has to be remembered is not a rule.
#
# The gate sits on the RAW text, before json.dumps: an encoded body shows the
# letter as \uXXXX, where a checker would no longer see a letter at all.
#
# Run:  bash scripts/__tests__/agent-msg-homoglyph.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HELPER="${HELPER_BIN:-$ROOT/scripts/agent-msg.sh}"
FAILS=0; N=0
ok() { N=$((N+1)); if [ "$2" = "0" ]; then echo "PASS  $1"; else echo "FAIL  $1${3:+  -- $3}"; FAILS=$((FAILS+1)); fi; }

# The instrument proves its own target first: every "nothing was sent"
# assertion below is satisfied by a missing helper just as well as by a
# working gate.
[ -r "$HELPER" ] || { echo "FATAL: the helper is missing: $HELPER" >&2; exit 2; }

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/msggate.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT
BIN="$SANDBOX/bin"; mkdir -p "$BIN"
printf 'test-token\n' > "$SANDBOX/token"

# curl stub: nothing leaves the machine, and the call is RECORDED -- that record
# is what turns "was refused" into a measurable claim instead of an absence.
cat > "$BIN/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "${CURL_CALLS:-/dev/null}"
printf '{"id":4242}\n200'
STUB
chmod +x "$BIN/curl"
for t in python3 sed tail cat printf date mktemp rm; do
  p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$BIN/$t"
done

CY="$(python3 -c 'print(chr(0x43E))')"   # CYRILLIC SMALL LETTER O
send() {  # send <content-or-dash> [extra env assignments via ENVX]
  : > "$SANDBOX/calls.txt"
  OUT="$(env PATH="$BIN:$PATH" CURL_CALLS="$SANDBOX/calls.txt" \
             MARVEEN_TOKEN_FILE="$SANDBOX/token" ${ENVX:-} \
             /bin/bash "$HELPER" igor hex "$1" 2>"$SANDBOX/err.txt")"
  RC=$?
  ERR="$(cat "$SANDBOX/err.txt")"
  CALLED="$([ -s "$SANDBOX/calls.txt" ] && echo yes || echo no)"
}

# POSITIVE CONTROL: clean text must still go out. A gate that refuses
# everything would pass every "was not sent" assertion below.
ENVX= send "tiszta magyar szoveg, arvizturo tukorfurogep"
ok "clean text is still sent" "$([ "$RC" = "0" ] && [ "$CALLED" = "yes" ] && echo 0 || echo 1)" "rc=$RC curl-called=$CALLED"
ok "  ...and the helper reports the id" "$(printf '%s' "$OUT" | grep -q 'id=4242' && echo 0 || echo 1)" "out: $OUT"

# THE ASSERTION THAT FAILS WITHOUT THE GATE.
ENVX= send "szennyezett sz${CY}veg egy lathatatlan betuvel"
ok "contaminated text is REFUSED" "$([ "$RC" = "3" ] && echo 0 || echo 1)" "rc=$RC (expected 3)"
ok "  ...and NOTHING was sent" "$([ "$CALLED" = "no" ] && echo 0 || echo 1)" "curl was called anyway"
ok "  ...and the refusal names the letter" "$(printf '%s' "$ERR" | grep -qi 'CYRILLIC' && echo 0 || echo 1)" "stderr: $ERR"
# The message must steer to the right fix, or the next person reaches for the
# override and the gate ends up switched off.
ok "  ...and it steers away from the override, not toward it" \
   "$(printf '%s' "$ERR" | grep -q 'NE masold at' && printf '%s' "$ERR" | grep -q 'nem elso' && echo 0 || echo 1)" \
   "stderr: $ERR"

# STDIN form takes the same route -- it is the form used for long messages.
: > "$SANDBOX/calls.txt"
OUT="$(printf 'stdin sz%sveg' "$CY" | env PATH="$BIN:$PATH" CURL_CALLS="$SANDBOX/calls.txt" \
        MARVEEN_TOKEN_FILE="$SANDBOX/token" /bin/bash "$HELPER" igor hex - 2>/dev/null)"
ok "the STDIN form is gated too" "$([ "$?" = "3" ] && [ ! -s "$SANDBOX/calls.txt" ] && echo 0 || echo 1)"

# TISZTIT=1 cleans and sends -- and the payload that leaves must be clean.
ENVX="TISZTIT=1" send "tisztitando sz${CY}veg"
ok "TISZTIT=1 sends the CLEANED text" "$([ "$RC" = "0" ] && [ "$CALLED" = "yes" ] && echo 0 || echo 1)" "rc=$RC"
# The recorded arguments must be DECODED before looking for the letter.
# json.dumps escapes it to \u043e, i.e. plain ASCII -- a raw scan of the
# recorded text finds nothing and the assertion passes on a body that still
# carries it. Measured: this check was GREEN against the ungated helper until
# the decode was added.
ok "  ...and no Cyrillic letter reaches the payload" \
   "$(python3 -c "
import json, sys, unicodedata
args = open('$SANDBOX/calls.txt', encoding='utf-8').read().splitlines()
sent = ''
for a in args:
    try:
        d = json.loads(a)
    except Exception:
        continue
    if isinstance(d, dict) and 'content' in d:
        sent = d['content']
if not sent:
    sys.stderr.write('no JSON body was recorded')
    sys.exit(1)
bad = [c for c in sent if ord(c) > 127 and 'CYRILLIC' in unicodedata.name(c, '')]
sys.exit(1 if bad else 0)
" && echo 0 || echo 1)" "the decoded body still carries a Cyrillic letter"

# A missing checker must FAIL OPEN -- this helper is the fleet's mandated route,
# and blocking every message on an install without the lib file would be a new,
# worse failure. But it must not be silent: that silence is today's bug.
ENVX="MARVEEN_HOMOGLYPH_BIN=$SANDBOX/nincs-ilyen.py" send "tiszta szoveg checker nelkul"
ok "a missing checker still sends (fail-open)" "$([ "$RC" = "0" ] && [ "$CALLED" = "yes" ] && echo 0 || echo 1)" "rc=$RC"
ok "  ...but says so out loud" "$(printf '%s' "$ERR" | grep -q 'UNCHECKED' && echo 0 || echo 1)" "stderr: $ERR"

echo
echo "$((N-FAILS))/$N passed  (helper under test: $HELPER)"
[ "$FAILS" = "0" ] || exit 1
