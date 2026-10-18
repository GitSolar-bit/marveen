#!/usr/bin/env bash
# agent-msg.sh --info (card 5e4110d7, HEX 3570): the message goes out with kind=info; without the switch the body
# is byte for byte what it always was (no kind key), so an older server and every existing caller are untouched.
# The curl stub records the -d body; nothing leaves the machine.
#
# Run:  bash scripts/__tests__/agent-msg-info.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HELPER="${HELPER_BIN:-$ROOT/scripts/agent-msg.sh}"
FAILS=0; N=0
ok() { N=$((N+1)); if [ "$2" = "0" ]; then echo "PASS  $1"; else echo "FAIL  $1${3:+  -- $3}"; FAILS=$((FAILS+1)); fi; }
[ -r "$HELPER" ] || { echo "FATAL: the helper is missing: $HELPER" >&2; exit 2; }

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/msginfo.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT
BIN="$SANDBOX/bin"; mkdir -p "$BIN"
printf 'test-token\n' > "$SANDBOX/token"
cat > "$BIN/curl" <<'STUB'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do [ "$1" = "-d" ] && printf '%s' "$2" > "$STUB_BODY"; shift; done
printf '{"id":7,"status":"pending"}\n200'
STUB
chmod +x "$BIN/curl"
printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/sleep"; chmod +x "$BIN/sleep"

send() {
  rm -f "$SANDBOX/body"
  OUT="$(env PATH="$BIN:$PATH" STUB_BODY="$SANDBOX/body" MARVEEN_TOKEN_FILE="$SANDBOX/token" /bin/bash "$HELPER" "$@" 2>"$SANDBOX/err.txt")"
  RC=$?
}
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2]); print("<absent>" if v is None else v)' "$SANDBOX/body" "$1"; }

send --info igor hex "tajekoztato, valasz nem kell"
ok "--info as the first argument: OK id, rc 0" "$([ "$RC" = "0" ] && [ "$OUT" = "OK id=7" ] && echo 0 || echo 1)" "rc=$RC out='$OUT'"
ok "  ...the body carries kind=info" "$([ "$(field kind)" = "info" ] && echo 0 || echo 1)" "kind=$(field kind)"
ok "  ...from, to and content are the three positionals, not shifted" \
   "$([ "$(field from)" = "igor" ] && [ "$(field to)" = "hex" ] && [ "$(field content)" = "tajekoztato, valasz nem kell" ] && echo 0 || echo 1)" "$(cat "$SANDBOX/body")"

send igor hex "feladat"
ok "NEGATIVE CONTROL: without --info the body has NO kind key (the old body, byte for byte)" \
   "$([ "$(field kind)" = "<absent>" ] && echo 0 || echo 1)" "kind=$(field kind) body=$(cat "$SANDBOX/body")"
ok "  ...and the body is exactly the three keys it always was" \
   "$([ "$(cat "$SANDBOX/body")" = '{"from": "igor", "to": "hex", "content": "feladat"}' ] && echo 0 || echo 1)" "$(cat "$SANDBOX/body")"

send igor hex --info
ok "a message whose TEXT is --info is a message, not the switch (it is only a switch as the FIRST argument)" \
   "$([ "$(field content)" = "--info" ] && [ "$(field kind)" = "<absent>" ] && echo 0 || echo 1)" "$(cat "$SANDBOX/body")"

printf 'sor1\nsor2\n' | { env PATH="$BIN:$PATH" STUB_BODY="$SANDBOX/body" MARVEEN_TOKEN_FILE="$SANDBOX/token" /bin/bash "$HELPER" --info igor hex - >/dev/null 2>&1; }
ok "--info works with the STDIN content form too" \
   "$([ "$(field kind)" = "info" ] && [ "$(field content)" = $'sor1\nsor2' ] && echo 0 || echo 1)" "$(cat "$SANDBOX/body")"

send --info igor hex
ok "--info with the content missing still fails on the missing argument, not silently" "$([ "$RC" != "0" ] && echo 0 || echo 1)" "rc=$RC"

echo
[ "$FAILS" = "0" ] && { echo "All $N agent-msg --info checks passed."; exit 0; }
echo "$FAILS of $N FAILED" >&2; exit 1
