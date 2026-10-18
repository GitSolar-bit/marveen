#!/bin/bash
# Contract tests for acknowledgement handling in the Telegram progress hooks.
# Run: bash scripts/__tests__/telegram-ack-progress.test.sh
#
# What is under test (card bb1cf047):
#   1. telegram_progress.py records, per inbound, whether it is a pure
#      acknowledgement ("ack": true), with the SAME predicate as
#      telegram-reply-guard.py (telegram_ack_lib.is_ack). Only an UNNUMBERED
#      ack word counts ("ok", "koszi", a thumbs-up). A NUMBERED short reply
#      ("118 ok", "86. ok") is NOT an ack: the owner used "86. ok" as a decision
#      one day and as an acknowledgement another, and the text cannot tell them
#      apart (measured 2026-09-30). A question mark anywhere is never an ack.
#   2. telegram_progress_clear.py (Stop) removes an ack-type placeholder QUIETLY:
#      no block, and above all no fallback send of the transcript's last assistant
#      text to the chat (an internal CLI summary going out as channel text).
#   3. telegram_progress_reply_clear.py (PostToolUse) treats a REACT on the
#      inbound of an ack-type entry as the answer, and ONLY that: a react on a
#      question or decision keeps the placeholder, and the mandatory reply with it.
#
# Every case has a CONTROL that the same setup with the opposite property still
# blocks / sends, so a green result is not what a dead hook would also return.
# Bot API traffic goes to a local stub via TELEGRAM_API_BASE (hermetic).

set -u

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
assert_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi; }

INSTALL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
HOOKS_DIR="$INSTALL_DIR/scripts/hooks"
SUBMIT_HOOK="$HOOKS_DIR/telegram_progress.py"
STOP_HOOK="$HOOKS_DIR/telegram_progress_clear.py"
REPLY_CLEAR="$HOOKS_DIR/telegram_progress_reply_clear.py"

TMP="$(mktemp -d)"
trap 'kill "$STUB_PID" 2>/dev/null; rm -rf "$TMP"' EXIT

REQLOG="$TMP/requests.log"
PORTFILE="$TMP/port"
cat > "$TMP/stub.py" <<'PYEOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
reqlog = sys.argv[1]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8") if n else ""
        method = self.path.rsplit("/", 1)[-1]
        with open(reqlog, "a", encoding="utf-8") as f:
            f.write(f"{method} {body}\n")
        out = {"ok": True, "result": {"message_id": 9001} if method == "sendMessage" else True}
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
srv = HTTPServer(("127.0.0.1", 0), H)
with open(sys.argv[2], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
python3 "$TMP/stub.py" "$REQLOG" "$PORTFILE" &
STUB_PID=$!
for _ in $(seq 1 50); do [ -s "$PORTFILE" ] && break; sleep 0.1; done
PORT="$(cat "$PORTFILE" 2>/dev/null)"
if [ -z "$PORT" ]; then echo "FATAL: stub did not start"; exit 1; fi
export TELEGRAM_API_BASE="http://127.0.0.1:$PORT"

CHAT="10000000001"
SID="ACKSID"

new_state() { # dir
    mkdir -p "$1/progress"
    printf 'TELEGRAM_BOT_TOKEN=TESTTOKEN\n' > "$1/.env"
    printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"INTERNAL_CLI_SUMMARY"}]}}' \
        > "$1/transcript.jsonl"
}
# Write a pending file. Args: dir, then JSON list text.
set_pend() { printf '%s\n' "$2" > "$1/progress/$SID.json"; }
pend_count() { python3 - "$1/progress/$SID.json" <<'PYEOF'
import json, sys
try:
    print(len(json.load(open(sys.argv[1]))))
except Exception:
    print(0)
PYEOF
}
pend_field() { # dir index field
    python3 - "$1/progress/$SID.json" "$2" "$3" <<'PYEOF'
import json, sys
try:
    print(json.load(open(sys.argv[1]))[int(sys.argv[2])].get(sys.argv[3]))
except Exception:
    print("MISSING")
PYEOF
}
count() { grep -c "^$1 " "$REQLOG" 2>/dev/null || true; }
reset_log() { : > "$REQLOG"; }

submit() { # dir prompt
    python3 - "$SID" "$2" <<'PYEOF' | TELEGRAM_STATE_DIR="$1" python3 "$SUBMIT_HOOK"
import json, sys
print(json.dumps({"session_id": sys.argv[1], "prompt": sys.argv[2]}))
PYEOF
}
channel() { # message_id text [extra attrs]
    printf '<channel source="plugin:telegram:telegram" chat_id="%s" message_id="%s" user="owner" ts="2026-09-30T13:00:00.000Z"%s>%s</channel>' \
        "$CHAT" "$1" "${3:-}" "$2"
}
stop_hook() { # dir active
    printf '{"session_id":"%s","transcript_path":"%s","stop_hook_active":%s}' "$SID" "$1/transcript.jsonl" "$2" \
        | TELEGRAM_STATE_DIR="$1" python3 "$STOP_HOOK"
}
post_tool() { # dir tool tool_input_json
    printf '{"session_id":"%s","tool_name":"%s","tool_input":%s}' "$SID" "$2" "$3" \
        | TELEGRAM_STATE_DIR="$1" python3 "$REPLY_CLEAR"
}
REACT="mcp__plugin_telegram_telegram__react"
REPLY="mcp__plugin_telegram_telegram__reply"

echo "telegram-ack-progress tests"
echo "==========================="

# ---------------------------------------------------------------------------
echo ""
echo "(1) telegram_progress.py records the ack flag with the shared predicate"
i=0
for row in "ok|true" "köszi|true" "köszi 👍|true" "👍|true" "118 ok|false" "86. ok|false" "104: ok|false" "7) ok|false" "118 jo?|false" "jó?|false" "ok?|false" "igen|false" "mehet|false" "91 igen|false" "115 mehet|false" "104 ok de mikor?|false" "118|false" "mennyi 2+2?|false"; do
    text="${row%|*}"; want="${row##*|}"; i=$((i + 1))
    SD="$TMP/s1-$i"; new_state "$SD"; reset_log
    submit "$SD" "$(channel "50$i" "$text")"
    assert_eq "inbound '$text' -> ack=$want" "$want" "$(pend_field "$SD" 0 ack | tr 'A-Z' 'a-z')"
    assert_eq "  ... placeholder recorded for src 50$i" "50$i" "$(pend_field "$SD" 0 src_mid)"
done
SD="$TMP/s1-photo"; new_state "$SD"
submit "$SD" "$(channel 602 "(photo)" ' image_path="/tmp/x.jpg"')"
assert_eq "the real photo inbound '(photo)' + image_path -> ack=false (a reply is owed)" "false" "$(pend_field "$SD" 0 ack | tr 'A-Z' 'a-z')"
SD="$TMP/s1-media"; new_state "$SD"
submit "$SD" "$(channel 600 "" ' image_path="/tmp/x.jpg"')"
assert_eq "bare photo (empty text + image_path) -> ack=true" "true" "$(pend_field "$SD" 0 ack | tr 'A-Z' 'a-z')"
SD="$TMP/s1-empty"; new_state "$SD"
submit "$SD" "$(channel 601 "")"
assert_eq "empty text WITHOUT an attachment is a parse miss, not an ack -> ack=false" "false" "$(pend_field "$SD" 0 ack | tr 'A-Z' 'a-z')"

# ---------------------------------------------------------------------------
echo ""
echo "(2) Stop hook: an ack-type placeholder is removed quietly"
SD="$TMP/s2a"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": true}]"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision"'; then fail "first Stop on an ack must NOT block"; else pass "first Stop on an ack does not block"; fi
assert_eq "placeholder deleted (deleteMessage)" "1" "$(count deleteMessage)"
assert_eq "NO fallback send of the transcript text" "0" "$(count sendMessage)"
assert_eq "pending file gone" "0" "$(pend_count "$SD")"
stop_hook "$SD" true >/dev/null
assert_eq "second Stop: still no send" "0" "$(count sendMessage)"

echo "  -- controls: the same setup WITHOUT the ack flag still enforces"
SD="$TMP/s2b"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": false}]"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision": *"block"'; then pass "control: ack=false blocks the first Stop"; else fail "control: ack=false must block the first Stop"; fi
stop_hook "$SD" true >/dev/null
assert_eq "control: second Stop fallback-sends the transcript text" "1" "$(count sendMessage)"

SD="$TMP/s2c"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555}]"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision": *"block"'; then pass "control: a legacy entry (no ack key) is NOT an ack, still blocks"; else fail "control: legacy entry must keep the old enforcement"; fi

SD="$TMP/s2d"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": true}, {\"chat_id\": \"$CHAT\", \"message_id\": 556, \"src_mid\": \"78\", \"ack\": false}]"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision": *"block"'; then pass "mixed: the question still blocks"; else fail "mixed: the question must still block"; fi
assert_eq "mixed: only the ack placeholder was deleted" "1" "$(count deleteMessage)"
assert_eq "mixed: the question entry is kept" "1" "$(pend_count "$SD")"
assert_eq "mixed: and it is the question (src 78)" "78" "$(pend_field "$SD" 0 src_mid)"

# ---------------------------------------------------------------------------
echo ""
echo "(3) PostToolUse: a REACT answers an ack, and only an ack"
SD="$TMP/s3a"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": true}]"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"77\", \"emoji\": \"👍\"}"
assert_eq "react on the ack inbound deletes the placeholder" "1" "$(count deleteMessage)"
assert_eq "react on the ack inbound clears the pending file" "0" "$(pend_count "$SD")"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision"'; then fail "after the react the Stop must not block"; else pass "after the react the Stop does not block"; fi
assert_eq "after the react nothing is fallback-sent" "0" "$(count sendMessage)"

echo "  -- controls: a react on a QUESTION / DECISION is not an answer"
SD="$TMP/s3b"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": false}]"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"77\", \"emoji\": \"👍\"}"
assert_eq "react on a question deletes nothing" "0" "$(count deleteMessage)"
assert_eq "react on a question keeps the entry" "1" "$(pend_count "$SD")"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision": *"block"'; then pass "react on a question: the Stop STILL blocks"; else fail "react on a question must not lift the requirement"; fi

SD="$TMP/s3c"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": true}]"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"99\", \"emoji\": \"👍\"}"
assert_eq "react on a DIFFERENT message keeps the ack entry" "1" "$(pend_count "$SD")"
post_tool "$SD" "$REACT" "{\"chat_id\": \"999\", \"message_id\": \"77\", \"emoji\": \"👍\"}"
assert_eq "react in a DIFFERENT chat keeps the ack entry" "1" "$(pend_count "$SD")"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"emoji\": \"👍\"}"
assert_eq "react with no message_id keeps the entry" "1" "$(pend_count "$SD")"
assert_eq "none of those deleted anything" "0" "$(count deleteMessage)"

SD="$TMP/s3d"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\"}]"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"77\", \"emoji\": \"👍\"}"
assert_eq "react on a legacy entry (no ack key) keeps it" "1" "$(pend_count "$SD")"

echo "  -- regression: the reply tool still clears exactly as before"
SD="$TMP/s3e"; new_state "$SD"; reset_log
set_pend "$SD" "[{\"chat_id\": \"$CHAT\", \"message_id\": 555, \"src_mid\": \"77\", \"ack\": false}]"
post_tool "$SD" "$REPLY" "{\"chat_id\": \"$CHAT\", \"text\": \"valasz\"}"
assert_eq "reply tool deletes the placeholder" "1" "$(count deleteMessage)"
assert_eq "reply tool clears the pending file" "0" "$(pend_count "$SD")"

# ---------------------------------------------------------------------------
echo ""
echo "(4) End to end: submit -> react -> Stop"
# The closing case: an UNNUMBERED ack answered by a react ends the turn quietly.
SD="$TMP/s4"; new_state "$SD"; reset_log
submit "$SD" "$(channel 700 "köszi")"
assert_eq "e2e: placeholder posted" "1" "$(count sendMessage)"
post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"700\", \"emoji\": \"👍\"}"
OUT="$(stop_hook "$SD" false)"
if printf '%s' "$OUT" | grep -q '"decision"'; then fail "e2e: 'köszi' answered by a react must not block"; else pass "e2e: 'köszi' + react -> the turn ends"; fi
assert_eq "e2e: only the placeholder was ever sent (no fallback text)" "1" "$(count sendMessage)"
assert_eq "e2e: the placeholder was deleted" "1" "$(count deleteMessage)"

# The other direction, the worse one: a numbered short reply or a question is
# NEVER closed by a react. Each of these carries a real decision or question.
echo "  -- e2e controls: a react does NOT close a numbered reply or a question"
j=0
for text in "86. ok" "118 ok" "115 mehet" "118 jo?" "jó?" "ok?"; do
    j=$((j + 1))
    SD="$TMP/s5-$j"; new_state "$SD"; reset_log
    submit "$SD" "$(channel "71$j" "$text")"
    post_tool "$SD" "$REACT" "{\"chat_id\": \"$CHAT\", \"message_id\": \"71$j\", \"emoji\": \"👍\"}"
    assert_eq "e2e control '$text': the react deletes nothing" "0" "$(count deleteMessage)"
    OUT="$(stop_hook "$SD" false)"
    if printf '%s' "$OUT" | grep -q '"decision": *"block"'; then pass "e2e control '$text' + react: the Stop still blocks"; else fail "e2e control '$text': a real reply is owed, the Stop must block"; fi
done

echo ""
echo "==========================="
TOTAL=$((PASS + FAIL))
echo "Results: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then echo "FAILED: $FAIL tests"; exit 1; fi
echo "All tests passed."
