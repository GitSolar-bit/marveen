#!/usr/bin/env bash
# Tests for wait-for.sh. The one that matters is SELF-MATCH: the watcher must
# not find its own command line. Without the guard that case never terminates,
# which is exactly what burned 242 minutes on 2026-09-23.
#
# Run:  bash scripts/__tests__/wait-for.test.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
W="${WAITFOR_SCRIPT:-$ROOT/scripts/wait-for.sh}"
# MUSZER-ONIGAZOLAS (HEX merte 2026-09-24): 2 of the 13 of these assertions PASS against a
# script that does not exist, because a no-op assertion is satisfied by nothing
# just as well as by correct silence. The suite cannot tell "correctly did
# nothing" from "was not there at all" -- so it must first prove its own target.
# Same principle as the positive control below, pointed the other way.
[ -x "$W" ] || { echo "FATAL: the script under test is missing or not executable: $W" >&2; exit 2; }

FAILS=0; N=0
ok() { N=$((N+1)); if [ "$2" = "0" ]; then echo "PASS  $1"; else echo "FAIL  $1${3:+  -- $3}"; FAILS=$((FAILS+1)); fi; }

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/waitfor.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT
MARK="waitfor-marker-$$-$RANDOM"

# --- 1. POSITIVE CONTROL: the naive pattern really does match itself. --------
# If this fails, every check below is vacuous: there would be no trap to avoid.
naive_rc=0
timeout 3 bash -c "until ! pgrep -f 'pgrep-self-probe-$MARK' >/dev/null 2>&1; do sleep 1; done" || naive_rc=$?
ok "positive control: naive 'until ! pgrep -f PAT' hangs on its own command line" \
   "$([ "$naive_rc" = "124" ] && echo 0 || echo 1)" "rc=$naive_rc (expected 124 = timeout)"

# --- 2. The same pattern through wait-for.sh must return at once. ------------
t0=$(date +%s); rc=0
timeout 20 bash "$W" pattern "pgrep-self-probe-$MARK" --interval 1 --quiet || rc=$?
ok "pattern mode does NOT match itself (returns instead of spinning)" \
   "$([ "$rc" = "0" ] && echo 0 || echo 1)" "rc=$rc"
ok "  ...and it returns fast (<5s)" \
   "$([ $(( $(date +%s) - t0 )) -lt 5 ] && echo 0 || echo 1)" "took $(( $(date +%s) - t0 ))s"

# --- 3. pattern mode on a REAL process: waits, then returns when it ends. ----
cat > "$SANDBOX/$MARK.sh" <<'JOB'
#!/usr/bin/env bash
sleep "${1:-3}"
JOB
chmod +x "$SANDBOX/$MARK.sh"
bash "$SANDBOX/$MARK.sh" 2 &
job_pid=$!
t0=$(date +%s); rc=0
timeout 20 bash "$W" pattern "$MARK.sh" --interval 1 --quiet || rc=$?
el=$(( $(date +%s) - t0 ))
ok "pattern mode waits for a real matching process" \
   "$([ "$rc" = "0" ] && [ "$el" -ge 1 ] && echo 0 || echo 1)" "rc=$rc elapsed=${el}s (expected >=1s)"
wait "$job_pid" 2>/dev/null

# --- 4. pid mode ------------------------------------------------------------
sleep 2 & sp=$!
t0=$(date +%s); rc=0
timeout 20 bash "$W" pid "$sp" --interval 1 --quiet || rc=$?
el=$(( $(date +%s) - t0 ))
ok "pid mode waits for the pid to exit" \
   "$([ "$rc" = "0" ] && [ "$el" -ge 1 ] && echo 0 || echo 1)" "rc=$rc elapsed=${el}s"
rc=0; timeout 10 bash "$W" pid 999999999 --interval 1 --quiet || rc=$?
ok "pid mode returns at once for a pid that is already gone" "$([ "$rc" = "0" ] && echo 0 || echo 1)" "rc=$rc"

# --- 5. file / gone modes ---------------------------------------------------
( sleep 1; : > "$SANDBOX/out.txt" ) &
rc=0; timeout 20 bash "$W" file "$SANDBOX/out.txt" --interval 1 --quiet || rc=$?
ok "file mode waits for the file to appear" "$([ "$rc" = "0" ] && echo 0 || echo 1)" "rc=$rc"
( sleep 1; rm -f "$SANDBOX/out.txt" ) &
rc=0; timeout 20 bash "$W" gone "$SANDBOX/out.txt" --interval 1 --quiet || rc=$?
ok "gone mode waits for the file to disappear" "$([ "$rc" = "0" ] && echo 0 || echo 1)" "rc=$rc"

# --- 6. timeout is a reported, non-zero RESULT ------------------------------
rc=0
err="$(timeout 20 bash "$W" file "$SANDBOX/never-appears" --timeout 2 --interval 1 2>&1 >/dev/null)" || rc=$?
ok "timeout exits 1 (so a && chain stops)" "$([ "$rc" = "1" ] && echo 0 || echo 1)" "rc=$rc"
ok "timeout says so on stderr" \
   "$(printf '%s' "$err" | grep -q 'TIMEOUT' && echo 0 || echo 1)" "stderr: $err"

# --- 7. the watcher must be SILENT on stderr -------------------------------
# Not cosmetics: the two noises this caught were a broken ancestor walk
# (`[: S: integer expected` -- /proc/<pid>/stat field 4 is not PPid when `comm`
# contains a space) and an unreadable /proc/<pid>/cmdline for a pid that exited
# between pgrep and the read. The first one silently disabled half the
# self-exclusion while every check above still passed.
( sleep 2; : ) &
noise_job=$!
noise="$(timeout 20 bash "$W" pattern "waitfor-silence-probe-$MARK" --interval 1 2>&1 >/dev/null)"
ok "pattern mode writes nothing to stderr" \
   "$([ -z "$noise" ] && echo 0 || echo 1)" "stderr: $noise"
wait "$noise_job" 2>/dev/null

# --- 8. usage errors --------------------------------------------------------
rc=0; bash "$W" >/dev/null 2>&1 || rc=$?
ok "no arguments -> usage, exit 2" "$([ "$rc" = "2" ] && echo 0 || echo 1)" "rc=$rc"
rc=0; bash "$W" pid notanumber >/dev/null 2>&1 || rc=$?
ok "non-numeric pid -> exit 2" "$([ "$rc" = "2" ] && echo 0 || echo 1)" "rc=$rc"

echo
echo "$((N-FAILS))/$N passed"
[ "$FAILS" = "0" ] || exit 1
