#!/usr/bin/env bash
# Wait for a background job to finish, without the watcher finding ITSELF.
#
# Why this exists: on 2026-09-23 three `until ... pgrep -f 'build-images.py'`
# loops of mine spun for 242 MINUTES while the build had been finished since
# 13:43. `pgrep -f` matched the watcher's own command line -- the pattern is in
# it -- so the condition could never become false. A watcher that finds itself
# is not a watcher, it is an infinite loop. The lesson was written into a
# handoff the same day and went off again in the same session, because a
# handoff is read at the START of a session and this mistake happens in the
# MIDDLE of one. So the guard goes where the command is typed.
#
# Modes, BEST FIRST -- use the first one that fits:
#   scripts/wait-for.sh pid <PID>...        wait until the process(es) exit.   BEST:
#                                   no pattern, so nothing to match wrongly.
#   scripts/wait-for.sh file <PATH>...      wait until every path EXISTS.      GOOD:
#                                   looks at the result, not at a process.
#   scripts/wait-for.sh gone <PATH>...      wait until every path is GONE (lockfile).
#   scripts/wait-for.sh port <PORT>...      wait until something LISTENS there.
#   scripts/wait-for.sh pattern <PAT>...    wait until no process matches.     LAST
#                                   RESORT: this is the trap, and the only
#                                   mode that has to defend against it.
#
# Options:  --timeout SEC (default 1800)   --interval SEC (default 5)   --quiet
#
# Exit: 0 = the condition came true.  1 = timed out.  2 = usage error.
# Timing out is a RESULT, not a crash: it is reported and it is non-zero, so a
# `&&` chain stops instead of continuing on a job that never finished.
set -u

TIMEOUT=1800
INTERVAL=5
QUIET=0

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

[ $# -ge 1 ] || usage
MODE="$1"; shift

ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --timeout)  TIMEOUT="${2:-}"; shift 2 || usage ;;
        --interval) INTERVAL="${2:-}"; shift 2 || usage ;;
        --quiet)    QUIET=1; shift ;;
        --help|-h)  usage ;;
        --*)        echo "unknown option: $1" >&2; exit 2 ;;
        *)          ARGS+=("$1"); shift ;;
    esac
done
[ "${#ARGS[@]}" -ge 1 ] || usage
case "$TIMEOUT"  in ''|*[!0-9]*) echo "--timeout needs whole seconds" >&2;  exit 2 ;; esac
case "$INTERVAL" in ''|*[!0-9]*) echo "--interval needs whole seconds" >&2; exit 2 ;; esac
[ "$INTERVAL" -ge 1 ] || INTERVAL=1

say() { [ "$QUIET" = "1" ] || printf '%s\n' "$*"; }

# --- self-exclusion, the whole point of the pattern mode -------------------
# Every pid from here to init, so neither this script nor the shell that
# launched it can ever be counted as "the job we are waiting for".
own_chain() {
    local p=$$ guard=0
    # PPid from /proc/<pid>/status, NOT field 4 of /proc/<pid>/stat: `comm` there
    # is unquoted and may contain spaces, which shifts every later field. Measured
    # 2026-09-24 -- field 4 came back as "S" (the state) and the whole ancestor
    # walk died on `[: S: integer expected`, leaving only the name filter below.
    while [ "$p" -gt 1 ] && [ "$guard" -lt 64 ]; do
        printf '%s\n' "$p"
        p="$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null)"
        case "${p:-}" in ''|*[!0-9]*) break ;; esac
        guard=$((guard+1))
    done
}

# Processes matching the pattern, MINUS our own chain, minus any process whose
# command line runs this script (a second wait-for.sh watching the same thing
# is not the job either).
matching_pids() {
    local pat="$1" self_name pid cmdline
    self_name="$(basename "$0")"
    local -a own=()
    mapfile -t own < <(own_chain)
    for pid in $(pgrep -f -- "$pat" 2>/dev/null); do
        local skip=0 o
        for o in "${own[@]}"; do [ "$pid" = "$o" ] && skip=1 && break; done
        [ "$skip" = "1" ] && continue
        # The pid can exit between pgrep and this read. The redirection failure is
        # raised by the SHELL, so a 2>/dev/null on `tr` does not silence it --
        # check readability first, or the watcher prints noise on every tick.
        [ -r "/proc/$pid/cmdline" ] || continue
        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" || continue
        [ -n "$cmdline" ] || continue                  # kernel thread: no cmdline
        case "$cmdline" in *"$self_name"*) continue ;; esac
        printf '%s\n' "$pid"
    done
}

# --- one evaluation of the condition; 0 = satisfied ------------------------
condition_met() {
    local a
    case "$MODE" in
        pid)
            for a in "${ARGS[@]}"; do kill -0 "$a" 2>/dev/null && return 1; done
            return 0 ;;
        file)
            for a in "${ARGS[@]}"; do [ -e "$a" ] || return 1; done
            return 0 ;;
        gone)
            for a in "${ARGS[@]}"; do [ -e "$a" ] && return 1; done
            return 0 ;;
        port)
            for a in "${ARGS[@]}"; do
                ss -lntH 2>/dev/null | awk -v p=":${a}" '$4 ~ p"$" {f=1} END{exit !f}' || return 1
            done
            return 0 ;;
        pattern)
            for a in "${ARGS[@]}"; do [ -n "$(matching_pids "$a")" ] && return 1; done
            return 0 ;;
        *) echo "unknown mode: $MODE" >&2; exit 2 ;;
    esac
}

case "$MODE" in
    pid) for a in "${ARGS[@]}"; do
             case "$a" in ''|*[!0-9]*) echo "not a pid: $a" >&2; exit 2 ;; esac
         done ;;
    port) for a in "${ARGS[@]}"; do
             case "$a" in ''|*[!0-9]*) echo "not a port: $a" >&2; exit 2 ;; esac
          done ;;
esac

start=$(date +%s)
say "waiting: $MODE ${ARGS[*]}  (timeout ${TIMEOUT}s, checking every ${INTERVAL}s)"
while :; do
    if condition_met; then
        say "done after $(( $(date +%s) - start ))s: $MODE ${ARGS[*]}"
        exit 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$TIMEOUT" ]; then
        echo "TIMEOUT after ${TIMEOUT}s, condition still unmet: $MODE ${ARGS[*]}" >&2
        [ "$MODE" = "pattern" ] && echo "  still matching: $(for a in "${ARGS[@]}"; do matching_pids "$a" | tr '\n' ' '; done)" >&2
        exit 1
    fi
    sleep "$INTERVAL"
done
