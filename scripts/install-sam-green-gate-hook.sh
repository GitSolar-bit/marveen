#!/usr/bin/env bash
# Idempotent installer (card ee1a22f1): pre-push gate "outgoing code needs a Sam-green trace".
# Auto-run by scripts/sync-hooks.sh on update, same as install-git-guard-hook.sh. The hook's
# contract, the trace format and the bypass are documented at the top of
# scripts/git-hooks/pre-push-sam-green.py and in docs/security-hardening.md.
#
# THIS HOOK GUARDS AGAINST FORGETTING, NOT AGAINST A DELIBERATE BYPASS: it is skipped by
# `git push --no-verify`, and its trace (a mailbox row from "sam") is self-declared.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# `rev-parse --git-common-dir` answers RELATIVE TO THE REPO (".git"); resolving it with a bare
# `cd` resolves it against the CALLER's cwd (measured on the sibling installers, see
# src/__tests__/hook-installer-cwd-independence.test.ts). Anchor it to $ROOT.
GIT_COMMON_DIR="$(git -C "$ROOT" rev-parse --git-common-dir)"
case "$GIT_COMMON_DIR" in /*) ;; *) GIT_COMMON_DIR="$ROOT/$GIT_COMMON_DIR" ;; esac
HOOK_DIR="$(cd "$GIT_COMMON_DIR" && pwd)/hooks"
DISPATCH="$HOOK_DIR/pre-push"
GUARD="$HOOK_DIR/pre-push.d/30-sam-green-gate"
SRC="$ROOT/scripts/git-hooks/pre-push-sam-green.py"
MARK="marveen-pre-push-dispatcher"

[ -f "$SRC" ] || { echo "install-sam-green-gate-hook: $SRC missing" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "install-sam-green-gate-hook: python3 not found, the gate cannot run -- NOT installed" >&2; exit 1; }

# The dispatcher is the git-guard installer's job; run it when it is not there yet, then verify.
if ! grep -q "$MARK" "$DISPATCH" 2>/dev/null; then
  bash "$ROOT/scripts/install-git-guard-hook.sh" >/dev/null
fi
grep -q "$MARK" "$DISPATCH" 2>/dev/null || { echo "install-sam-green-gate-hook: no pre-push dispatcher at $DISPATCH after install-git-guard-hook.sh -- the gate would never run" >&2; exit 1; }

mkdir -p "$HOOK_DIR/pre-push.d"
cp "$SRC" "$GUARD"
chmod +x "$GUARD"

# Record the member in pre-push.required: its name and the sha256 of the bytes just written. The
# dispatcher refuses to run if a listed member is missing or no longer matches, so this gate (the owner's
# rule: outgoing code only after Sam) cannot be removed or swapped for `exit 0` without a trace.
register_pre_push_member() {
  local name="$1" file="$2" sum
  sum="$( (sha256sum "$file" 2>/dev/null || shasum -a 256 "$file") | cut -d' ' -f1)"
  touch "$HOOK_DIR/pre-push.required"
  grep -v "^${name} " "$HOOK_DIR/pre-push.required" > "$HOOK_DIR/pre-push.required.tmp" 2>/dev/null || true
  printf '%s %s\n' "$name" "$sum" >> "$HOOK_DIR/pre-push.required.tmp"
  mv "$HOOK_DIR/pre-push.required.tmp" "$HOOK_DIR/pre-push.required"
}
register_pre_push_member "30-sam-green-gate" "$GUARD"

echo "✓ sam-green gate: outgoing code needs a SAM-ZOLD <sha> trace (guards against forgetting; bypass: SKIP_SAM_GREEN_GATE=1 + SAM_GREEN_SKIP_REASON, logged)."
