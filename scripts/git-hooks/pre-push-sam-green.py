#!/usr/bin/env python3
"""pre-push gate: outgoing code needs a Sam-green trace for the exact head being pushed.

Card ee1a22f1 (parent 548bb2a4). Laci's rule, 2026-09-30 (Telegram 2603, restated 2026-10-11):
"code that goes outward (push, force-push, updating a PR branch) only after Sam's approval;
a green test is not enough". The rule lived in two CLAUDE.md files and nothing enforced it.

WHAT THIS GATE IS FOR. It guards against FORGETTING the rule. It is NOT evidence that Sam
reviewed anything, and it does not stop a deliberate bypass. Three reasons, all measured or
read from the code, stated here so nobody reads this as stronger than it is:
  1. The trace is self-declared. The mailbox is written through one shared bearer token, so
     any agent can create a row with from_agent="sam". The gate checks that the row exists,
     not who typed it.
  2. `git push --no-verify` and `git -c core.hooksPath=/dev/null push` skip EVERY pre-push
     hook, this one included, and leave no line anywhere.
  3. SKIP_SAM_GREEN_GATE=1 (below) is an override by design.

WHO IT APPLIES TO (Laci's decision 2026-10-11, Telegram 4034, option 5b): AGENT sessions only. A
push that does not come from a Claude Code session goes through without a trace, so Laci's own
hand push is free. "Comes from an agent session" = at least one of the markers in AGENT_MARKERS
is set and non-empty in the environment of the push. Claude Code sets them for every process its
Bash tool starts, and git hands that environment on to the hook. Measured on this install
(2026-10-11, from the agent's own shell): CLAUDECODE, CLAUDE_CODE_ENTRYPOINT,
CLAUDE_CODE_SESSION_ID and CLAUDE_CODE_EXECPATH were all set.
Limits, stated so nobody reads this as a boundary:
  - It is a "who typed it" guess from the environment, not an identity. An agent that unsets the
    markers (`env -u CLAUDECODE -u ... <the push>`) or pushes from a process that is not a Claude
    Code child walks through, silently. Same class as `--no-verify`: the gate guards against
    FORGETTING, not against a deliberate bypass.
  - The opposite error is a push Laci types INSIDE a Claude Code session (the `!` prefix): the
    markers are set, so it counts as an agent push and is gated. His way through is the logged
    skip below.
  - A non-agent pass leaves no trace anywhere except one stderr line.
  - CLAUDE_CONFIG_DIR is NOT a marker: it can be exported in a plain terminal to run `claude`.

WHAT COUNTS AS A TRACE (designed here, not by Sam, on purpose: Sam asked that he not define
the criterion he is then measured by). A message in the fleet mailbox that
  - has from_agent == "sam" and a status other than "failed", and
  - carries a LINE that is exactly:   SAM-ZOLD <hex>
    where <hex> is 8 to 40 hex digits and a prefix of the commit being pushed.
Why this shape:
  - Bound to the commit SHA, so a PR-branch update (a new head) needs a new Sam-green. A
    green for the old head says nothing about the new one.
  - A line of its own, nothing after the hash: "SAM-ZOLD abc12345 NEM" or a sentence that
    merely mentions the token must not pass. Strictness here costs Sam one extra line.
  - Mailbox, not a kanban comment: it is one endpoint (`/api/messages?agent=sam`) that does
    not need a card id, and it is where Sam reports back to the requester anyway.
Sam's own card comment stays the human-readable verdict; this line is the machine-readable one.

WHAT NEEDS NO TRACE. A push that sends no commit the destination lacks: a deletion, a ref that
already exists on the target remote's tracking refs, and (when the destination is not the
upstream) a commit that is already on the upstream. Same exclusion logic as 20-outgoing-identity
(v4), including its stated limit: tracking refs can be stale.

FAIL DIRECTION. Anything that cannot be verified (dashboard down, token unreadable, a ref that
does not resolve, git failing) BLOCKS. The bypass below is the way through, and it is logged.

BYPASS, ONLY ON LACI'S EXPLICIT INSTRUCTION FOR THAT PUSH:
  SKIP_SAM_GREEN_GATE=1 SAM_GREEN_SKIP_REASON="Laci TG <message id>: <why>" git push ...
The reason is mandatory and the call is recorded in <install>/store/push-samgreen-skips.log
(who, when, remote, refs, reason). If the line cannot be written the push is refused: an
override nothing records is the hole.

Env (same names as scripts/agent-msg.sh):
  MARVEEN_API_BASE    full base URL (overrides host+port)
  MARVEEN_WEB_PORT    dashboard port (then WEB_PORT in the env, then in <install>/.env, then 3420)
  MARVEEN_TOKEN_FILE  bearer token file (default <install>/store/.dashboard-token)
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

ZERO = "0" * 40
UPSTREAM = "origin"
# Set by Claude Code for every process its Bash tool starts (see "WHO IT APPLIES TO").
AGENT_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_EXECPATH")
TRACE_RE = re.compile(r"^[ \t]*SAM-ZOLD[ \t]+([0-9a-fA-F]{8,40})[ \t]*$", re.MULTILINE)
PAGE = 200
MAX_PAGES = 10  # 2000 of Sam's messages back; a green older than that is asked for again
MIN_REASON = 8

# <install>/.git/hooks/pre-push.d/<this file>  ->  <install>
INSTALL = Path(os.environ.get("SAM_GREEN_INSTALL_ROOT") or Path(__file__).resolve().parents[3])
STORE = INSTALL / "store"
SKIPLOG = STORE / "push-samgreen-skips.log"


def agent_session():
    return any(os.environ.get(k) for k in AGENT_MARKERS)


def git(*args):
    """Run git, return (rc, stdout). stderr is folded into stdout on failure for the message."""
    p = subprocess.run(["git", *args], capture_output=True, text=True)
    return p.returncode, (p.stdout if p.returncode == 0 else (p.stdout + p.stderr))


def api_base():
    base = os.environ.get("MARVEEN_API_BASE")
    if base:
        return base.rstrip("/")
    port = os.environ.get("MARVEEN_WEB_PORT") or os.environ.get("WEB_PORT")
    if not port:
        try:
            for line in (INSTALL / ".env").read_text().splitlines():
                if line.startswith("WEB_PORT="):
                    port = line.split("=", 1)[1].strip().strip("\"'")
                    break
        except OSError:
            pass
    return "http://localhost:%s" % (port or "3420")


def sam_green_hashes():
    """Every hash Sam has greened, newest first. Raises on anything that is not a clean answer."""
    token_file = Path(os.environ.get("MARVEEN_TOKEN_FILE") or STORE / ".dashboard-token")
    token = token_file.read_text().strip()
    if not token:
        raise RuntimeError("token file %s is empty" % token_file)
    base = api_base()
    seen = []
    before = None
    for _ in range(MAX_PAGES):
        url = "%s/api/messages?agent=sam&limit=%d" % (base, PAGE)
        if before is not None:
            url += "&before=%d" % before
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=10) as resp:
            rows = json.loads(resp.read().decode("utf-8"))
        if not isinstance(rows, list):
            raise RuntimeError("the mailbox answered with %s, not a list" % type(rows).__name__)
        for m in rows:
            if m.get("from_agent") != "sam" or m.get("status") == "failed":
                continue
            for h in TRACE_RE.findall(m.get("content") or ""):
                seen.append(h.lower())
        ids = [m["id"] for m in rows if isinstance(m.get("id"), int)]
        if len(rows) < PAGE or not ids:
            break
        before = min(ids)
    return seen


def record_skip(remote, url, payload, reason):
    try:
        STORE.mkdir(parents=True, exist_ok=True)
        with open(SKIPLOG, "a", encoding="utf-8") as fh:
            parent = ""
            try:
                parent = subprocess.run(["ps", "-o", "args=", "-p", str(os.getppid())],
                                        capture_output=True, text=True).stdout.strip()
            except OSError:
                pass
            fh.write("%s\tuser=%s\tcwd=%s\tremote=%s\turl=%s\treason=%s\tparent=%s\n" % (
                datetime.now().astimezone().strftime("%F %T%z"), os.environ.get("USER", "?"), os.getcwd(),
                remote, url, reason.replace("\t", " ").replace("\n", " "), parent.replace("\t", " ")))
            for ln in payload.splitlines():
                fh.write("\tref\t%s\n" % ln)
        return True
    except OSError:
        return False


def exclusions(remote, url):
    """The --not operands that say what the destination already has (see 20-outgoing-identity v4)."""
    excl = []
    rc, remotes = git("remote")
    names = remotes.split() if rc == 0 else []
    if remote and remote in names:
        rc, fetch_urls = git("remote", "get-url", "--all", remote)
        if rc == 0 and url and fetch_urls.strip() == url:
            excl.append("--remotes=" + remote)
    if remote != UPSTREAM and UPSTREAM in names:
        _, a = git("remote", "get-url", "--all", UPSTREAM)
        _, b = git("remote", "get-url", "--push", "--all", UPSTREAM)
        if url not in (a + "\n" + b).splitlines():
            excl.append("--remotes=" + UPSTREAM)
    return excl


def main():
    remote = sys.argv[1] if len(sys.argv) > 1 else ""
    url = sys.argv[2] if len(sys.argv) > 2 else ""
    payload = sys.stdin.read()

    if not agent_session():
        sys.stderr.write("pre-push: not a Claude Code agent session (none of %s is set) -- Sam-green is NOT "
                         "checked (Laci's own push, card ee1a22f1).\n" % ", ".join(AGENT_MARKERS))
        return 0

    if os.environ.get("SKIP_SAM_GREEN_GATE") == "1":
        reason = (os.environ.get("SAM_GREEN_SKIP_REASON") or "").strip()
        if len(reason) < MIN_REASON:
            sys.stderr.write("pre-push BLOCKED (sam-green): SKIP_SAM_GREEN_GATE=1 needs SAM_GREEN_SKIP_REASON"
                             "=\"Laci TG <id>: <why>\" (at least %d characters). A skip with no reason is refused.\n" % MIN_REASON)
            return 1
        sys.stderr.write("pre-push: SKIP_SAM_GREEN_GATE=1 -- Sam-green is NOT checked.\n")
        if not record_skip(remote, url, payload, reason):
            sys.stderr.write("pre-push BLOCKED (sam-green): the skip could not be recorded in %s, and an "
                             "unrecorded skip is refused.\n" % SKIPLOG)
            return 1
        sys.stderr.write("pre-push: skip recorded in %s.\n" % SKIPLOG)
        return 0

    excl = None  # computed once, only if a ref needs it
    greens = None  # fetched once, only if a ref needs it
    fail = 0

    for line in payload.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts[:4]
        if local_sha == ZERO:
            continue  # deletion: nothing is sent

        rc, out = git("rev-parse", "-q", "--verify", local_sha + "^{commit}")
        if rc != 0:
            sys.stderr.write("pre-push BLOCKED (sam-green): cannot verify %s (the ref does not resolve to a "
                             "commit). A push that cannot be checked is refused.\n" % local_ref)
            fail = 1
            continue
        commit = out.strip()

        if excl is None:
            excl = exclusions(remote, url)
        not_ops = list(excl)
        if remote_sha != ZERO:
            rc, _ = git("cat-file", "-e", remote_sha + "^{commit}")
            if rc == 0:
                not_ops.append(remote_sha)
        rc, out = git("rev-list", "-n", "1", commit, "--not", *not_ops)
        if rc != 0:
            sys.stderr.write("pre-push BLOCKED (sam-green): cannot verify %s (git rev-list failed: %s). A push "
                             "that cannot be checked is refused.\n" % (local_ref, out.strip().splitlines()[0] if out.strip() else "?"))
            fail = 1
            continue
        if not out.strip():
            continue  # no commit the destination lacks

        if greens is None:
            try:
                greens = sam_green_hashes()
            except (OSError, ValueError, RuntimeError, urllib.error.URLError) as e:
                sys.stderr.write("pre-push BLOCKED (sam-green): cannot read Sam's messages from the dashboard "
                                 "(%s: %s). A push that cannot be checked is refused.\n" % (type(e).__name__, e))
                fail = 1
                greens = []
                continue
        if any(commit.startswith(h) for h in greens):
            continue
        short = commit[:12]
        sys.stderr.write(
            "pre-push BLOCKED (sam-green): %s -> %s (head %s) has no Sam-green trace.\n"
            "  Needed: a message FROM sam in the fleet mailbox with a line of its own, exactly:\n"
            "      SAM-ZOLD %s\n"
            "  Ask Sam to review %s; he sends that line when it is green. A new head (amend, rebase, a further\n"
            "  commit on the PR branch) needs a new line.\n" % (local_ref, remote_ref, short, commit[:8], short))
        fail = 1

    if fail:
        sys.stderr.write(
            "  This gate guards against FORGETTING Laci's rule (2026-09-30, Telegram 2603); it is not proof of review.\n"
            "  Only on Laci's explicit instruction for this push:\n"
            "      SKIP_SAM_GREEN_GATE=1 SAM_GREEN_SKIP_REASON=\"Laci TG <id>: <why>\" git push ...\n"
            "  (recorded in store/push-samgreen-skips.log).\n")
    return fail


if __name__ == "__main__":
    sys.exit(main())
