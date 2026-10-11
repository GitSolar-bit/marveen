#!/usr/bin/env python3
"""Test the pre-push Sam-green gate (scripts/git-hooks/pre-push-sam-green.py), card ee1a22f1.

Real git, real installer, real dispatcher: every case runs an actual `git push` from a throwaway
repo to a bare remote, with the hook installed by scripts/install-sam-green-gate-hook.sh. The
dashboard is a local stub (a thread serving /api/messages), so nothing here touches the live
mailbox, the live .git/hooks or the network. Run:
  python3 scripts/__tests__/pre-push-sam-green.test.py
Exit 0 = all pass; non-zero = a failure (message on stderr).

What this file guards above all, in the order the gate can go wrong:
  - the FAIL direction: a stub that cannot be reached, a missing token, a malformed answer must
    BLOCK, never pass;
  - the lookalikes that must NOT count as a trace: Sam's line with text after the hash, a sentence
    mentioning the token, a row from another sender, a failed row, a 7-digit prefix, a green for
    the OLD head after an amend;
  - what needs NO trace and must pass without even asking the dashboard (deletion, a commit that
    is already on the remote), proved by the stub's request counter.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
CLEAN_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
CLEAN_ENV.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                  "GIT_COMMITTER_EMAIL": "t@t"})
for _k in ("SKIP_SAM_GREEN_GATE", "SAM_GREEN_SKIP_REASON", "MARVEEN_API_BASE", "MARVEEN_WEB_PORT",
           "WEB_PORT", "MARVEEN_TOKEN_FILE", "SAM_GREEN_INSTALL_ROOT"):
    CLEAN_ENV.pop(_k, None)
# The gate applies to agent sessions only (Laci, 2026-10-11, 5b). The suite itself may run inside one,
# so the agent markers are removed here and the agent case is put back explicitly in setUp.
AGENT_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_EXECPATH")
for _k in AGENT_MARKERS:
    CLEAN_ENV.pop(_k, None)


class Stub:
    """Serves GET /api/messages. `rows` is the whole mailbox; the handler honours agent/limit/before."""

    def __init__(self):
        self.rows = []
        self.requests = []
        self.token_seen = []
        self.raw = None  # when set, answer with this body instead (malformed-answer case)
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                stub.requests.append(self.path)
                stub.token_seen.append(self.headers.get("Authorization"))
                if stub.raw is not None:
                    body = stub.raw.encode()
                else:
                    rows = [r for r in stub.rows if r["from_agent"] == "sam" or r["to_agent"] == "sam"]
                    rows.sort(key=lambda r: -r["id"])
                    if "before" in q:
                        rows = [r for r in rows if r["id"] < int(q["before"][0])]
                    body = json.dumps(rows[: int(q.get("limit", ["50"])[0])]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.next_id = 1

    def add(self, content, frm="sam", to="igor", status="done"):
        self.rows.append({"id": self.next_id, "from_agent": frm, "to_agent": to, "content": content, "status": status})
        self.next_id += 1

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def sh(*cmd, cwd=None, env=None, check=True):
    p = subprocess.run(cmd, cwd=cwd, env=env or CLEAN_ENV, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError("%s failed (%d): %s%s" % (" ".join(cmd), p.returncode, p.stdout, p.stderr))
    return p


class SamGreen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = Stub()
        cls.tmp = tempfile.mkdtemp(prefix="samgreen-")
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.stub.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        SamGreen.n += 1
        self.stub.rows.clear()
        self.stub.requests.clear()
        self.stub.next_id = 1
        base = os.path.join(self.tmp, "case%d" % SamGreen.n)
        self.repo = os.path.join(base, "repo")
        self.bare = os.path.join(base, "fork.git")
        self.upbare = os.path.join(base, "up.git")
        os.makedirs(os.path.join(self.repo, "scripts", "git-hooks"))
        os.makedirs(os.path.join(self.repo, "store"))
        sh("git", "init", "-q", "--bare", "-b", "develop", self.bare)
        sh("git", "init", "-q", "--bare", "-b", "develop", self.upbare)
        sh("git", "init", "-q", "-b", "develop", self.repo)
        for f in ("install-sam-green-gate-hook.sh", "install-git-guard-hook.sh"):
            shutil.copy(os.path.join(SCRIPTS, f), os.path.join(self.repo, "scripts", f))
        shutil.copy(os.path.join(SCRIPTS, "git-hooks", "pre-push-sam-green.py"),
                    os.path.join(self.repo, "scripts", "git-hooks", "pre-push-sam-green.py"))
        with open(os.path.join(self.repo, "store", ".dashboard-token"), "w") as fh:
            fh.write("test-token\n")
        sh("git", "remote", "add", "origin", self.upbare, cwd=self.repo)
        sh("git", "remote", "add", "fork", self.bare, cwd=self.repo)
        self.commit("base")
        # Setup pushes happen BEFORE the hook is installed (a setup push through the hook is itself gated).
        sh("git", "push", "-q", "origin", "develop", cwd=self.repo)
        sh("git", "push", "-q", "fork", "develop", cwd=self.repo)
        sh("git", "fetch", "-q", "origin", cwd=self.repo)
        sh("git", "fetch", "-q", "fork", cwd=self.repo)
        sh("bash", os.path.join(self.repo, "scripts", "install-sam-green-gate-hook.sh"), cwd=self.repo)
        # self.env is an AGENT push (CLAUDECODE set); self.laci_env is a hand push (no marker).
        self.laci_env = dict(CLEAN_ENV, MARVEEN_API_BASE="http://127.0.0.1:%d" % self.stub.port)
        self.env = dict(self.laci_env, CLAUDECODE="1")
        sh("git", "checkout", "-q", "-b", "feature", cwd=self.repo)

    def commit(self, msg):
        with open(os.path.join(self.repo, "f.txt"), "a") as fh:
            fh.write(msg + "\n")
        sh("git", "add", "f.txt", cwd=self.repo)
        sh("git", "commit", "-q", "-m", msg, cwd=self.repo)
        return self.head()

    def head(self):
        return sh("git", "rev-parse", "HEAD", cwd=self.repo).stdout.strip()

    def push(self, *args, env=None):
        return subprocess.run(["git", "push", "-q", *args], cwd=self.repo, env=env or self.env,
                              capture_output=True, text=True)

    def hook_path(self):
        return os.path.join(self.repo, ".git", "hooks", "pre-push.d", "30-sam-green-gate")

    # ---- the trace -------------------------------------------------------------------------

    def test_no_trace_blocks_and_names_what_is_needed(self):
        h = self.commit("a")
        p = self.push("fork", "feature")
        self.assertNotEqual(p.returncode, 0, p.stderr)
        self.assertIn("no Sam-green trace", p.stderr)
        self.assertIn("SAM-ZOLD " + h[:8], p.stderr)

    def test_trace_for_the_head_passes(self):
        h = self.commit("a")
        self.stub.add("Atnezve, rendben.\nSAM-ZOLD %s\nKartya: x" % h[:8])
        p = self.push("fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(h, sh("git", "ls-remote", self.bare, "refs/heads/feature").stdout)

    def test_full_40_digit_hash_and_uppercase_pass(self):
        h = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % h.upper())
        self.assertEqual(self.push("fork", "feature").returncode, 0)

    def test_green_for_the_old_head_does_not_cover_an_amended_head(self):
        old = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % old[:8])
        self.assertEqual(self.push("fork", "feature").returncode, 0)
        sh("git", "commit", "-q", "--amend", "-m", "a (amended)", cwd=self.repo)
        p = self.push("--force", "fork", "feature")
        self.assertNotEqual(p.returncode, 0, "a force-push of a NEW head must need a NEW green")
        self.assertIn("no Sam-green trace", p.stderr)

    def test_a_further_commit_on_the_pr_branch_needs_its_own_green(self):
        first = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % first[:8])
        self.assertEqual(self.push("fork", "feature").returncode, 0)
        self.commit("b")
        p = self.push("fork", "feature")
        self.assertNotEqual(p.returncode, 0)

    def test_lookalikes_do_not_count(self):
        h = self.commit("a")
        for text in (
            "SAM-ZOLD %s NEM" % h[:8],                      # text after the hash
            "SAM-ZOLD %s." % h[:8],                         # trailing punctuation
            "Ha zold lenne: SAM-ZOLD %s" % h[:8],           # not a line of its own
            "`SAM-ZOLD %s`" % h[:8],                        # wrapped
            "SAM-ZOLD %s" % h[:7],                          # prefix too short
            "SAM-NEM %s" % h[:8],                           # a refusal
            "SAM-ZOLD deadbeef",                            # another commit
        ):
            self.stub.rows.clear()
            self.stub.add(text)
            p = self.push("--dry-run", "fork", "feature")
            self.assertNotEqual(p.returncode, 0, "must NOT count as a trace: %r\n%s" % (text, p.stderr))

    def test_a_row_from_another_sender_or_a_failed_row_does_not_count(self):
        h = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % h[:8], frm="hex", to="sam")
        self.stub.add("SAM-ZOLD %s" % h[:8], frm="sam", status="failed")
        self.assertNotEqual(self.push("--dry-run", "fork", "feature").returncode, 0)

    def test_the_token_is_sent_and_never_printed(self):
        h = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % h[:8])
        p = self.push("fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Bearer test-token", self.stub.token_seen)
        self.assertNotIn("test-token", p.stderr + p.stdout)

    def test_a_green_older_than_one_page_is_found(self):
        h = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % h[:8])
        for i in range(250):
            self.stub.add("chatter %d" % i)
        p = self.push("fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertGreaterEqual(len(self.stub.requests), 2, "should have paged back")

    # ---- fail direction --------------------------------------------------------------------

    def test_dashboard_unreachable_blocks(self):
        self.commit("a")
        env = dict(self.env, MARVEEN_API_BASE="http://127.0.0.1:1")
        p = self.push("fork", "feature", env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot read Sam's messages", p.stderr)

    def test_missing_token_blocks(self):
        self.commit("a")
        os.remove(os.path.join(self.repo, "store", ".dashboard-token"))
        p = self.push("fork", "feature")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot read Sam's messages", p.stderr)

    def test_a_malformed_answer_blocks(self):
        self.commit("a")
        self.stub.raw = '{"error":"nope"}'
        try:
            p = self.push("fork", "feature")
        finally:
            self.stub.raw = None
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot read Sam's messages", p.stderr)

    def test_python_missing_from_the_hook_means_the_push_is_blocked_not_skipped(self):
        # the dispatcher turns a hook that cannot start into a failed push: shebang to nowhere
        self.commit("a")
        path = self.hook_path()
        with open(path) as fh:
            body = fh.read().replace("#!/usr/bin/env python3", "#!/nonexistent/python3", 1)
        with open(path, "w") as fh:
            fh.write(body)
        self.assertNotEqual(self.push("fork", "feature").returncode, 0)

    # ---- what needs no trace ---------------------------------------------------------------

    def test_branch_deletion_needs_no_trace_and_no_request(self):
        self.commit("a")
        self.stub.add("SAM-ZOLD %s" % self.head()[:8])
        self.assertEqual(self.push("fork", "feature").returncode, 0)
        self.stub.rows.clear()
        self.stub.requests.clear()
        p = self.push("fork", "--delete", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.stub.requests, [])

    def test_a_commit_the_remote_already_has_needs_no_trace_and_no_request(self):
        # pushing an existing commit to a second branch name sends no new code
        self.assertEqual(sh("git", "rev-parse", "develop", cwd=self.repo).stdout.strip(), self.head())
        p = self.push("fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.stub.requests, [])

    def test_an_upstream_commit_pushed_to_the_fork_needs_no_trace(self):
        # the fork lags: origin has a commit the fork does not; syncing it is not our code going out
        sh("git", "checkout", "-q", "develop", cwd=self.repo)
        h = self.commit("upstream work")
        sh("git", "push", "-q", "--no-verify", "origin", "develop", cwd=self.repo)
        sh("git", "fetch", "-q", "origin", cwd=self.repo)
        p = self.push("fork", "develop")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.stub.requests, [])
        self.assertIn(h, sh("git", "ls-remote", self.bare, "refs/heads/develop").stdout)

    def test_pushing_new_code_to_the_upstream_itself_still_needs_a_trace(self):
        self.commit("ours")
        p = self.push("origin", "feature")
        self.assertNotEqual(p.returncode, 0)

    # ---- who it applies to -----------------------------------------------------------------

    def test_a_hand_push_without_agent_markers_passes_with_no_trace_and_no_request(self):
        self.commit("a")
        for remote in ("fork", "origin"):
            p = self.push(remote, "feature", env=self.laci_env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("not a Claude Code agent session", p.stderr)
        self.assertEqual(self.stub.requests, [], "a non-agent push must not even ask the dashboard")

    def test_every_agent_marker_alone_makes_the_push_gated(self):
        for marker in AGENT_MARKERS:
            with self.subTest(marker=marker):
                self.commit("m-" + marker)
                p = self.push("fork", "feature", env=dict(self.laci_env, **{marker: "1"}))
                self.assertNotEqual(p.returncode, 0, p.stderr)
                self.assertIn("no Sam-green trace", p.stderr)

    def test_an_empty_marker_does_not_make_the_push_an_agent_push(self):
        self.commit("a")
        p = self.push("fork", "feature", env=dict(self.laci_env, CLAUDECODE=""))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_config_dir_alone_is_not_a_marker(self):
        # CLAUDE_CONFIG_DIR can be exported in a plain terminal to run `claude`; it must not gate a hand push.
        self.commit("a")
        p = self.push("fork", "feature", env=dict(self.laci_env, CLAUDE_CONFIG_DIR="/tmp/x"))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_documented_limit_an_agent_that_unsets_the_markers_walks_through(self):
        # NOT a feature: pins the stated limit (a "who typed it" guess, not an identity). If this ever
        # fails, update the docs too.
        self.commit("a")
        env = {k: v for k, v in self.env.items() if k not in AGENT_MARKERS}
        self.assertEqual(self.push("fork", "feature", env=env).returncode, 0)

    def test_a_green_agent_push_still_passes(self):
        h = self.commit("a")
        self.stub.add("SAM-ZOLD %s" % h[:12])
        p = self.push("fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)

    # ---- the bypass ------------------------------------------------------------------------

    def test_skip_without_a_reason_is_refused(self):
        self.commit("a")
        p = self.push("fork", "feature", env=dict(self.env, SKIP_SAM_GREEN_GATE="1"))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("needs SAM_GREEN_SKIP_REASON", p.stderr)

    def test_skip_with_a_reason_passes_and_is_recorded(self):
        h = self.commit("a")
        env = dict(self.env, SKIP_SAM_GREEN_GATE="1", SAM_GREEN_SKIP_REASON="Laci TG 9999: emergency hotfix")
        p = self.push("fork", "feature", env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(self.repo, "store", "push-samgreen-skips.log")) as fh:
            log = fh.read()
        self.assertIn("Laci TG 9999: emergency hotfix", log)
        self.assertIn(h, log)
        self.assertEqual(self.stub.requests, [], "a skip must not even ask the dashboard")

    def test_a_skip_that_cannot_be_recorded_is_refused(self):
        self.commit("a")
        os.symlink("/nonexistent-dir/x.log", os.path.join(self.repo, "store", "push-samgreen-skips.log"))
        env = dict(self.env, SKIP_SAM_GREEN_GATE="1", SAM_GREEN_SKIP_REASON="Laci TG 9999: emergency hotfix")
        p = self.push("fork", "feature", env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("unrecorded skip is refused", p.stderr)

    def test_documented_limit_no_verify_skips_the_gate(self):
        # NOT a feature: this pins the stated limit (the gate guards against forgetting) so nobody
        # later reads the gate as stronger than it is. If this ever fails, update the docs too.
        self.commit("a")
        p = self.push("--no-verify", "fork", "feature")
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
