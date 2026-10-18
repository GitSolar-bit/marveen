#!/usr/bin/env python3
"""ff9a0528: the destructive gate must not let a git config key/value or git program-valued environment variable through, when git
would RUN the value as a program.

The class (Sam 4155, HEX 4160): `git -c core.fsmonitor='touch /tmp/x' status` was rc 0 on the live gate, and so were core.pager,
core.editor, core.sshCommand, diff.external, sequence.editor, an `alias.x=!prog`, a `credential.helper=!prog`, `--config-env`, and
a persistent `git config core.pager 'prog'`. The rule is an INVERTED PROOF: a config key given to git on the command line or
written with `git config` is silent only when it is on the closed list of keys that run no program, or it is a credential helper
with an empty value / exactly the fork-push recipe. GIT_EDITOR / GIT_SEQUENCE_EDITOR / GIT_PAGER / GIT_ASKPASS keep their place on
the environment allowlist, but their VALUE must be a no-op program.

Sections:
  1. spellings that must BLOCK
  2. forms that must PASS (the normal workflow)
  3. DIFFERENTIAL against the real git: a probe program is handed to git in a sandbox repo through each key/variable; every one that
     really RUNS the probe must be blocked by the gate, and every key on the inert list must NOT run it
  4. blanked (quoted, with a space) values are read from the raw command

Run: python3 <this file>   Exit 0 = all green.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
GATE = os.environ.get("GITCFG_GATE") or os.path.join(ROOT, "scripts", "hooks", "destructive-gate.py")   # the env var: mutation runs

for _n in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "MARVEEN_PROD_ROOT", "SKIP_SECRET_GATE", "PATH"):
    os.environ.setdefault(_n, "1")
spec = importlib.util.spec_from_file_location("dgate", GATE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class Blocked(Exception):
    pass


def _raise(msg):
    raise Blocked(msg)


gate.block = _raise
failed = []


def check(name, ok):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    if not ok:
        failed.append(name)


def blocks(cmd):
    try:
        gate.check_bash(cmd, cwd="/tmp")
        return False
    except Blocked:
        return True


# ---------------------------------------------------------------------------------------------------------------------
print("1. BLOCK -- a config key/value or environment variable that runs a program")
PROG_KEYS = ["core.fsmonitor", "core.pager", "core.editor", "core.sshCommand", "core.askPass", "sequence.editor", "diff.external",
             "alias.x", "pager.log", "gpg.program", "credential.helper", "core.gitProxy", "http.proxy", "core.hooksPath",
             "include.path", "diff.tool", "merge.tool", "difftool.x.cmd", "mergetool.x.cmd", "filter.x.clean", "merge.x.driver",
             "web.browser", "browser.x.cmd", "ssh.variant", "gpg.ssh.program", "sendemail.smtpServer", "protocol.ext.allow"]
for k in PROG_KEYS:
    for sub in ("status", "log"):
        check("git -c %s='touch /tmp/p' %s" % (k, sub), blocks("git -c %s='touch /tmp/p' %s" % (k, sub)))
    check("glued -c%s=x" % k, blocks("git -c%s=x status" % k))
    check("--config-env=%s=V" % k, blocks("git --config-env=%s=V status" % k))
    check("config write %s" % k, blocks("git config %s 'touch /tmp/p'" % k))
    check("config --global write %s" % k, blocks("git config --global %s 'touch /tmp/p'" % k))
    check("config set %s" % k, blocks("git config set %s 'touch /tmp/p'" % k))
for cmd in [
    "git -c core.fsmonitor=x -c user.name=a status",                       # the bad one is not the first
    "git -c user.name=a -c core.pager=x log",                              # ... nor the last
    "git -C /tmp/r -c core.fsmonitor=x status",                            # after -C
    "git --no-pager -c core.pager=x log",                                  # after a flag
    "git -c 'core.fsmonitor=touch /tmp/p' status",                         # the whole pair quoted
    'git -c "core.fsmonitor=touch /tmp/p" status',
    "git -c core.fsmonitor=$P status",                                     # the value is an expansion
    "git -c $K=x status",                                                  # the key is an expansion
    "git -c credential.helper='!sh -c id' ls-remote origin",
    "H='!gh auth git-credential'; git -c credential.helper=\"$H\" fetch origin",      # a variable is not read: name the recipe in the command
    "git -c credential.helper='store' ls-remote origin",
    "git -c credential.helper=cache fetch origin",
    "git -c 'credential.https://github.com.helper=!sh -c id' fetch origin",
    "git --config-env credential.helper=H fetch origin",
    "git --exec-path=/tmp/x status",
    "git config --edit",
    "git config -e",
    "git config --global --edit",
    "git config --add core.pager 'sh -c id'",
    "git config --replace-all core.editor vim",
    "git -c core.editor=vim commit",
    "GIT_EDITOR='sh -c id' git commit",
    "GIT_EDITOR=vim git commit",
    "GIT_SEQUENCE_EDITOR='sh -c id' git rebase -i HEAD~2",
    "GIT_PAGER='sh -c id' git log",
    "GIT_ASKPASS=/tmp/ask git fetch origin",
    "GIT_ASKPASS=$ASK git fetch origin",
    "export GIT_EDITOR='sh -c id'; git commit",
    "export GIT_EDITOR=vim && git commit",
    "env GIT_PAGER=less git log",
    "GIT_EDITOR=vim; git commit",
    "git commit -m x && git -c core.pager=x log",
    "echo a | git -c core.fsmonitor=x status",
    "xargs git -c core.fsmonitor=x status",
    "bash -c 'git -c core.fsmonitor=x status'",
    "x=$(git -c core.fsmonitor=x status)",
    "( git -c core.fsmonitor=x status )",
    "time git -c core.fsmonitor=x status",
    "env git -c core.fsmonitor=x status",
    "command git -c core.fsmonitor=x status",
]:
    check(cmd, blocks(cmd))

# ---------------------------------------------------------------------------------------------------------------------
print("2. PASS -- the normal workflow")
for cmd in [
    "git status",
    "git -c user.name=a -c user.email=b@c.d commit -m x",
    "git -c 'user.name=A B' -c user.email=b@c.d commit -m x",
    'git -c "user.name=A B" commit -m x',
    "git -c credential.helper= -c credential.helper='!gh auth git-credential' push fork HEAD:refs/heads/x",
    "git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push fork HEAD:refs/heads/x",
    "git -c credential.helper= fetch origin",
    "git -c color.ui=always status",
    "git -c advice.detachedHead=false checkout --detach HEAD",
    "git -c commit.gpgsign=false log -1",
    "git -c core.quotepath=false diff --stat",
    "git -c protocol.file.allow=always clone /tmp/a /tmp/b",
    "git -c init.defaultBranch=main init /tmp/r",
    "git -c safe.directory=/tmp/r status",
    "git -c pull.rebase=false fetch origin",
    "git -c credential.useHttpPath=true fetch origin",
    "git -c",                                                  # nothing follows: sets nothing
    "git config user.name",
    "git -c core.fsmonitor status",                            # `-c KEY` without `=` is the boolean true: no value, nothing to run
    "git config --get core.pager",
    "git config --get-regexp 'alias.*'",
    "git config --list",
    "git config -l",
    "git config get user.name",
    "git config list",
    "git config --unset core.fsmonitor",
    "git config --unset-all core.pager",
    "git config unset core.pager",
    "git config user.name 'A B'",
    "git config --global user.email b@c.d",
    "git config --local color.ui auto",
    "git config set user.name a",
    "git config --file /tmp/x.cfg --get user.name",
    "git commit -c abc123",                                    # the subcommand's own -c
    "git log -c",
    "git show -c HEAD",
    "git diff -c",
    "GIT_EDITOR=true git rebase --continue",
    "GIT_SEQUENCE_EDITOR=true git rebase -i HEAD~2",
    "GIT_EDITOR=: git commit --amend",
    "GIT_EDITOR=cat git commit",
    "GIT_TERMINAL_PROMPT=0 git fetch origin",
    "export GIT_EDITOR=true; git commit",
    "env GIT_EDITOR=true git commit",
    "GIT_AUTHOR_NAME=a GIT_COMMITTER_NAME=a git commit -m x",
    "echo GIT_EDITOR=vim",
    "echo 'set GIT_EDITOR=vim to edit'",
    "printf '%s\\n' 'GIT_PAGER=less'",
    "bash -c 'echo hi'",
    "ls -c",
    "tar -c -f /tmp/a.tar /tmp/b",
    "git -C /tmp/r log --oneline -3",
    "git --no-pager log -3",
]:
    check(cmd, not blocks(cmd))

# ---------------------------------------------------------------------------------------------------------------------
print("3. DIFFERENTIAL against the real git")
git = shutil.which("git")
sandbox = tempfile.mkdtemp(prefix="gitcfg-")
marker = os.path.join(sandbox, "RAN")
probe = os.path.join(sandbox, "probe.sh")
with open(probe, "w") as fh:
    fh.write("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
os.chmod(probe, 0o755)
repo = os.path.join(sandbox, "repo")
env = {"PATH": os.environ["PATH"], "HOME": sandbox, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def run(args, extra=None, input_text=None):
    e = dict(env)
    e.update(extra or {})
    return subprocess.run(args, cwd=repo, env=e, input=input_text, capture_output=True, text=True, timeout=30)


def ran(args, extra=None, input_text=None, tty=False):
    if os.path.exists(marker):
        os.remove(marker)
    if tty:                                  # a pager only starts when stdout is a terminal
        import pty
        master, slave = pty.openpty()
        e = dict(env)
        e.update(extra or {})
        proc = subprocess.Popen(args, cwd=repo, env=e, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        try:
            proc.wait(timeout=30)
        finally:
            os.close(master)
    else:
        run(args, extra, input_text)
    return os.path.exists(marker)


if git:
    os.makedirs(repo)
    run([git, "init", "-q", "-b", "main"])
    open(os.path.join(repo, "f"), "w").write("a\n")
    run([git, "add", "f"])
    run([git, "commit", "-q", "-m", "one"])
    open(os.path.join(repo, "f"), "w").write("b\n")
    run([git, "commit", "-q", "-am", "two"])
    # the tree stays CLEAN (an editor/rebase needs it); `git diff HEAD~1 HEAD` has something to show
    P = probe
    # (key, the git invocation after `-c key=<probe>`, text of the command for the gate)
    RUNS = [
        ("core.fsmonitor", ["status"]),
        ("core.pager", ["-p", "log", "-1"]),
        ("pager.log", ["log", "-1"]),
        ("core.editor", ["commit", "--amend"]),
        ("sequence.editor", ["rebase", "-i", "HEAD~1"]),
        ("diff.external", ["diff", "HEAD~1", "HEAD"]),
        ("alias.zz", ["zz"]),
        ("gpg.program", ["commit", "-S", "--amend", "-m", "x"]),
        ("core.sshCommand", ["ls-remote", "ssh://example.invalid/r"]),
    ]
    runs_any = False
    for key, tail in RUNS:
        value = ("!" + P) if key.startswith("alias.") else P
        did = ran([git, "-c", "%s=%s" % (key, value)] + tail, tty=key in ("core.pager", "pager.log"))
        gate_blocks = blocks("git -c %s='%s' %s" % (key, value, " ".join(tail)))
        print("      real git runs the probe for %-16s: %s ; gate blocks: %s" % (key, did, gate_blocks))
        if did:
            runs_any = True
            check("a key that really RUNS its value is blocked: %s" % key, gate_blocks)
        else:
            check("(not triggered here, still blocked by inversion) %s" % key, gate_blocks)
    check("the differential triggered at least one real program run (the probe works)", runs_any)
    # credential helper: `git credential fill` runs the helper
    if os.path.exists(marker):
        os.remove(marker)
    run([git, "-c", "credential.helper=!" + P, "credential", "fill"], input_text="protocol=https\nhost=example.invalid\n\n")
    cred_ran = os.path.exists(marker)
    print("      real git runs the probe for credential.helper : %s" % cred_ran)
    check("credential.helper=!prog runs for real -> the gate blocks it",
          (not cred_ran) or blocks("git -c credential.helper='!%s' credential fill" % P))
    # the environment variables
    ENVRUNS = [
        ("GIT_EDITOR", ["commit", "--amend"]),
        ("GIT_SEQUENCE_EDITOR", ["rebase", "-i", "HEAD~1"]),
        ("GIT_PAGER", ["-p", "log", "-1"]),
    ]
    for name, tail in ENVRUNS:
        did = ran([git] + tail, extra={name: P}, tty=(name == "GIT_PAGER"))
        gate_blocks = blocks("%s='%s' git %s" % (name, P, " ".join(tail)))
        print("      real git runs the probe for %-20s: %s ; gate blocks: %s" % (name, did, gate_blocks))
        if did:
            check("an env variable that really RUNS its value is blocked: %s" % name, gate_blocks)
        # and the no-op value must pass and really be harmless
        check("%s=true passes the gate" % name, not blocks("%s=true git %s" % (name, " ".join(tail))))
    # the inert list: none of these keys may run the probe, whatever the subcommand
    INERT = ["user.name", "user.email", "user.signingkey", "commit.gpgsign", "tag.gpgsign", "core.quotepath", "core.autocrlf",
             "core.safecrlf", "core.filemode", "color.ui", "color.diff", "advice.detachedHead", "init.defaultBranch",
             "diff.renames", "diff.algorithm", "diff.context", "diff.colorMoved", "merge.ff", "merge.conflictStyle", "pull.rebase",
             "pull.ff", "rebase.autostash", "safe.directory", "gc.auto", "protocol.file.allow", "push.default", "fetch.prune",
             "credential.useHttpPath", "credential.interactive", "credential.username", "credential.https://x.invalid.username"]
    SUBS = [["status"], ["log", "-1"], ["diff"], ["commit", "--allow-empty", "-q", "-m", "z"], ["branch", "-f", "zz", "HEAD"],
            ["fetch", "/nonexistent"], ["config", "--list"], ["stash", "list"], ["rebase", "--abort"], ["checkout", "-q", "main"],
            ["credential", "fill"]]
    leaked = []
    for key in INERT:
        for tail in SUBS:
            if ran([git, "-c", "%s=%s" % (key, P)] + tail, input_text="protocol=https\nhost=example.invalid\n\n"):
                leaked.append((key, tail[0]))
    check("no key on the inert list runs the probe on any of %d subcommands (%d keys)" % (len(SUBS), len(INERT)), not leaked)
    if leaked:
        print("      LEAKED:", leaked)
    for key in INERT:
        check("inert key passes the gate: %s" % key, not blocks("git -c %s=anything status" % key))
else:
    check("git is installed (the differential needs it)", False)
shutil.rmtree(sandbox, ignore_errors=True)

# ---------------------------------------------------------------------------------------------------------------------
print("4. quoted values with a space are read from the raw command")
check("a quoted program value is not hidden by its quotes", blocks("git -c core.pager='sh -c id' log"))
check("a quoted harmless value passes", not blocks("git -c user.name='A B' log"))
check("two quoted -c: the bad one is found", blocks("git -c user.name='A B' -c core.pager='sh -c id' log"))
check("two quoted -c: both fine", not blocks("git -c user.name='A B' -c user.email='a b@c.d' log"))
check("same length, other key: the helper recipe passes only as the helper",
      not blocks("git -c 'credential.helper=!gh auth git-credential' fetch origin"))
check("a helper of the same length as the recipe is still denied",
      blocks("git -c 'credential.helper=!xx auth git-credential' fetch origin"))
check("a helper value with a variable is denied", blocks("git -c credential.helper=\"!gh auth $X\" fetch origin"))
check("a helper that is only a variable is denied (it was assumed harmless before ff9a0528)", blocks("git -c credential.helper=\"$CH\" status"))
check("an unrelated quoted `bash -c` word does not make a harmless pair fail",
      not blocks("git -c user.name='A B' log; bash -c 'echo hi there friend'"))
check("a typed -c word of ANOTHER length with the same key is not this pair (it is not a git call)",
      not blocks("git -c 'credential.helper=!gh auth git-credential' fetch origin; echo -c 'credential.helper=!rm -rf x'"))
check("a typed -c word of the same length but ANOTHER key is not this pair",
      not blocks("git -c user.name='A B' log; echo -c core.pager=xy"))
check("--unset with a value pattern is a removal, not a write", not blocks("git config --unset core.pager 'x.*'"))
check("--get-all with a value pattern is a read", not blocks("git config --get-all core.pager 'x'"))
check("an unrelated quoted `bash -c` word does not hide a bad pair",
      blocks("git -c core.pager='sh -c id' log; bash -c 'echo hi there friend'"))

# ---------------------------------------------------------------------------------------------------------------------
print("5. round 2 (Sam 1772): a program-valued name bound by ANY form, an ANSI-C -c pair, a global option with a separate value")
ANSIC = "$" + "'"
for name, tail in [("GIT_EDITOR", "git commit --amend --allow-empty"), ("GIT_SEQUENCE_EDITOR", "git rebase -i HEAD~1"),
                   ("GIT_PAGER", "git log -1"), ("GIT_ASKPASS", "git fetch origin")]:
    for form, cmd in [
        ("+=", "%s+='; touch m'; %s" % (name, tail)),
        ("printf -v", "printf -v %s '%%s' 'touch m'; %s" % (name, tail)),
        ("read", "read %s <<< 'touch m'; %s" % (name, tail)),
        ("for", "for %s in 'touch m'; do %s; done" % (name, tail)),
        ("plain =", "%s='touch m'; %s" % (name, tail)),
        ("export", "export %s='touch m'; %s" % (name, tail)),
        ("declare -x", "declare -x %s='touch m'; %s" % (name, tail)),
        ("arithmetic", "(( %s=1 )); %s" % (name, tail)),
        ("${:=}", ": ${%s:=touch m}; %s" % (name, tail)),
        ("mapfile", "mapfile -t %s <<< 'touch m'; %s" % (name, tail)),
        ("printf -v in a subshell", "( printf -v %s '%%s' 'touch m'; %s )" % (name, tail)),
    ]:
        check("%s bound by %s is blocked" % (name, form), blocks(cmd))
    check("%s=true in front of git still passes" % name, not blocks("%s=true %s" % (name, tail)))
    check("export %s=true still passes" % name, not blocks("export %s=true; %s" % (name, tail)))
    check("%s=true; (a plain no-op binding) still passes" % name, not blocks("%s=true; %s" % (name, tail)))
    check("%s=: in front of git still passes" % name, not blocks("%s=: %s" % (name, tail)))
    check("%s+= even with a no-op value is blocked (it APPENDS to an exported program)" % name, blocks("%s+=true %s" % (name, tail)))
for cmd in [
    "git -c " + ANSIC + "core.fsmonitor=touch m' status",                       # A12: the whole pair is an ANSI-C string
    "git -c" + ANSIC + "core.fsmonitor=touch m' status",                        # glued
    "git -c core.fsmonitor=" + ANSIC + "touch m' status",
    "git -c " + ANSIC + "core.fsmonitor\\x3dtouch m' status",                         # 4b42b6b0: the `=` written as an escape is read as the `=`
    "git -c " + ANSIC + "core.\\x66smonitor=touch m' status",                           # ... and so is a letter of the key
    'git -c core.fsmonitor"=touch m" status',                                   # the `=` is inside the quotes
    "git --attr-source status -c core.fsmonitor='touch m' status",              # A2: --attr-source takes `status` as ITS value
    "git --attr-source HEAD -c core.fsmonitor='touch m' status",
    "git --attr-source HEAD status",                                            # (denied before this round too, by the hook-class rule: it reads HEAD as the subcommand)
    "git --attr-source=HEAD -c core.fsmonitor='touch m' status",
    "git --super-prefix x/ -c core.fsmonitor='touch m' status",
    "git --namespace n -c core.fsmonitor='touch m' status",
    "git --config-env=core.fsmonitor=V status",
    "git --config-env core.fsmonitor=V --attr-source HEAD status",
    "git --some-future-option -c core.fsmonitor='touch m' status",              # an option the gate does not know, a pair behind it
    "git --some-future-option status -c core.fsmonitor='touch m' status",
    "git --some-future-option config core.pager 'touch m'",
    "git --some-future-option v config core.pager 'touch m'",                   # the future option takes `v` as its value: `config` is behind it
]:
    check(cmd, blocks(cmd))
for cmd in [
    "git --attr-source=HEAD log -1",
    "git --some-future-option status",                                          # nothing behind it that this rule judges
    "git --some-future-option log -1",
    "git --bare log -1",
    "git --git-dir=/tmp/x/.git --work-tree=/tmp/x status",
    "git --git-dir=/tmp/x/.git -c user.name=a status",                          # a glued global option is KNOWN: a pair behind it is judged, not doubted
    "git --namespace=n -c user.email=b@c.d status",
    "git --no-pager -c user.name=a log -1",
    "git -C /tmp/r -c user.name=a status",
    "git -c " + ANSIC + "user.name=a' status",                                      # 4b42b6b0: the word is DECODED now, and harmless: it was a deny only because it could not be read
    "git -c core.fsmonitor status",                                             # a bare key is still the boolean true
    "git -c color.ui status",
]:
    check(cmd + " (passes)", not blocks(cmd))
if git:
    sandbox2 = tempfile.mkdtemp(prefix="gitcfg2-")
    marker = os.path.join(sandbox2, "RAN")
    probe = os.path.join(sandbox2, "probe.sh")
    with open(probe, "w") as fh:
        fh.write("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
    os.chmod(probe, 0o755)
    repo = os.path.join(sandbox2, "repo")
    env2 = dict(env, HOME=sandbox2, GIT_EDITOR="true", GIT_SEQUENCE_EDITOR="true", GIT_PAGER="cat", GIT_ASKPASS="true")
    os.makedirs(repo)
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repo, env=env2, capture_output=True)
    for body in ("a\n", "b\n"):
        open(os.path.join(repo, "f"), "w").write(body)
        subprocess.run([git, "add", "f"], cwd=repo, env=env2, capture_output=True)
        subprocess.run([git, "commit", "-q", "-m", "c"], cwd=repo, env=env2, capture_output=True)
    bash = shutil.which("bash")

    def bash_ran(cmd):
        if os.path.exists(marker):
            os.remove(marker)
        subprocess.run([bash, "-c", cmd], cwd=repo, env=env2, capture_output=True, text=True, timeout=30)
        return os.path.exists(marker)

    real_runs = 0
    for name, tail in [("GIT_EDITOR", "git commit --amend --allow-empty"), ("GIT_SEQUENCE_EDITOR", "git rebase -i HEAD~1")]:
        for form, tmpl in [("+=", "%(n)s+='; %(p)s'; %(t)s"), ("printf -v", "printf -v %(n)s '%%s' '%(p)s'; %(t)s"),
                           ("read", "read %(n)s <<< '%(p)s'; %(t)s"), ("for", "for %(n)s in '%(p)s'; do %(t)s; done")]:
            cmd = tmpl % {"n": name, "p": probe, "t": tail}
            did = bash_ran(cmd)
            real_runs += did
            print("      real bash+git runs the probe for %-20s %-10s: %s ; gate blocks: %s" % (name, form, did, blocks(cmd)))
            if did:
                check("DIFFERENTIAL %s bound by %s really RUNS the probe -> the gate blocks it" % (name, form), blocks(cmd))
            else:
                check("(not triggered here) %s by %s is still blocked" % (name, form), blocks(cmd))
    check("the differential for the program-valued names triggered at least one real run (the probe works)", real_runs > 0)
    for desc, cmd in [("ANSI-C pair", "git -c " + ANSIC + "core.fsmonitor=%s' status" % probe),
                      ("--attr-source value", "git --attr-source status -c core.fsmonitor='%s' status" % probe)]:
        did = bash_ran(cmd)
        print("      real bash+git runs the probe for %-20s: %s ; gate blocks: %s" % (desc, did, blocks(cmd)))
        check("DIFFERENTIAL %s: %s" % (desc, "really RUNS the probe -> blocked" if did else "not triggered here, blocked by inversion"),
              blocks(cmd))
    shutil.rmtree(sandbox2, ignore_errors=True)

print()
if failed:
    print("FAILED %d:" % len(failed))
    for f in failed:
        print("  -", f)
    sys.exit(1)
print("ALL PASS")
