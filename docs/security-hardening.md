# Git force-push guard

Marveen agents run autonomously, often with shell access and the ability to push
to git, so a prompt-injected or simply mistaken agent can rewrite shared history.
This guard reduces that blast radius without changing how the fleet works.

## What it does

`scripts/install-git-guard-hook.sh` installs a `pre-push` hook that **refuses a
non-fast-forward (force / rebase / amend) push to `main` or `master`**. Normal
fast-forwards and merge commits pass untouched, and every other ref (`develop`,
feature branches, fork branches, including `--force-with-lease` to those) is
unaffected: only history rewrites of a protected branch are blocked.

It is named `install-*-hook.sh`, so `scripts/sync-hooks.sh` (and the dashboard
update flow) run it automatically. It composes with an existing `pre-push` hook
(e.g. a secret scanner) by moving it under `.git/hooks/pre-push.d/` and adding a
small dispatcher that feeds the ref list to every sub-hook.

```bash
scripts/install-git-guard-hook.sh   # runs automatically on update; manual run also works
```

Override an intentional rewrite of a protected branch:

```bash
ALLOW_FORCE_PUSH=1 git push ...
```

# Outgoing code needs a Sam-green trace (pre-push)

The owner's rule (2026-09-30): code that goes outward (a push, a force-push, an update of a PR
branch) goes only after Sam's approval; a green test is not enough. The rule used to live in
two CLAUDE.md files and nothing enforced it.

`scripts/install-sam-green-gate-hook.sh` (run by `scripts/sync-hooks.sh`, like the other
installers) copies `scripts/git-hooks/pre-push-sam-green.py` into
`.git/hooks/pre-push.d/30-sam-green-gate`. The hook is repo-level, but it gates **agent
sessions only** (the owner's decision, 2026-10-11, Telegram 4034): a push that does not come from a
Claude Code session goes through without a trace, with one line on stderr, so the owner's own hand
push is free.

**Who counts as an agent.** At least one of `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
`CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_EXECPATH` is set and non-empty in the environment of the
push. Claude Code sets them for every process its Bash tool starts and git passes the
environment on to the hook (measured from an agent's own shell, 2026-10-11).
`CLAUDE_CONFIG_DIR` is deliberately not a marker: it can be exported in a plain terminal to run
`claude`. This is a "who typed it" guess from the environment, **not an identity**, and it fails
in both directions:

- An agent that unsets the markers (`env -u CLAUDECODE ...`) or pushes from a process that is
  not a Claude Code child walks through, silently. Same class as `--no-verify`; pinned in the
  tests as a documented limit.
- A push the owner types *inside* a Claude Code session (the `!` prefix) carries the markers, so it
  is gated like an agent's. His way through is the logged skip below.

**What counts as the trace.** A message in the fleet mailbox that is from `sam` (status not
`failed`) and contains a line of its own, exactly:

```
SAM-ZOLD <8 to 40 hex digits of the head commit>
```

The hash binds the green to the commit being pushed, so an amend, a rebase or a further commit
on the PR branch needs a new line. Text after the hash, a wrapped or inline mention, a prefix
shorter than 8 digits and a row from another sender do not count. The gate reads
`/api/messages?agent=sam` (up to 2000 of Sam's messages back) with the dashboard token.

**What needs no trace:** a deletion, and a push that sends no commit the destination lacks
(already on the target remote's tracking refs; for a destination other than `origin`, also
already on `origin`). Anything that cannot be verified (dashboard down, token unreadable, a ref
that does not resolve) blocks.

**The member is in `pre-push.required`** (like the force-push guard and the personal-data gate):
the installer records its sha256, and the dispatcher blocks a push if `30-sam-green-gate` is
missing or its bytes changed (for example replaced by `exit 0`). Removing the gate therefore leaves
a line in the push output. Reinstalling re-records the hash. Another member that someone installs by
hand into `pre-push.d` is not covered unless its installer registers it.

**What it is not.** It guards against *forgetting* the rule, not against a deliberate bypass:
the trace is self-declared (one shared bearer token writes any `from_agent`), and
`--no-verify` on the push skips every pre-push hook without leaving a line. Do not read a pass
as proof that Sam reviewed the change.

**The way through, only on the owner's explicit instruction for that push:** set
`SKIP_SAM_GREEN_GATE=1` and `SAM_GREEN_SKIP_REASON="Owner TG <message id>: <why>"` in the
environment of the push command. The reason is mandatory and the call is appended to
`store/push-samgreen-skips.log` (who, when, remote, refs, reason); if the line cannot be
written the push is refused.

# Personal data and repository visibility on the way out

The secret gate asks whether a file holds a credential. This gate asks a different
question of a different object: does the push add **data about a person**, and is the
place it goes **public**? It reuses the same dispatcher (`pre-push.d/`) and the same
runner (`scripts/secret-gate.ts`), so there is one entry point for "may this leave the
host", not a second gate to forget to install.

## What it does

`scripts/install-secret-gate-hook.sh` (run by `scripts/sync-hooks.sh` on update) now also
installs `pre-push.d/15-personal-data-gate`. For every ref a push updates it works out the
commits the remote does not have yet, and scans **the lines each commit adds and its
message** for:

| Detector | What it flags |
|----------|---------------|
| `email` | an address that is not a reserved domain, a no-reply/bot form, a role mailbox (`support@`, `info@`, ...), a synthetic domain (`b.hu`, `pelda.hu`, `ceg.hu`, one/two-letter labels), a system address (service accounts, calendar ids) or a URL's userinfo |
| `local-path` | `/home/<name>`, `/Users/<name>`, `/mnt/c/Users/<name>` (WSL), `C:\Users\<name>` in any case and slash style, and the JSON-escaped form, with an account that is not a placeholder (`u`, `user`, `foo`, `runner`, `$USER`, ...) |
| `phone` | `+36` / `06` Hungarian numbers written with any mix of spaces, brackets, slashes, dots and dashes, and generic `+cc` numbers, minus obviously invented ones, date ranges and counting sequences |
| `iban` | an IBAN whose ISO 13616 mod-97 checksum passes |
| `hu-account`, `hu-taxid` | Hungarian bank-account (8-8, 8-8-8) and tax-number (8-1-2) shapes |
| `denylist` | any term in your **local** denylist (below) |
| `binary` | a binary file in the pushed commits (public or unknown target: blocks unless a reviewed exception names the blob) |

Design points, each one a failure of the mod this replaces:

- **It runs in git, not on the command text.** The hook sees what git is about to
  transmit, so `git push`, `git -C x push`, `HEAD:refs/heads/y`, an alias, a script, or a
  tool that shells out are all the same push. (A check written against the literal
  `git push` string sees only the spellings its author thought of.)
- **Added lines only, per commit.** Deleted and context lines are never scanned, so
  removing personal data is never punished. A line added in one commit and removed in the
  next is still published, so every commit is scanned, not the net diff.
- **Patches are read by hunk length, never by what a line looks like.** An added line that
  begins with `++` is not mistaken for a file header and silently dropped.
- **Record boundaries are a per-run random token** at a line start, not a fixed control
  byte. The matched text is never printed, only file, line and detector.
- **Fail-closed everywhere.** An outgoing set that cannot be computed, a patch git will not
  produce, a denylist rule that does not compile, a malformed exception table: each blocks.
  Binary changes cannot be read by a text detector and are reported as NOT scanned.
- **Visibility only ever raises strictness.** The target is probed *anonymously*
  (`GET api.github.com/repos/<o>/<r>`, no token): `200` + `private:false` is public, `404`
  is "not readable by a stranger" (private), and everything else (rate limit, 5xx,
  timeout, a non-GitHub remote) is *unknown* and treated as **public**. Findings block when
  the target is public or unknown; they only downgrade to a loud warning on a positive
  "private". The probe cannot be switched off with an environment variable.

## Deliberate literals, names, and the audit before a repo goes public

- A reviewed, deliberate literal goes in `PII_EXCEPTIONS` (`src/security/pii-gate.ts`) as a
  **sha256 of the matched text + a written reason**, exactly like the secret gate's fixture
  exceptions: the key is a hash (no line number to go stale, and the literal cannot live in
  the scanner), a changed literal stops matching, and every applied exception is printed.
  There is **no environment override**.
- A **name** is not a shape, so the gate cannot recognise one. Put known names in a
  *local, untracked* file, `<repo>/.git/hooks/pii-denylist.txt` (one per line; `#` comments;
  `re:<pattern>` for a regex). It lives outside the tree on purpose: the names are the data
  being protected. Without the file the gate says so in its output.
- Before a private repository is made public, audit its **whole history**:
  `npx tsx scripts/secret-gate.ts --pii-range <rev-list args>` (for example `--all`).

## Turning the hook off, and what stops that

Every way of making git skip a hook is a way of making this gate off, so the
`destructive-gate` PreToolUse hook denies them for agent sessions:

- `git push --no-verify`, including git's *unambiguous* abbreviations (`--no-veri`; `--no-ver`
  is ambiguous between `--no-verify` and `--no-verbose`, so git itself refuses it), and the
  same resolution for `--force-w`, `--del`, `--mir`, `--prune`. Bundled short flags that contain
  `f` or `d` (`-fu`, `-df`) count as force / delete.
- `core.hooksPath` in **any** git command: `git config core.hooksPath X` (a separate, lasting
  command), `git config --local ...`, `git -c core.hooksPath=X <anything>`, and the
  `GIT_CONFIG_KEY_n` / `GIT_CONFIG_PARAMETERS` environment forms. Reading it (`git config
  core.hooksPath`, `--get`, `get`, `--list`) and *unsetting* it (the repair) stay allowed.
- The **effective value**, not only the spelling. Matching command text is always one writing
  method behind (an alternative config file, `include.path`, a `cd` followed by a relative path
  each got past the first two versions), so before a `git push` **and before every other
  hook-running subcommand** (`commit`, `merge`, `rebase`, `am`, `pull`, `cherry-pick`, `revert`;
  round 3: an interpreter can append `core.hooksPath=/dev/null` to the repo's `.git/config`, and
  that switched off the commit-time gates) the gate asks git itself what it would see:
  `git config --show-origin --get-all core.hooksPath`, with the same `-C` and inline
  environment the call would run with. Any value from any source (repo, user, system, an
  included file) blocks the call. A directory git cannot read (`-C` to a path that does not
  exist yet) is a deny as well: the gate cannot prove the hooks run. `git config include.path` / `includeIf.*` writes are denied
  for the same reason, and so are the variables that move git's config around:
  `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_*`, `XDG_CONFIG_HOME` and a `HOME=`
  placed in front of `git`. (The effective-value query cannot see a file that the *same*
  command creates a moment earlier; the variable rules are what close that.) A relative path
  after a `cd` is resolved against the working directory the gate tracks, so
  `cd .git && printf ... >> config` is judged as the file it is.
- The dispatcher knows which members **must** exist and what they must contain: the installers
  list them with the sha256 of the bytes they wrote in `.git/hooks/pre-push.required`, and a
  listed member that is missing, or whose bytes no longer match, blocks the push, like one that
  cannot run. Deleting a gate file, or replacing it with `exit 0`, no longer makes the dispatcher
  quietly run fewer checks; reinstalling re-records the hash.
- **The environment the hooks read: an allowlist** (round 3, replaced in round 2 of card f4057869). A fixed list of names kept
  growing by one (`SKIP_SECRET_GATE`, `CLAUDECODE=`, `MARVEEN_PROD_ROOT`), and round 3 derived the names from the text of the
  hook files. Both fail the same way: the runtimes that RUN the hooks read their own names outside that text. Measured by Sam
  with a real git and a real hook: `BASH_ENV=f git commit` switches off every bash hook at once, `PYTHONPATH=dir` (a `json.py`
  in it) every python hook, `NODE_OPTIONS='--require f'` every node hook; `LD_PRELOAD`, `ENV`, `SHELLOPTS` and `PS4` are the same
  family (not measured against the live hooks). So nothing is listed as dangerous any more (inverted proof): on a command line
  that runs git, an environment name may be given to a child only if it is on a short allowlist (`GIT_AUTHOR_*` and
  `GIT_COMMITTER_*`, `GIT_EDITOR` and its relatives, `GH_TOKEN`, `GITHUB_TOKEN`, `LANG`, `LC_*`, `TZ`, `NO_COLOR`, `CI`, `TERM`,
  `COLUMNS`, `LINES`, `IFS`) or is not all upper case. `IFS` is on the list because it was measured: `IFS=Q git commit` shows
  the default `IFS` inside a bash hook, bash ignores it from the environment. Where the line puts a name in a child's
  environment (a prefix assignment `NAME=v cmd`, `export`, `declare|typeset -x`, `env NAME=v`) the name must be allowed. Where it
  only binds a shell variable (`NAME=v;`, `for`, `read`, `let`, `(( ))` ...) it is a deny only when the name is already exported
  in the session (`CLAUDECODE=; git push`, `PATH=/x:$PATH; git commit`), because a variable that is not exported cannot reach
  git. `unset NAME` and `env -u NAME` follow the same rule (removing a name that is not in the environment is a no-op).
  Whole-environment switches are a deny: `env -i`, `env -`, `exec -c`, `set -a` / `set -o allexport` (every later assignment
  becomes a child variable) and `export -f` / `declare -fx` (an exported function becomes `BASH_FUNC_name` in every child bash).
  An interpreter payload (`python3 -c`, `python3 - <<PY`, `node -e`, `ruby -e`, `perl -e`) that starts git AND passes or edits
  an environment (`env=`, `os.environ[...] =`, `os.putenv`, `os.execve`, `process.env.X =`, `ENV.clear`, `%ENV = ...`) is a
  deny: the gate cannot prove the hooks see the session environment. A python or node heredoc body is not shell text and is not
  scanned for `NAME=`. A target that is not a plain identifier (`export $V=1`, `export {A,B}=1`, `export S''KIP=1`) is a deny.
  The cost, measured on the 3,901 recorded commands against the live gate (4bc00eb0): 27 new refusals and 18 commands the live
  gate refused that now pass. The refusals are `export PATH=...` (8), `set -a; . file` (7), a python payload that mentions git
  and edits the environment (5), and upper-case prefix assignments on a git line (`HOOK_SCRIPT=`, `CLAUDE_PROJECT_DIR=`,
  `PATH=`, `MARVEEN_BOT_EMAIL=`, 5; two more, `H=` and `TOK=` inside a quoted multi-line text, are false positives). The 18
  passes were script variables the derived list refused for sharing a name with a hook (`URL=`, `HEAD=`, `ALERT_TO=` ..., 17)
  and one `env -u` of a name that was not set. Friction: an upper-case prefix assignment in front of ANY command on a line that
  also runs git is refused (`FOO=1 echo hi; git status`); write it lower case, or on its own line. Activating a virtualenv
  (`. venv/bin/activate && git commit`) is refused, because the activate script exports `PATH`.
  Where those numbers were measured: the rule "a plain binding is a deny only for a name already exported" reads the gate
  process's own environment, so the decision depends on it. The 27 / 18 above is the replay in a session environment (what every
  live hook has: `CLAUDECODE` is always set). Replayed in an empty environment (`PATH`, `HOME`, `LANG` only) the same corpus gives
  27 / 20; the two extra passes are both `env -u CLAUDECODE`, which the gate refuses only when `CLAUDECODE` is set in its own
  environment (Sam, card f4057869, comment 1636). A replay or CI run outside a session therefore reports a different number, and
  the same line can get a different verdict in agents whose sessions export different names. Set the session names before
  replaying, and state the environment next to the number.
- **Every place bash can bind a name** (round 4, card f4057869). `for CLAUDECODE in ""; do git push ...; done` empties
  the exported marker in the child (measured with real bash by Sam), and it is not a `NAME=` or one of the verbs above. The
  grammar of bash has a finite set of binding places, and a name that is not allowed for it (see the allowlist above), or a target
  that is not a plain identifier, in any of them is a deny on a line that runs git: `for` / `select` variables, `getopts o NAME`, `let`, `(( ))` and `$(( ))`
  assignments and `++` / `--`, `${NAME:=x}` / `${NAME=x}`, `{NAME}>file` (the fd number), `NAME+=`, `NAME[i]=`,
  `coproc NAME {`, `wait -p NAME`, a nameref (`declare|typeset|local|export -n`), and `source` / `.`: silent only for a literal
  path the gate can read (a leading `~` is expanded) that exports no name outside the allowlist, binds no already exported name,
  and holds no `set -a` or `export -f` (the content is matched, never printed); a file made in the same command, a computed path
  or an unreadable file is a deny.
- A **backslash** in an option position is an expansion (bash turns `\-n` into `-n`), and the
  **dashed git-core commands** are the subcommand itself: `/usr/lib/git-core/git-send-pack`,
  `git-http-push` and the `git remote-http|https|ftp|ftps|ext|fd` helpers send refs without
  running `pre-push`, `git-commit` is `git commit`. The directory does not matter.
- **The GitHub ref API** moves a ref without git, so it skips every pre-push gate: for agents,
  `gh api` writes (any method but GET, and a field-sending `-f/-F/--input` call, which defaults
  to POST) to `repos/<o>/<r>/git/refs...`, `.../branches/<b>/protection` and `.../rulesets`, and
  a `graphql` call that holds `createRef`/`updateRef`/`deleteRef`/`mergeBranch`/
  `createCommitOnBranch` (or whose query text the gate cannot read: `--input`, `query=@file`).
  Reading (GET, no fields) stays allowed. Named, not closed: `PUT repos/.../contents/<path>`
  and `POST repos/.../merges`, which also create commits on a branch through the API.
- Named limits of the environment and plumbing rules (rule 11 (c), not closed here): a lowercase
  variable a runtime or a hook reads (`http_proxy`, `no_proxy` ... are free); an interpreter that builds its environment from
  variables and starts git (the payload rule reads the text, it cannot evaluate it); `LD_PRELOAD`, `ENV`, `SHELLOPTS` and `PS4`
  are denied on the same ground as `BASH_ENV` but their effect on the live hooks was not measured; a `PATH`-prefixed fake `git`
  that is not a prefix assignment; `git commit-tree` / `git replay` (they create commits
  or refs without a hook); `git push --receive-pack=...`.
- Changing the gate's own files, and every file `core.hooksPath` can be written into: `chmod`,
  `mv`, `rm`, `cp`, `ln`, `sed`, `tee`, `dd`, `truncate`, `find ... -delete/-exec`, a pipe into
  the xargs/parallel family ... on anything under `.git/hooks`, on `.git/config`,
  `config.worktree`, `~/.gitconfig` and `~/.config/git/config`, and shell redirection into any
  of them (`printf ... >> .git/config` is as lasting as `git config core.hooksPath X`).
  Reading stays allowed.
- The dispatcher itself no longer skips a `pre-push.d` member that is present but not
  executable: that is an **error** ("a hook that cannot run is a gate that is off"). Both
  installers write the same dispatcher, and a test pins that they stay identical.

It also denies the *visibility flips* that expose a whole history at once:
`gh repo edit --visibility public|internal`, `gh repo create --public`, and `gh api` PATCH/POST
calls to `repos/<owner>/<repo>` that set `private=false` or `visibility=public`, including the
glued short-flag spellings (`-XPATCH`, `-Fprivate=false`). A body passed with `--input` is
refused because the gate cannot read it.

What the scan itself cannot be talked out of (found by review on the first version): the patches
are produced with `--text --no-textconv --no-ext-diff` and fixed `a/` `b/` prefixes, so a
`diff=` attribute, a `textconv` driver, an external diff driver or `-diff` in `.gitattributes`
cannot hide an added line. A **binary** (a NUL byte in what git would diff) is a *finding* in a
public or unknown target, not a note: an xlsx or a pdf full of personal data must not sail
through. A reviewed binary goes in `PII_EXCEPTIONS` keyed by path and the sha256 of its git
object id. Annotated tag messages are scanned too (nested tags peeled), and when the URL behind a
remote name changes, its old tracking refs stop hiding commits from the scan. The new URL is
recorded (as a hash, in `hooks/pii-gate-remotes.json`) only after a run that let the push go,
so repeating a blocked push unchanged is still scanned in full.

Limits, stated out loud:

- A person at a terminal can still `--no-verify`; the hook protects against mistakes and
  against agents, not against its owner. CI is the check a hook cannot be.
- The destructive-gate reads command text. A quoted string containing a space is data to
  it, so a GraphQL mutation inside `-f query='...'` is not seen. `curl`, `python` or `node`
  calling the GitHub API directly (a PATCH to `repos/<o>/<r>` with `private:false`) is not
  something this gate recognises; it is only as covered as the egress gate covers that script.
  The same goes for any script or interpreter that writes under `.git/hooks` itself.
- That "quoted text is data" rule rests on the gate's quote map, so the map has to end a quote
  where the shell does. ANSI-C quoting (`$'...'`) ends at the first apostrophe that a backslash
  has not escaped, unlike a plain single quote: `echo $'a\'b'` is ONE word. The map used to cut it
  at the `\'` and read everything after it, including the next line's `rm -rf`, as quoted
  data, so that command passed (card f8acbcb4, measured on the live gate). `$$'` (the PID, then
  a plain quote) and `"$'"` (inside double quotes, literal) are not ANSI-C. Measured against the real
  bash: 16,000 random quote strings, a final word that bash executes sat inside a quote in the map
  148 times before the fix and 0 times after; the suite carries a 1,500-string version of that run.
  Price, final verdicts on every Bash command of every transcript on this install (32,248 unique commands, old and new gate
  in-process): 0 newly denied, 0 newly allowed. Mutants: 8 of 10 killed, the 2 survivors are equivalent (the `$` counter is
  reset on every exit from a quote, so counting inside quotes or keeping it after the opener changes nothing).
- A hook runs inside the repository it was installed in. A fresh clone has none, so cloning the
  repository elsewhere and pushing from the clone is not seen by this gate; that is the natural
  edge of any git hook, and the reason CI is the check a hook cannot be.
- Removing the `15-personal-data-gate` member from a hook directory the installers wrote is not
  silent: `pre-push.required` lists it, and a listed member that is missing (or whose bytes no
  longer match the recorded hash) blocks the push. Measured with the installed hook. A checkout
  that was never installed has no manifest and so nothing to compare against; the destructive-gate
  denies the commands that would remove the member, and a re-run of `scripts/sync-hooks.sh`
  restores it.
- The manifest hash covers the members of `.git/hooks/pre-push.d`, not the code they run. The
  `15-personal-data-gate` member executes the install root's own sources (`scripts/secret-gate.ts`,
  `src/security/pii-*.ts`); whoever rewrites those files switches the gate off while the member's
  recorded hash still matches. Editing them is the same class as the interpreter write above.
- The destructive-gate asks git for the effective `core.hooksPath` of the repository the push
  runs in. A push aimed at a different repository through the environment (`export GIT_DIR=...`
  before `git push`) is not that repository's hook problem and is not seen; it is the same edge
  as the fresh-clone limit above.
- Known over-blocking, in the fail-closed direction: commands that only *read* `.git/config` or
  copy `.git/hooks/pre-push` out (`sed -n` on the file, `cp` to a temp path) are denied, and
  `XDG_CONFIG_HOME=` is denied on any command, not only in front of `git`. Measured by review on
  the fleet's recorded commands: zero pure copy-out cases (the `cp` hits were copies *into*
  `.git/hooks`, rightly denied, or sat in a command that also edited the hook), about a dozen pure
  `sed -n` reads, and zero env cases. The copy-out over-block exists, but was only reproduced with
  hand-made probes.
- The detectors know *shapes*. An address written as `name at domain dot com`, a path assembled
  by string concatenation or a number written in words is not seen. The e-mail rules also let
  through role mailboxes and the placeholder domains listed in `pii-gate.ts`; each word in those
  lists is a claim that the thing is not a real organisation.
- The `--remotes=<name>` exclusion trusts the tracking refs under that name. If they are stale
  they make the scan *larger*, never smaller; the URL-change record above covers the one case
  where they describe the wrong repository.
- Measured on the last 150 develop commits (1401 commits, 9 s): after calibration the audit
  flags 83 home-directory lines and 27 addresses, mostly real-looking account names and free-mail
  addresses in test fixtures. That is the `--pii-range` audit, not what a push scans: a push
  scans only the commits the remote does not have. Run `--pii-range` yourself before relying on
  the numbers.

# Bash egress deny rules

`scripts/hooks/egress-gate.mjs` compares a URL against the allowlist, but it is
wired as a `PreToolUse` hook with matcher `WebFetch` **only**. Bash was never
ungated (`outgoing-copy-gate.py` and `email-approval-gate.py` on the main agent,
`email-send-gate.mjs` and `self-pace-gate.mjs` on sub-agents) but none of those
gates looks at the destination host, so a shell `curl` never met the allowlist.
The realistic threat is not a malicious agent: it is a fetched page telling an
agent to run a `curl`, which is why the quarantine-reader exists in the first
place.

## What it does

`BASH_EGRESS_DENY` in `src/web/agent-scaffold.ts` is the single source of truth
for the EGRESS part of `permissions.deny`, and it lands in **every** agent's
`settings.json` by three routes:

- on spawn, via `writeAgentSettingsFromProfile()`,
- on server startup, via `ensureBashEgressDeny()` (existing fleet, and the main
  agent -- see the scope note below),
- on scaffold, via `templates/settings.json.template` (so the next agent created
  starts gated -- a parity test keeps the template and the constant in step).

It is **not** the only list any more: since DENYARGS925 a second constant, the
fleet deny FLOOR, feeds the same block. The two are described together in the
next section, because the difference between them is not what they deny but how
they REACH an agent -- and that is the part that decides what happens when one
of them is edited.

Denied: `curl` to an `https://` URL, and `wget` / `nc` / `ncat` / `telnet`
outright. A `deny` rule is checked **before** the
`--dangerously-skip-permissions` bypass, so it binds on permissive profiles too.
Sanctioned tooling that speaks HTTPS on its own account (`git`, `gh`, `npm`) is
deliberately untouched: denying it would break the release path without closing
anything an agent could not do through it anyway.

The sanctioned route for external content is unchanged: the quarantine-reader
sub-agent, through `WebFetch`, where the domain check already runs. A host being
on the egress allowlist does not open it to the shell.

## Two lists, and why they are not one

Since DENYARGS925 (2026-09-25) `permissions.deny` is fed by TWO constants in
`src/web/agent-scaffold.ts`. Reading either one as "the" deny list is the
mistake this section exists to prevent.

| | `BASH_EGRESS_DENY` | `FLEET_BASELINE_DENY` |
|---|---|---|
| covers | shell URL-fetch verbs: `curl` to `https://`, `wget`, `nc`, `ncat`, `telnet` | the fleet FLOOR: key/credential dirs, `.env`, `sudo`, `rm -rf` of `$HOME` and `/`, force-push (friction only), the unsafe browser-code MCP tool |
| sub-agent gets it | spawn + server-startup migration + scaffold template | **spawn only** (`writeAgentSettingsFromProfile`) |
| main agent gets it | `ensureBashEgressDeny()` into its own config dir | the repo's tracked `.claude/settings.json` (the scaffold never writes the main agent, #1305) |
| parity guarded by | `bash-egress-deny.test.ts` (template vs constant) | `fleet-baseline-deny.test.ts` (shipped file vs constant, both directions) |

Two consequences follow from the row that differs, and both are deliberate:

**The floor has no startup migration.** An agent that is running right now and is
not respawned keeps whatever deny list it started with; the egress rules would be
merged into its file at the next server start, the floor would not. The floor
therefore takes effect at the next spawn, not at the next server restart. This is
the honest limit, not a claim of immediate fleet-wide cover.

**The floor is deliberately NOT in `templates/settings.json.template`.** Measured
2026-09-25: after `scaffoldAgentDir()` the template-derived file carries 10 deny
rules and **zero** of the floor's 13 -- but on the create path
(`routes/agents.ts`) `scaffoldAgentDir()`, `writeAgentModel()`,
`writeAgentSecurityProfile()` and `writeAgentSettingsFromProfile()` are four
SYNCHRONOUS calls with no await and no session launch between them, and on the
spawn path the profile write runs before the Claude Code process starts. So the
template-only state exists on disk but no session reads it, and
`loadProfileTemplate()` cannot throw its way around that: a missing or unparseable
profile falls back to `default` and finally to `HARDCODED_DEFAULT_PROFILE`. The
live fleet agrees: the leanest agent here carries 16 rules, none carries 10.

If a future change adds a route that scaffolds WITHOUT writing the profile
straight after, that reasoning expires and the floor belongs in the template too.
The parity test names this condition so the decision can be re-measured rather
than re-argued.

## Where the main agent's copy goes

The main agent's nominal settings path is the shared user root
(`~/.claude/settings.json`) -- and that same file is the operator's own
interactive Claude Code sessions. The owner's decision (2026-09-07) was that
their own shell stays unrestricted while the fleet stays gated, which makes the
shared file unusable in both directions: writing there restricts the operator,
removing it from there un-gates the main agent, which is the one agent that
reads untrusted web content on the owner's behalf.

Measured way out: when the install gives the main agent a config dir of its own
(`MAIN_AGENT_CONFIG_DIR`, or the provisioned isolated dir behind
`MAIN_AGENT_ISOLATED_CONFIG`), that dir's `settings.json` is the agent's user
scope and the operator's shell does not read it. `bashEgressDenyTargetPath()`
sends the rules there. The separation survives restarts: the provisioner
rebuilds that file from the shared one on every start but keeps keys the shared
file never mentions, and `permissions` is such a key.

When the main agent runs on the shared root there is no scope that covers it
without covering the operator, so **nothing is written** and the startup log
says so. Giving the main agent its own config dir is the fix; picking a side
quietly is not this code's call.

## The trap for whoever measures this next

The two scopes do not behave the same way, and the difference is invisible until
it misleads you (both measured 2026-09-07):

- The **project scope** (`<cwd>/.claude/settings.json` and `settings.local.json`)
  is re-read while a session runs. A rule written there fires immediately, which
  makes it a fine live test bench: drop a narrow, unique rule in, probe it, then
  delete the file.
- The **user scope** (the `settings.json` in the session's `CLAUDE_CONFIG_DIR`)
  is read when the session STARTS and is not re-read afterwards. A rule written
  there while the session runs does nothing at all.

So a probe that works perfectly on the project scope reports a confident
"allowed" on the user scope, and the honest-looking conclusion -- "the rule does
not work" -- is wrong. What it means is "this session has not read it yet".
Measure a user-scope rule from a session that started AFTER the write, or after
the next restart.

The same asymmetry is why a newly written rule binds the main agent from its
next restart rather than immediately.

## The Ponder tier: one agent that may read the public web

One agent, the research agent `agents/ponder`, may read the public web without
an allowlist (owner decision, `permission_change`). Everybody else is unchanged.
It takes three conditions at once, in `scripts/hooks/egress-gate.mjs`:

1. **Identity.** The PreToolUse payload's `transcript_path` lies under
   `<install>/agents/ponder/.claude-config/` and the payload carries no
   `agent_type` / `agent_id` (so a helper Ponder spawned is not Ponder). The path
   is written by the harness from the session's own isolated config dir, which an
   agent cannot change from inside a session. Nothing the caller composes is
   used: `cwd` follows a `cd`, a tool argument or a prompt is just text. A path
   that changes under normalisation (`..`, `//`, `/./`) is not trusted.
2. **Switch.** `store/egress-allowlist.json`: `{"ponder_posture": "open"}`. Only
   the literal string `open` opens it; a missing key, a missing file, a typo or a
   wrong type is closed. The file is read on every call, so flipping it needs no
   restart, and the allowlist baseline watcher reports the change like any other.
   The switch ships closed: applying the code changes nothing until the operator
   flips it.
3. **Rules, before every allow path.** Public `http(s)` only; no userinfo; ports
   80/443; no IP literal in any spelling; no internal, private, loopback,
   link-local or metadata host; no single-label name; URL at most 2048 characters
   and query at most 512. WebFetch is GET-only by construction (its input is a url
   and a prompt, never a method or a body). The URL itself is the one thing a
   poisoned page could abuse to carry data out, hence the length caps and the
   audit.

Playwright for Ponder (identity only, the switch is not needed because these are
restrictions): an **allowlist** of 16 reading tools out of the 83 that
`@playwright/mcp` 0.0.82 ships (`navigate`, `navigate_back`, `navigate_forward`,
`reload`, `tabs`, `close`, `snapshot`, `take_screenshot`, `find`, `wait_for`,
`console_messages`, `network_requests`, `network_request`, `click`, `hover`,
`press_key`, which passes only a key that prints nothing: Enter, Escape, Tab, the
arrows, PageUp/PageDown, Home/End; any character or modifier combo would type text one
call at a time and empty the `type` ban). Every other `mcp__playwright__*` tool is refused, so a tool a later
package version adds is closed by default. The navigation URL gets the same rules
as WebFetch, on both tools that navigate: `browser_navigate` and `browser_tabs`
(action `new` with a `url`; any `url` on any tabs action is judged, and an action
outside list/new/select/close is refused). The browser is narrower, not
read-only: `click` and `press_key` stay, and a click can submit a form the page
prepared. The hook is wired on `mcp__playwright__.*` for every sub-agent and is a
no-op for everyone but Ponder.

For Ponder the resolved address is judged as well: the hook resolves the host of a
WebFetch (Ponder tier), `browser_navigate` and `browser_tabs` url, and refuses it
when ANY returned address is non-public (private, loopback, link-local, CGNAT,
multicast, v4-mapped, NAT64, 6to4 and Teredo forms, with the embedded v4 unpacked) or when the name does not resolve or the
lookup exceeds 3 s (fail closed). Measured cost: 70-120 ms per call, whole hook.
This is a point-in-time check: the tool resolves again when it fetches, so DNS
rebinding is not closed, and neither is a redirect or a navigation the page itself
starts (a click, a script, a meta refresh), which the gate never sees.

Every Ponder call that reaches the gate, allowed or denied, is appended to
`store/ponder-egress.jsonl` (time, session, tool, decision, tier or reason, host,
full URL, URL and query length). The WebFetch prompt and page content are never
logged.

**The browser, behind a destination filter (v4).** The hook judges the URL a
Playwright call is asked to open, and nothing the page does afterwards. Measured
against `@playwright/mcp` 0.0.82 with a real Chromium and a local "internal" server:
all nine routes reach it: a server redirect, a meta refresh, `window.location`, a
click, `window.open`, `fetch()`, an iframe, `browser_tabs` new, a direct navigate.
The MCP's own `--blocked-origins` / `--allowed-origins` close eight of them and say
that they do not affect redirects (measured: the redirect still arrives); they also
match exact origins, not address ranges or names that resolve somewhere private.
So the research agent's browser runs behind `scripts/ponder-browser-proxy.mjs`,
started by `scripts/ponder-playwright-mcp.mjs` (the server command in the agent's
`.mcp.json`, key exactly `playwright`). The proxy sees every request the browser
makes, resolves the name itself, refuses a port other than 80/443, an IP literal,
a single-label name, a name that does not resolve, and any name for which ANY
resolved address is non-public (the hook's `isNonPublicAddress`, one definition),
and connects to the address it checked, so a rebinding answer between the check
and the connection cannot happen. With the proxy in the path the same nine routes
to an internal name are refused, and the same nine routes to a public-looking name
still work (the positive control in the end-to-end test). The launcher refuses the
flags that would route around it (`--proxy-server`, `--proxy-bypass`,
`--cdp-endpoint`, `--extension`, `--config`, `--allow-unrestricted-file-access`) and
removes `PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK` from the server's
environment. `scripts/ponder-browser-check.mjs` reads the agent's `.mcp.json` and
says whether that is the setup in place. Every refusal is appended to
`store/ponder-proxy.jsonl`; allowed requests are only counted.

The browser binary is pinned by HASH (PONDERBINPIN1004, v5.3 PONDERBINHASH1004).
`--executable-path` used to take any absolute path, so a wrapper script that ignores
`--proxy-server` was a valid browser; v5.2 pinned the name and the ELF shape, and the
owner's second bypass search showed that an ELF dropped there by `curl -o` / `wget -O`
passed both. The launcher and the check now accept only a file that (1) resolves under
the running user's `~/.cache/ms-playwright` (passwd entry, not `$HOME` or
`PLAYWRIGHT_BROWSERS_PATH`), (2) has one of the two exact names
(`chromium-<N>/chrome-linux*/chrome`,
`chromium_headless_shell-<N>/chrome-headless-shell-linux*/chrome-headless-shell`) and
(3) hashes to one of the two sha256 values in `PINNED_BROWSER_SHA256`
(`scripts/ponder-playwright-mcp.mjs`, measured 2026-10-04 for chromium-1228). The server
is started with the resolved path. Hashing costs about 1.5 s per launch (278 MB, measured
with node:crypto). A Playwright update changes the hashes ON PURPOSE: the new browser is
refused until somebody replaces the two lines (the file header has the `sha256sum`
command). Not closed: hash-then-spawn is not atomic, so whoever can replace the file in
that ~2 s window is not stopped here; that is the write confinement's job.

That confinement is PONDERWRITE1004 (`scripts/hooks/destructive-gate.py`): the research
agent may write only in `~/agents_munka/ponder/`, `agents/ponder/HANDOFF.md`, the Claude
Code scratchpad and `/dev/null`; everything else is refused for Write/Edit/NotebookEdit
and for the Bash forms the gate can read (redirections, `tee`, `cp`, `install`, `ln`,
`touch`, `mkdir`, `truncate`, `sed -i`, and since v5.3 `wget` (`-O -P -o -a`,
`--save-cookies`, `--directory-prefix`, the implicit cwd target, `-e` except a short
safe list) and `sqlite3` (`.output .once .save .backup .clone .log .trace .excel .open`,
`.shell`/`.system` refused, and the DB file itself unless `-readonly`); the move and
`dd` commands are banned for everyone already). `vim vi ex view vimdiff nvim ed patch
emacs` are refused outright for that agent: they take their program from `-c`, stdin or
the diff headers, so the target cannot be read from the command line, and Ponder has
Write/Edit. A write target spelled through a shell variable is resolved when the variable
got one literal value earlier on the same command line (`D=/tmp/x; echo > $D/f`, the same
resolution the gate already applies to a command name); an unresolved variable is still
refused. It is an allowlist because a list of closed places leaves out the one the
bypass finds. Named limits, not closed and not going to be chased: a write made inside
an interpreter payload (`python3 -c "open(..., 'w')"`, node writeFile), `git clone`,
`tar -x`, `unzip`, `rsync`, `curl -o`, `perl -i`, `awk -i inplace`, a variable chain
(`B=$A`), the `Bun.$` template shell.

INTERPFLAG1004 v2 (the interpreter's program arrives by another door), measured on the
live gate 4571448: every one of these passed with a deleting payload. Now judged: a
here-string (`python3 <<< "..."`, also `bash`/`sh`/`perl`/`node`/`ruby`/`php`/`bun`), a
process substitution (`python3 <(echo "...")`, `source <(...)`, `. <(...)`), a pipe
into an interpreter that names no program file (`echo "..." | python3`, `| bash`, no `-`
needed, also `/dev/stdin`), awk-family programs (`system()`, `"cmd" | getline`,
`print | "cmd"`), `bun -e/--eval/-p/--print`, `deno eval`, `php -B/-R/-E`, and every
`-e` / `-r` of a call that has several (`perl -e A -e B`). A shell that receives its
program this way is checked as a command line; any other interpreter's text goes through
the payload rules. Not closed: a program read from a file by redirection (`python3 < f`),
the `Bun.$` template shell, awk `-i inplace`.

v5.3 fix (found by Sam's fleet replay, 2026-10-05, one false block on a routine command of
a non-Ponder agent): `bash scripts/agent-msg.sh zola sam -` is a script FILE with an
argument `-`, not a shell reading its program from stdin, but the pipe check read the
`-` as the stdin marker and judged every quoted string on the left of the pipe as a
command line (an earlier `-H "$T"` became "command name from a variable"). Now a shell
counts as stdin-fed only when its options name no program file, and only the quoted text of
the command directly before the pipe is judged as that shell's program. The payload
rules still see the whole left side, as before. Known cost of the narrowing: a program
assembled across commands on the left (`x="rm ..."; echo "hi"; ...`) is not judged as a
command line unless it is in the last command before the pipe.

The hook also refuses an internal host or an IP literal to the Ponder session when
the switch is CLOSED (the built-in grant for the install's own dashboard,
`http://localhost:PORT/`, would otherwise have let a closed Ponder fetch it); a
public name keeps the old behaviour exactly.

What it does not close: a Bash route to the web through a binary the parser does
not know (a `chromium --dump-dom`, a script file; `yt-dlp`, `npx playwright`,
`git clone`, `git ls-remote`, `wget` and `pip download` are judged per agent since
2026-10-14 and are denied for Ponder, see "Shell routes to the web, decided per agent"
below); DNS rebinding on WebFetch (the hook resolves once, the tool resolves
again; only the browser, behind the proxy, connects to the address that was
checked); a nested `claude` launched with Ponder's config dir; the URL channel
itself, capped and audited but not closed (for HTTPS the proxy sees host and port
only, and the URL caps apply to the URL the agent asks for, not to what a page
requests afterwards); a browser that is not started through the launcher (the check
script catches the `.mcp.json`, not another way of starting one); WebFetch
redirects, which are not measured (the tool's own description says a cross-host
redirect is returned to the caller instead of followed, so the next fetch is a new
call through the hook; that is documentation, not a measurement here).

## Limits, stated out loud

This is a deny list, not a sandbox.

- **The localhost exception is why only `https://` is denied for `curl`.** The
  rule language has no negation and `deny` always beats `allow`, so "any
  `http://` host except localhost" cannot be expressed. A `*http://*` rule would
  also match `http://localhost:3420/...` and mute the whole fleet (memory,
  kanban, message queue, approvals all ride that URL).
- Still open, by construction: plain-http external fetches, an interpreter
  one-liner (`python3 -c`, `node -e`), and a URL hidden in a shell variable.
  Closing those needs a Bash `PreToolUse` hook that parses the command.
- Known collateral: an internal POST whose **double-quoted** payload quotes an
  `https://` URL matches the `curl` rule. Single-quoted payloads do not (the
  permission engine excludes single-quoted content). Use single quotes or
  `-d @file` for such a call.

## The command parser (`bash-egress-parser.mjs`): what it denies and the limits it will keep

The deny list above cannot read a command. `scripts/hooks/bash-egress-parser.mjs` is the PreToolUse
hook that does: it splits a Bash command into its simple commands, resolves the assignments and
loops it can see, and judges the destination of a `curl`. The sub-agents run it in the full mode;
the main agent runs it with `--git-only` (the force-push family only, because its own work reaches
api.github.com and friends from python heredocs).

Decided closed (the owner, Telegram 4196/4199, 2026-10-13), in the full mode:

- **A destination the parser cannot read is a deny, localhost included** (EGRESSPARAMEXP1009,
  EGRESSWRAP1009). `curl "$URL"` with `URL` set nowhere in the command, a parameter expansion
  (`${u#*|}`), a value computed by a substitution, `-K` / `--config`, and a command word that is an
  unset variable or a substitution on a line that carries an external URL all deny, because "I could
  not read it" must not mean "it was fine". `bash -c`, `sh -c` and `eval` bodies are judged in full,
  and a quoted command word is the command (`"curl" URL`).
- **A heredoc is judged when it runs as code, not when it is data** (EGRESSQUOTED1013, narrowed by
  the owner, Telegram 4457, 2026-10-13). Code is a heredoc that is an interpreter's or a shell's program
  (`python3 - <<'PY'`, `node <<EOF`, `bash <<EOF`, `bash -s`, `bash <<< '...'`), and also text that is
  handed on into one, whatever command reads the heredoc first. All of these get the full analysis:
  - a pipe: `cat <<EOF | bash`, through ANY stage that hands its stdin on (`grep`, `sed`, `tr`, `tac`,
    `dd`, `iconv`, `perl -pe`, `python3 -c '...'`, `tee`, ...): the pipe is followed through every stage
    except those that count, hash, compare or ship the text (`wc`, `sha256sum`, `md5sum`, `cksum`, `cmp`,
    `diff`, `curl`, `wget`, `nc`, `ssh`, `grep -c/-q/-l`, ...), which end the chain; `|&` and `2>&1` do
    not matter;
  - a subshell or a group, on one line or over several (the closing `) | bash` / `} | bash` may sit on a
    line after the heredoc's terminator): `(cat <<EOF) | bash`, `{ cat <<EOF; } | bash`,
    `(cat <<'EOF'` ... `EOF` / `) | bash`, `{ echo x; cat <<'EOF'` ... `EOF` / `} | bash`; a pipe INSIDE the
    group (`(cat <<EOF | bash)`) is followed too. A brace counts as a group only as a word at a command
    position (`${x}`, `{a,b}`, `xargs -I {}` are not groups);
  - `source /dev/stdin <<EOF`, `. /dev/stdin <<EOF` (also `/dev/fd/0`, `/proc/self/fd/0`);
  - a process substitution: `tee <<EOF >(bash)`, `>(exec bash -s)`, `>(timeout 5 bash)`;
  - `xargs ... bash -c {}`, when the command xargs runs is a shell with `-c` (a shell that only appears as
    a word on the line, `xargs -I{} echo bash {}`, is not one).
  A shell, python or node at the end of the pipe counts only when it has NO program of its own, and that is
  decided by its options, not by their shape: after `-s` or `-` the rest are positional arguments
  (`| bash -s arg1`, `| sh -s stable`, `| bash - arg1`); `-o NAME`, `-O NAME`, `+o NAME`, `--rcfile FILE`,
  python's `-W x` / `-X x` and node's `-r mod` carry a value of their own (`| bash -o pipefail`,
  `| python3 -W ignore`, `| node -r dotenv/config`); `-c` counts as a program only in a short option group
  (not the `c` in `--norc`); a plain word is a script file (`| bash run.sh`, `| python3 script.py`,
  `| node app.js`), and `-c`, `-m`, `-e` give the program its own text: those read the heredoc as data.
  Named limits of this rule, each pinned by a test (flip the test when one is closed):
  - perl, ruby, php and deno follow the OLD rule, not the option tables: a plain word after the command is a
    script file, so a value-taking option makes its value look like one and the text that reaches them through a
    pipe is read as data (`| perl -M strict`, `| perl -I lib`, `| ruby -I lib`, `| ruby -r net/http`, `| php -d display_errors=1`,
    `| deno run -A -` all pass). Their bare forms (`| perl`, `| ruby -`, `| php`) are judged;
  - `busybox sh` is not a shell word and passes;
  - the pass-through default has a price: a program in the MIDDLE of the pipe whose own output (not the
    heredoc) is what the shell reads is denied too (`| python3 gen.py | bash`, `| jq -r -R . | bash`,
    `| sqlite3 db | sh`), because the parser cannot tell it from a filter that hands the text on. No everyday
    false positive was found (the corpus replay shows none stricter), but it is a deny a reader may meet;
  - code run INSIDE a filter (`awk '{system($0)}'`, `sed e`, `while read l; do eval "$l"; done`) has no shell
    at the end to judge.
  A heredoc that is only data (`cat > file`, `tee`, `curl --data-binary @-`,
  `bash scripts/agent-msg.sh ... -`, a here-string to `cat`) is text and is not judged, a quoted
  `curl https://...` line in it included. The first version of this rule denied that quoted line in
  any data heredoc; it was withdrawn because what it caught was messages, memory saves and reports
  that QUOTE a curl line, not calls. The first version of the withdrawal let `cat <<EOF | bash` through
  as well (Sam, review 3528): the previous rule had denied those by accident, so that was a loosening of
  an approved state, and the pipe is followed now. The second version (Sam, review 3544) judged the
  options too coarsely and followed only a short list of filters; it is the paragraph above.
  Measured, replaying the fleet's transcripts (main agent and five sub-agents, 27245 distinct Bash
  commands, full mode, 2026-10-13): the new rules deny 5 commands the base `d6f5a723` allowed (main 3,
  sam 2, the other agents 0), and allow nothing the base denied. None of the 5 comes from the withdrawn
  rule: the two sub-agent ones are real external `curl` calls in a loop (one through a
  `${u#*|}` expansion, one over a URL list), and of the three main-agent ones, which run `--git-only`
  and are not affected, one is a PowerShell `Invoke-WebRequest` and two are a message to
  `agent-msg.sh` whose prose quotes a `bash -c` / `eval` wrapper at a command position (see the next
  paragraph). Against the previous version of this rule (`216e65e0`) the change is looser by 35
  commands, all of them quoted-curl heredocs (main 11, igor 17, sam 7), and stricter by none; the
  igor count may include probes written while building this change. The main agent's `--git-only`
  mode: 12 commands denied before and after in the corpus, none looser, none stricter (the pipe rule
  does reach it, `cat <<EOF | bash` with a force-push inside is a deny there now, but the corpus holds no
  such command).
  **What stays denied, on purpose:** a heredoc to a SHELL is always read as a command line, also when
  the shell is given a script (`bash scripts/agent-msg.sh ... - <<EOF`). A message to a script whose
  own text starts a line with `curl https://...`, or quotes a `bash -c` / `eval` wrapper at a command
  position, is therefore still a deny. That is the pinned "any shell heredoc is a command line" limit
  (`bash-git-force-push.test.ts`, `bash-egress-wrap.test.ts`); it guards the force-push family of the
  main agent too, so it was not reversed here. The way round for such a message: write the text with the
  file-writing tool, then send it with `--data-binary @file` or `... - < file`. Also still open, as on
  the base: an interpreter heredoc that shells out to curl without a network primitive the parser
  recognises (`os.system("curl ...")`, `subprocess.run`, node `execSync`, perl `system`) passes in
  both versions (measured with classify()), and heredocs nested more than four levels deep
  (`bash <<A` inside `bash <<B` ... five times) pass: the recursion stops at depth 4, measured the same on
  the base. Code that runs INSIDE a stage of the pipe has no shell at the end to judge and passes (HEX 3546):
  `cat <<EOF | awk '{system($0)}'`, `| sed e`, `| while read l; do eval "$l"; done`. A curl wrapped in a
  shell **function** or an **alias** (`f() { bash; }; cat <<EOF | f`), text kept in a variable and run later
  (`x=$(cat <<EOF); bash -c "$x"`), and a script written to a file and run by another command also pass,
  on the base as well.

**Named limits, accepted rather than patched** (no further fix round is planned for them; the real
closure is OS-level isolation of the agent's network, which is a separate decision):

- a substitution with **no URL in the command** whose output is run (`$(cat run.sh)`,
  `$(ssh-agent)`): it stays open on purpose, because denying every substitution would break the fleet;
- a **variable as the command name** when the line carries no external URL (`$cmd args`);
- **`xargs` / `parallel`** feeding a network command;
- a **script file** (`bash run.sh`, `python3 fetch.py`): the parser reads the command, not the file;
- **process substitution** as a program: `bash <(...)`, `source <(...)`. Measured open even for
  `bash <(curl -s https://...)`: the body of `<(...)` is not judged at all;
- shell programs fed by a **pipe or a here-string** (`echo ... | bash`, `bash <<< "..."`,
  `cat <<EOF | bash`) are judged when the URL is visible in the command text or in an assignment the
  parser can follow (measured: denied, also with a variable URL and with a command word that is a
  variable, and for a heredoc piped into a shell or interpreter, see above); they stay open when the
  program text itself comes from a file or from another command's output at run time. The heredoc
  pipe rule stops at a stage that counts, hashes, compares or ships the text
  (`cat <<EOF | curl --data-binary @- URL | bash` hands `bash` curl's reply, not the heredoc).

### Shell routes to the web, decided per agent (BYPASSPERAGENT1014, card 521f1f39)

Decided by the owner (Telegram 4554, 2026-10-14). Six shell routes to the web are not `curl` and not an
interpreter one-liner, and the name-and-shape list never knew them: `yt-dlp` (also `youtube-dl`,
`python -m yt_dlp`), `npx playwright` (any runner: `pnpm dlx`, `npm exec`, `bunx`, `pipx run`, `uvx`,
`playwright` itself, `python -m playwright`), `git clone`, `git ls-remote`, `wget`, `pip download`.

| agent | allowed | denied |
|---|---|---|
| igor | `git clone` and its routes (`fetch`/`pull`/`archive`/`submodule add`/`remote add` with a URL), `npx playwright` | the other four |
| willy | `yt-dlp`, `npx playwright` | the other four |
| zola, sam, ponder | nothing | all six |
| the main agent | not covered (it runs the hook with `--git-only`) | |

The table is `BYPASS_ALLOW` in `scripts/hooks/bash-egress-parser.mjs` and is pinned, element by
element, by `src/__tests__/bash-egress-bypass-per-agent.test.ts`. A change to it is an owner decision
and a change to that test.

**Inverted proof (the owner's standing rule 11, Telegram 4539).** The default is DENY. A call is silent in
exactly two cases: the agent is allowed that shape, or the call is PROVABLY without network. Nothing
lists attack spellings; it lists what is allowed.

- *Who.* The agent is read from the hook event's `transcript_path`
  (`<install>/agents/<name>/.claude-config/...`), never from the cwd: a `cd` changes the cwd, the
  transcript path does not change during a session. This is how `destructive-gate.py` and
  `ledger_lib` identify the agent. An agent that cannot be named (no `transcript_path`, a path
  outside the install's `agents/`, a malformed id) has NO allowance.
- *Provably without network.* `--version`, `-V`, `--help`, `-h` as the only arguments (redirections
  such as `2>&1` do not count as arguments); `command -v NAME` (it prints a path, it runs nothing);
  `git clone` / `git ls-remote` whose EVERY option is spelled out in an allowlist (valueless:
  `-q -v -n -l -s --bare --mirror --no-hardlinks --single-branch --tags --no-tags ...`; with a value:
  `-b/--branch -o/--origin --depth --separate-git-dir --revision --ref-format --reference` (`--template` is NOT here: a template directory can carry `hooks/post-checkout`, which runs after the clone);
  ls-remote: `-q -t -h --refs --symref --get-url --exit-code --sort`), with no abbreviation (git accepts
  `--bran`, the gate does not), the options in front of the subcommand limited to
  `-C <dir> --no-pager -P -p --no-optional-locks --no-replace-objects --no-lazy-fetch`, at most two
  positionals for a clone, and the remote a PATH or a `file:///` URL (absolute, `./`, `../`, `~`, or for
  `clone` a bare word without a colon). `-c` / `--config` / `-u` / `--upload-pack` / `--exec` /
  `--recurse-submodules` / `--filter` / `--bundle-uri` and anything unknown make the call
  non-clean. A loopback or private HOST (`http://localhost`, `git@localhost:x`, `ssh://10.x`) is NOT
  provably free any more: the proxy and ssh environment still apply (round 2, below). A bare word to
  `git ls-remote` is a named remote and therefore network, and so is a remote that is a variable or a
  substitution.
- Wrappers are read through (`env`, `timeout`, an absolute path, a quoted command word, `bash -c`,
  a shell heredoc, `$(...)`, a pipeline stage, a loop body); the agent travels into every nested
  judgement.

Measured on replay (the 16 501 distinct recorded sub-agent Bash commands in the agents' session
transcripts, agent taken from the transcript path exactly as the hook does, old = the live parser
before this change, every row kept): 16 364 commands are silent in both, none changed from deny to
allow, and the new denies are 57, every one a real call: `git ls-remote` (igor 47, sam 9; four of
those lines were already denied for a force-push elsewhere in the same line, only the reason text
changes) and `git clone` (zola 1). The first pass also flagged `command -v yt-dlp`, `wget --version 2>&1` and `command -v wget`, which are
not runs; they are now silent and pinned.
**Expected denials (HEX 3746: `git ls-remote` gets no allowance, the decision stays literal).**
`git ls-remote` is how igor and sam proved that a push arrived (`git ls-remote --heads fork <branch>`
against the SHA). The recorded commands hold 47 such calls from igor and 9 from sam; every one of them is
denied from the first restart-free call after this change reaches the install, and that is the intended
outcome, not a regression. Replacement paths, neither of which is one of the six shapes:
- `git fetch fork <branch> && git rev-parse fork/<branch>` (compare with the pushed SHA);
- `gh api repos/<owner>/<repo>/git/ref/heads/<branch> --jq .object.sha` (the token from the vault as in the
  push recipe; `api.github.com` is on the egress allowlist and the tool is `gh`, not `curl`).
If `git fetch` ever became unavailable to a sub-agent the question goes to the owner.

**Round 2 (Sam, 2026-10-14, msg 3767): what changed and why.** The first version kept a LIST of the
options that take a value, which is a deny-list: every option it did not know shifted the positional word
(`git clone --revision v1 URL`, and the abbreviation `--bran`, which git accepts), ran a command
(`-u 'cmd; git-upload-pack'`) or rewrote the "local" remote (`-c url.<external>.insteadOf=file:///fake/`)
and was judged network-free. Now the options are an allowlist (above). Shape recognition was widened where
it had read the first non-option word as the subcommand: `python3 -mpip` / `-Im pip` / `-X dev -m pip`,
`pip --proxy URL download` (an option this reader does not know makes ANY later `download` / `wheel`
count), `pip wheel`, `wget2`, runner `--package=` and the words of a quoted `-c '...'` body,
`corepack` as a runner, and the wrappers `setsid`, `watch -n N` and an input process substitution
`<( ... )` for every command the parser reads (not only these six shapes; older than this branch).

**Round 3 (Sam, 2026-10-14, msg 3804; the case lists cases1-3 are fixed after this round).** `git submodule add ./x` and `../x` are resolved
against the superproject's ORIGIN url, not the file system (with a GitHub origin `../../<anyone>/<repo>.git` is any repository), so
only an absolute path and `file:///` are local for a submodule. A runner's `-c` / `--call` body is a SHELL command line and is judged
like a `bash -c` body, not as a word list (`npx -c 'pla""ywright install'`, `'p=playwright; $p install'`). `python -m pip.__main__`
and `yt_dlp.__main__` are `pip` and `yt_dlp` (the first dotted component), and a runner in front of pip (`pipx run pip download`,
`uv pip download`) is the pip shape. A `git config` WRITE of `url.<x>.insteadOf`, `alias.<n>`, `remote.<n>.url` or `core.sshCommand` is the
git-clone shape (it has the effect of the `-c` form the allowlist already refuses), and a git subcommand that is not a git command,
given a URL literal, is the git-clone shape too (an alias: `git dl URL`). `git clone|fetch -h|--help` is silent (not for `ls-remote`,
where `-h` is `--heads`). `git submodule set-url <path> <url>` is judged like `submodule add` (only an absolute path or
`file:///` is silent), because it rewrites the URL the next `git submodule update` fetches.

Named limits (rule 11 (c): not closed here, not a reason to hold the card):
- a command word that comes from a substitution inside a QUOTED runner body (`npx -c '$(echo playwright) install'`) is read the same
  way as inside a quoted `bash -c` body, which is the older, named gap of a command word from a substitution;
- a clone of `file:///x` or a path is silent even when a git config written by something other than `git config` already rewrites it
  (`insteadOf` in a file written by another route, `git submodule update` of URLs already in `.gitmodules`);
- the routes to the same download without the word `clone` are judged as the `git clone` shape (HEX 3769,
  so igor keeps them and the others do not): `git fetch|pull <repo>`, `git archive --remote=<repo>`,
  `git submodule add <repo>`, `git remote add|set-url <name> <repo>`. They are silent for a repository that
  is already NAMED (`origin`, `fork`: a word with no `:` or `/`) or a local path, with the options on an
  allowlist as well (`-c`, `--upload-pack`, `--recurse-submodules`, an abbreviation = not provable). Still
  open, by name: `git config remote.<n>.url URL` followed by a fetch of `<n>`, `git submodule update`
  (fetches the URLs already in `.gitmodules`), `git fetch <name>` when the name was configured to an
  external URL by something else, and `git ls-remote` with a named remote (denied, HEX 3746);
- a function defined and called on the SAME line (`f(){ wget "$1"; }; f URL`) and any command inside
  it; `node node_modules/playwright/cli.js`;
- the environment is not read: `PATH`, `GIT_EXEC_PATH`, `GIT_SSH_COMMAND`, proxy variables exported in
  an earlier statement (a path or `file:///` remote does not use ssh or a proxy; `PATH` hijack is not
  addressed);
- the identity comes from the config root of the session; a child `claude` started with ANOTHER
  agent's `CLAUDE_CONFIG_DIR` would take that agent's allowance (using another agent's config is a fleet
  rule violation on its own, and `destructive-gate.py` rests on the same fact);
- a runner subcommand that merely names the tool (`npm uninstall playwright`) counts as the shape (a
  false deny, in the safe direction);
- the other network-capable binaries of the list above stay open (`pip install`, `npm install`,
  `ssh`, `scp`, `rsync`, `dig`, `docker run`, `go get` ...); only the six shapes are decided;
- a script FILE that runs one of the six, a program that reaches an interpreter through a pipe or a
  file, an alias or a function defined elsewhere, an argument builder (`xargs`, `parallel`,
  `find -exec`), and a command word that is an unset variable on a line with no URL in it;
- `python -c` / `node -e` that spawn the binary (`subprocess.run(["yt-dlp", ...])`);
- the hook fails open on an internal error, as before (logged to stderr).

A deny list that reads commands is always one spelling behind the shell. These are the spellings it
does not follow.

# What the URL gate does not cover

Both web controls are wired to **one tool**. `scripts/hooks/egress-gate.mjs`
runs as a `PreToolUse` hook with matcher `WebFetch`, and `wrapUntrustedFetch()`
(`src/prompt-safety.ts`) frames what that tool returns. Everything else that
brings the outside world into an agent's context is outside both:

- **`WebSearch`** -- result snippets are external text; no allowlist decided
  which sites they came from, and nothing wraps them on the way in.
- **Any MCP server that fetches** -- a browser server (playwright, chrome), a
  docs server, an API connector. The agent's own `curl` is denied by
  `BASH_EGRESS_DENY`, but an MCP server makes the request in its own process,
  where neither control can see it.

This is stated in a comment inside `egress-gate.mjs`. It was not stated here,
which is the wrong place for it to be missing: the comment is read by whoever
edits the gate, this file is read by whoever decides what to install. An
operator adding a browser MCP server was therefore adding an ungated,
unlabelled content path while reading that egress was covered.

The fleet ships no browser by default, so a stock install is unaffected. But
the fleet's own scaffolding expects browsers to appear (the largest profile is
described as "filesystem + playwright + chrome"), so this is a normal
deployment, not an exotic one.

## Why a browser payload is the sharper case

A fetched page cannot run code in the agent; it can only try to talk to it. A
browser payload arrives the same way -- except the browser it arrives through
holds live logged-in sessions, and the agent reading it has a shell, a
filesystem and outbound channels. The realistic attack is not an exploit, it is
a sentence: text on the page addressed to the agent rather than to the reader.

The defence against that is framing, not filtering: content the agent knows is
content cannot impersonate an instruction. `WebFetch` gets that framing from
the wrapper. A browser payload gets none.

## The opt-in envelope hook

`scripts/hooks/browser-content-notice.py` is a `PostToolUse` hook that wraps
browser / search results in an `<untrusted source="..." fetch-nonce="...">`
envelope before the model sees them -- the same framing `wrapUntrustedFetch()`
gives the `WebFetch` path -- scrubs forged security tags out of the payload,
names any injection patterns it matched (forged `<untrusted>` /
`<system-reminder>` envelopes, a pre-injected scrub sentinel, instruction
overrides, credential targets, exfil shapes) and appends the full payload to
`store/browser-content.log` for reading outside the model's context.

It is **not registered by default** -- an install with no browser gains nothing
from it. Operators who run a browser MCP server wire it themselves, in the
project `settings.json` or `settings.local.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__playwright__browser_.*|mcp__chrome.*|WebSearch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/hooks/browser-content-notice.py\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

### The shape rule, and the silent fallback behind it

`hookSpecificOutput.updatedToolOutput` replaces a tool result before it reaches
the model. It is not unconditional, and the condition is the important part
(measured 2026-09-20, Claude Code 2.1.278):

- **MCP tool**: a plain string replaced the result outright. The original never
  reached the model.
- **Built-in tool** (`WebSearch`): the replacement must match THAT TOOL'S
  OUTPUT SHAPE. A string was rejected -- `expected: object` -- the harness
  logged `... does not match WebSearch's output shape; using original output`,
  and the raw payload reached the model unchanged.

The rejection is an execution-error record, not part of the tool result, so
**from the model's side a broken envelope is indistinguishable from a working
one**: the content simply arrives unwrapped, as it always did.

That is why the hook writes two layers on every call and never treats the
first as sufficient:

1. `updatedToolOutput` -- the envelope. Shape-preserving: a string stays a
   string, MCP content blocks stay blocks with their original keys, a record
   keeps every key and only its free-text leaves are wrapped. A shape it
   cannot mirror confidently is left alone, because a rejected replacement
   leaves the RAW payload in context -- declining is the safer failure.
2. `additionalContext` -- the label, which cannot be shape-rejected. It states
   that a payload arriving WITHOUT an envelope means the envelope was rejected,
   so the absence is readable rather than invisible.

The label quotes nothing back. Its own text is trusted framing, so echoing a
matched line there would reopen the channel the hook exists to close. Pattern
names and counts only; the payload itself goes to the log.

`envelope_attempted` in the log records which shape the hook tried. It says
"attempted", never "succeeded": the hook cannot observe the harness's decision,
and a field that claimed success would be the most misleading line in the file.

# Email approvals consumed on the send path

At `email_send` level 2 an approval authorizes ONE letter: `content_hash` pins
it to the exact envelope and `consumed_at` makes it one-shot. The gate
(`scripts/hooks/email-approval-gate.py`) flips `consumed_at` itself, but only
for a send it can read in the command text (an MCP mail tool, `send.py --to`,
an inline mailer call). A tool that mails through a script on another host,
for example `ssh <host> 'tsx send-letter.mjs'`, is invisible to it, so its
approval stayed unconsumed and could authorize a second send.

Such a tool consumes on its own path, right BEFORE the letter goes out, and
sends only on a yes:

```bash
python3 scripts/approval-consume.py --id <approval id> --content-hash <anchor> \
  --consumer <tool name> --message-id '<id@your.domain>' || exit 1   # 0 = send now
```

`POST /api/approvals/<id>/consume` is one conditional write (approved,
`email_send`, unconsumed, the same anchor, inside `EMAIL_APPROVAL_WINDOW_S`,
1800 s like the gate). Of two attempts exactly one gets 200; the other gets
409 with a reason (`already_consumed`, `not_approved`, `hash_mismatch`,
`expired`, `wrong_category`). The row records the consumer and the Message-Id
the tool generated up front (`consumed_by`, `consumed_ref`), and every call,
refused ones included, leaves a row in `approval_events`. The gate and the
endpoint read the same `consumed_at IS NULL`, so a letter consumed by one path
is refused by the other.

A 409 means: do not send, and check the sent mailbox before deciding anything,
because the earlier attempt may already have gone out.

## The self-pace gate: the tmux write primitive, and the script an interpreter runs

`scripts/self-pace-gate.mjs` keeps a sub-agent input-driven: it must not type into a tmux pane, schedule its own turn, or
launch a second claude. For the tmux part the gate used to look for the literal word `tmux` plus one of four literal
subcommand names in one command segment. Measured offline on that gate (the pure `gateDecision`, nothing executed, 32 cases):
20 got through. Most were not interpreters: tmux's own aliases (`send`, `pasteb`, `run`, `send-prefix`, `source-file`,
`if-shell`, `respawn-pane`), the command or the subcommand held in a shell variable, an `env` / `xargs` / `-S socket` prefix,
a python list split over two lines, and a script file whose content nobody read. Adding names to a list would have left the
next alias open, so the gate now answers the question the other way round (the owner's rule: "cannot be proven = deny").

- **The word `tmux`.** In a Bash command it may appear only as (a) the command word with a READ subcommand (`list-*`,
  `has-session`, `display-message`, `capture-pane`, `show-*`, `info`; no `#(...)` format expansion, no chained second command,
  and none of tmux's own `-c` (runs a shell command), `-C` (reads commands from stdin) or `-f` (loads a config that runs commands))
  or (b) an argument of a plain reader (`grep`, `cat`, `ls`, `jq`, `echo`, `pgrep`, `which` ...) in a command with no executing
  sink (a pipe into a shell or interpreter, `eval` / `source` / `xargs` in command position, a command substitution that itself
  says tmux). Every other mention is a deny. Quotes are dropped before the word is looked for (`tm''ux` is `tmux` to bash). A file
  or module name (`src/tmux.ts`) and the `$TMUX` variable are not the word.
- **A script an interpreter runs.** `python3 x.py`, `bash x.sh`, `node x.mjs`, `source x.sh` ... may run only when the gate can
  name and read the file, **or the text the same command writes to it** (`cat > F <<'EOF' ... EOF; python3 F`, `echo '...' > F;
  bash F`, `tee F <<EOF`): a literal path, or a `$NAME` the SAME command set to a literal earlier (`S=/abs/dir; python3
  $S/x.py`), with a literal `cd` followed for a relative path. The interpreter may sit behind a wrapper (`env`, `timeout`,
  `stdbuf`, `nice`, `sudo`, `time`, `npx`, `uv run` ...); `python3 -m runpy x.py` takes the file. The code lines of the file may
  mention tmux only in the two forms above; a whole-line comment is skipped **per language** (`#` for shell, python, ruby, perl,
  php; `//` and a one-line `/* */` for node and ts: a `#x` in JS is a class field, a `*)` in bash is a case arm). A computed
  path (a variable from the environment or from a `for` loop, a glob, a substitution), an unreadable one (missing, a directory,
  over 4 MB) and a relative path after a `cd` the gate cannot follow are a deny with its own message. Inline code (`-c`, `-e`,
  a heredoc of another language, `bash -c '...'`) is read as text and is not affected. **The way out is always the same: give
  the path literally, or set the variable in the same command.**
- **The waiver, bound to the install's repo** (owner's decisions: HEX 3999 on Sam's review, widened by HEX 4015 so that a
  review worktree can run the suites it reviews). A file of that repo, in its main checkout OR in a LINKED WORKTREE of it (the
  same git common dir), that is byte-identical to the blob committed in the `HEAD` of the work tree it sits in, is not scanned
  for tmux: it went through the history, and the fleet's own daemon and hook scripts (`channels.sh`, `watchdog.sh`,
  `scripts/hooks/destructive-gate.py` ...) say tmux send in earnest; without this, 24 of the repo's 314 scripts were unrunnable
  for a sub-agent. An untracked or edited file is scanned, and so is a file of any other git repo, however it describes itself;
  so is any text the same command writes. **Named limits (measured 2026-10-14):** a commit made in the main checkout is
  stopped by the pre-commit `prod-tree-guard` (its overrides, `MARVEEN_PROD_COMMIT_OK=1`, `--no-verify`, `-n`,
  `core.hooksPath` and `SKIP_COMMIT_IDENTITY_GATE`, are refused by the destructive gate when spelled), but (a) the guard covers
  only the main checkout, so an agent can commit a driver in its OWN linked worktree and then run it, and (b) a route that MOVES
  `HEAD` without a commit is not stopped: a branch committed in a linked worktree and fast-forwarded into the main checkout
  (`git merge --ff-only`) runs no commit hook, and the destructive gate lets that spelling through. In both cases the blob is a
  HEAD blob and the waiver applies. **Only (b) is closed by card deecccda** (a git operation that moves the live checkout's `HEAD`
  and refs is refused to a sub-agent, by inverted proof). **(a) is a standing limit**: a commit in a linked worktree is ordinary
  development work (the main agent and the reviewers do it all day), so the card cannot refuse it without stopping that work; it
  stays open unless the owner widens the card's scope (measured 2026-10-14 by Sam, offline: a driver committed in a throwaway
  linked worktree went through the live gates, and this gate's decision allows running it, by an absolute path and by a relative
  path after a `cd`; nothing was executed).
- **There is no exemption for test files.** The round-3 one (`<dir>/__tests__/<name>.test.<ext>`) was narrowed to the install
  checkout's tracked files in round 4 and then changed nothing on the 3,901-command corpus, while it still let an EDITED tracked
  test, or one that was only `git add`-ed, through (a hole no hook stops). A test file that mentions tmux is judged like any
  script: the HEAD blob of its own work tree, or scanned. **The cost that remains:** a suite you have EDITED in a worktree and not
  yet committed (the destructive-gate suite, which says tmux send as test data) is refused when run; commit the change first,
  and it runs.
- **What is shell text.** A heredoc body is read as shell lines only when the shell takes its program from it. The fleet's
  message recipe `bash agent-msg.sh sam hex - <<'EOF'` runs a script FILE: the body is that script's stdin (a message that
  quotes `... | bash x.sh -` is text), and so is the body of `sh -s arg`. `bash <<'EOF'`, `bash -s`, `bash -` read it as code.
  `command -v NAME` / `command -V NAME` prints how a name resolves and runs nothing, so the names after it are not scripts.
- **Not closed.** A name that is never spelled `tmux` once the shell has joined quotes and escapes (built at run time,
  `'tm'+'ux'` inside a python string, a decoded string), a script that runs another script, a wrapper this gate does not know,
  `python3 -m pytest x.py` and the like (a module runner that imports a file), a binary run by a computed direct path, a file
  written by an EARLIER command and replaced before it runs, and a binary that drives tmux without the word on its own command
  line. The gate's own header says a sub-agent is not adversarial to its gate: this closes the casual routes, and the first
  review of this gate showed how many of those there were.
  **Also not closed, found by Sam in round 4 (the live gate and every earlier round let them through; the closing is card 0bc127fc):** an interpreter that reads its PROGRAM from stdin out of a literal, readable file. `python3 < /abs/drv.py`,
  `python3 - < /abs/drv.py`, `node < /abs/drv`, `bash < /abs/drv.sh`, `sh < /abs/drv.sh`, `bash -s < /abs/drv.sh`, and
  `cat /abs/drv.py | python3` (also with `python3 -`) are all allowed, while the same file as `python3 /abs/drv.py` is a deny:
  the gate reads the positional path and a heredoc body, not a `<` source or a pipe source. **Smaller, named:** `node --check
  F` on a file that mentions tmux is refused outside the install checkout (it runs nothing); `bash -euo pipefail <<'EOF'` reads
  `pipefail` as a script name (a cluster ending in `o` takes a value); a quoted text that contains `| bash x.sh` (an `echo`
  or a regex alternation such as `grep -E "a\|agent-msg.sh .* -"`) is cut at the pipe by the naive segmenter and refused.
- **The price, measured on 3,901 recorded Bash commands** (replay through each round's gate, nothing executed, 2026-10-14;
  corpus `replay-corpus-3901.json`, sha256 `34345662...`, working directory `<agents-workdir>`, install root
  `<install-root>`; every row kept for every head). Old (live) gate -> this gate: 315 newly denied, none newly allowed.
  Of those, 234 are an unreadable relative path (worktrees that no longer exist plus a real miss that the corpus cannot
  tell apart; Sam classed 12 of the 235 as a real write-and-run in one command), 28 a computed script path (mostly a
  `for t in ...; do python3 "$t"` loop), 4 a relative path after a `cd` into a computed directory, 7 a prose or source mention of
  tmux inside an interpreter body, a JSON payload or a quoted regex, and **42 `tmux-script`**: 41 of them the destructive-gate
  suite run in a review worktree (the exemption narrowing above) and 1 a temporary copy of it. Round by round: round 3 -> round 4
  is 42 newly denied and 1 newly allowed (a `command -v` row); round 4 first version -> final is 41 newly denied; removing the
  test exemption in round 5 changed 0 of the 3,901; widening the waiver to linked worktrees (HEX 4015) turned 20 denials back to
  allow, 19 of them the destructive-gate suite run in a review worktree, so against the round-3 gate it is 22 newly denied and 1
  newly allowed, and against the live gate 295 newly denied (234 unreadable path, 28 computed, 7 plain tmux mention, 4 `cd`, 22
  `tmux-script`). Of the 41, 22 stay refused: runs in development worktrees where the suite had been edited, or whose command text
  itself carries tmux (the worktree states have moved on since, so they cannot be told apart afterwards). (The earlier sentence here, that round 4 only removes denials, was wrong:
  the replay had not been re-run.) Run through the gate one by one as `<interpreter> <absolute path>` (the live checkout's
  1,394 tracked py / sh / mjs / cjs / js / ts files, nothing executed, install root set to that checkout): 0 refused, the same as
  the old gate; this covers the install checkout, NOT the linked worktrees. About 14 ms per file
  on average (the git calls run only for a file that mentions tmux).

# A sub-agent may not move the install's main checkout HEAD or refs (card deecccda)

The live install (`PROJECT_ROOT`) is a git work tree, and the service runs the
code that sits in it. A sub-agent that moves that checkout's HEAD or the branch it
has checked out changes live code without any deploy approval: `git commit` or
`git merge --ff-only` inside it, `git reset`, `git checkout`, `git update-ref
refs/heads/<checked-out branch>`, or the same done from a linked worktree, because
a linked worktree shares the refs. The gate rule in
`scripts/hooks/destructive-gate.py` (`_head_move_gate`, called from `_check_git`)
closes this for sub-agents. It does not apply to the main agent, whose identity the
gate cannot tell apart from an unidentified caller (see Limits).

## The rule: allow only what it can prove

For a sub-agent (`OWN_AGENT` is set) a git call is silent only when the gate can
**prove** it does not move the main checkout's HEAD or its checked-out branch:

- a read subcommand from a closed list (`HM_READ`: `log`, `diff`, `show`,
  `rev-parse`, ...), or a subcommand that cannot move a HEAD (`HM_NOMOVE`: `add`,
  `fetch`, `push`, `worktree`, `tag`, ...), with the write forms of `config`,
  `push`, `fetch`, `stash`, `worktree`, `reflog` screened separately;
- a HEAD-moving subcommand (`HM_MOVE`: `commit`, `merge`, `reset`, `checkout`,
  `switch`, `rebase`, `cherry-pick`, `revert`, `am`, `pull`, `bisect`, `branch -m`)
  only when its target directory is a literal that resolves to a linked worktree,
  a foreign repo, or a place outside the install, never the main checkout;
- a ref written by name (`update-ref`, `symbolic-ref`, `branch <name>`, `branch -d`,
  `branch -f`, `checkout -b`, `worktree add -b`, `fetch <src>:<dst>`) only when the
  name is not the branch the main checkout has checked out, and not `HEAD` when
  the target is the main checkout. The checked-out branch is read from the install
  at call time, not hardcoded;
- taking that branch over is refused as well, because a linked worktree whose HEAD
  is the main checkout's branch moves the live HEAD with every commit. What a
  `checkout`/`switch` selects, the second word of `symbolic-ref`, and the branch
  `worktree add` will check out (its commit-ish, or without one the branch named
  like the directory, git's own convenience) are screened like a ref written by
  name, whatever flags (`--ignore-other-worktrees`, `--force`) come with them.

One condition covers all of them. A ref name is accepted only if the gate can read
**the words it came from**, as typed:

1. Every word a ref name comes from must be a plain literal: letters, digits and
   `. / + @ % = , : ~ ^ -`. A variable, `$(...)` or backticks, a glob, a brace
   expansion, an escape, or anything else that could expand to something else, or to
   nothing, is unprovable and denied. Quoting does not change that: the gate reads
   what the shell will pass on (a single-quoted `'main'` is `main`), but a quoted
   `"$B"` is still a variable. The words are: the first positional word of
   `checkout`/`switch` (so `$NOPE main` is denied, because `main` would become the
   branch), the value after `-b`/`-B`/`-c`/`-C`, the names of `branch`, `update-ref`,
   `symbolic-ref` and `stash branch`, the destination of a `fetch` refspec, and,
   for `worktree add --force`, every positional word (one that expands to nothing
   moves the others). A path or a start point is not one of them.
2. A command substitution after the call (`git checkout ... $(echo main)`) can supply
   words the gate never sees: denied.
3. Redirections are understood only in a short whitelist (`2>f`, `&>f`, `>f`, `<f`,
   `2> f`, `>> f`, `2>&1`); the word an operator takes is not an argument. Any other
   form (`>&`, `{fd}>`, `<<<`, ...) is unknown: it is dropped together with the word
   it takes and the call is denied where a ref name is involved. A comment ends the
   argument list.
4. `checkout <ref> -- <paths>` is a file restore only if at least one literal path
   follows the `--`; otherwise (empty, a variable, a glob that may match nothing)
   it is a branch switch and is screened like one.
5. `worktree add` takes the branch under `--force` only. Without `--force` git
   itself refuses a branch that is checked out elsewhere (measured, git 2.53). So
   the call is silent only if its flags are provably plain, from a closed list
   (`-b`, `-B`, `--detach`, `--orphan`, `--lock`, `--reason`, `--no-checkout`, `-q`,
   `--track`, ...); everything else, an abbreviation such as `--forc` or `--for`,
   `-f`, `-ff`, an unknown option, counts as forced.
6. `checkout -` and `@{-N}` name the previous branch, which only the target's
   reflog knows: the gate resolves it there (`rev-parse --abbrev-ref @{-1}`) and
   screens the answer; if it cannot, it denies. `worktree add` resolves its `-`
   the same way.
7. A fetch destination with a literal `refs/remotes/` or `refs/tags/` prefix and no
   `..` cannot become `refs/heads/<name>`, whatever follows the prefix: silent.
   Any other destination is a ref name and follows rule 1. `heads/<name>` is read as
   `refs/heads/<name>` for ref writers and fetch destinations (measured), not for
   what a `checkout` selects (git resolves `checkout heads/main` to a detached HEAD).
   A name containing `..` is denied.

A start point is not a take-over (`checkout -b feat main`, `checkout --detach main`,
`worktree add -b feat <p> main`, `branch -f <name> <start>`). A linked worktree that
already sits on the main checkout's branch counts as the main checkout.

Anything else is denied loudly, with a message that tells the agent what to make
literal (`cd <worktree> && git ...` in one chain, or `git -C <worktree> ...`).
`git -C <dir>` is resolved the way git walks it, physically: a `..` after a symlink
is taken from the link's target (a lexical cut would let `<link to the install>/..`
look like a place outside). A `cd` has two possible landings, because a shell may be in physical mode
(`set -P`, `set -o physical`, `SHELLOPTS`, a shell started with `-P`, an option set by
`eval` or a sourced file, any spelling the gate would have to recognise): `cd L/..`
lands at the parent of the link's target in physical mode and at the parent of the
link in logical mode. The gate follows both and allows the call only if every
possible landing is clear of the install. It does not try to detect how the mode was
set. (`CDPATH` changes where a `cd` lands in a way the gate cannot enumerate: it gives
up.)
Unprovable means: a computed path, an unknown cwd, `pushd`/`popd`/`cd -`/`env -C`,
`--git-dir`/`--work-tree`/`GIT_DIR`, a `-c` key outside a closed list (an alias or
`core.worktree`/`hooksPath` could rewrite the command), an unknown git option or
subcommand, and `git filter-branch`/`git replace`. A `cd` that may fail
(the target does not exist yet, or exists but cannot be read and entered) keeps the
old directory possible; with `;` or `||` the next git call may run there, with
`&&` it does not.

The development flow stays open: work in a linked worktree commits, resets and
branches freely. `refs/remotes/*` is not protected (reviews fetch PR heads under
it).

## Named limits

- **A committed driver is not inspected.** A script committed in a linked worktree
  and then run, or code an interpreter reads from stdin, can still call git
  against the main checkout; the gate sees the command line, not the program
  (the stdin gap is card 0bc127fc).
- **The gate judges the state before the command.** In `cd <main checkout>;
  git worktree add <new>; cd <new>; git cherry-pick ...` the new directory does
  not exist yet when the line is judged, so the `cd` into it could fail, and
  after a `;` the call would then run in the main checkout: denied. Chain the steps
  with `&&`, or give the later git call `-C <new>` as a separate command.
- **The payload of an interpreter is not seen.** A git call rebuilt from an
  interpreter's argument list is judged on its literal words only; a ref name
  that was not literal makes it deny.
- **Live code without a HEAD move is out of scope.** The rule covers HEAD and refs.
  `git restore --source=<branch> --worktree -- .` and `git read-tree -u --reset
  <branch>` put another branch's files into the live work tree without moving any
  HEAD, and a plain write to `<install>/.git/HEAD` is not a git call at all (that
  gap is older than this rule). The main agent decided (2026-10-14) that this is
  not part of this rule: a plain file write (Edit/Write) reaches the live tree
  the same way, so a git-command pattern cannot close it. It is a separate class
  with its own card.
- **Programs an unknown executable reads from somewhere other than `-c`.** The string after a
  `-c` style flag is read as a shell program whoever the command is (card 7fd3134e, below).
  What is still not read: a program an unknown executable takes from stdin (`dash <<EOF`,
  `echo '...' | dash`; card 0bc127fc), from a file it is handed, or as a bare argument
  without `-c` (`ssh host '<command>'`, `watch '<command>'`).
- **An unidentified caller is the main agent.** The gate identifies a sub-agent
  from its transcript path; a caller it cannot identify is treated as the main
  agent and not restricted. That is deliberate (the main agent ships code) and it
  is the weakest point of this rule.

## What it cost (measured 2026-10-14)

Replay of the 3,901-command corpus (sha256 `34345662...`) through the live gate
before and after, nothing executed, every row kept for both heads:

| caller, cwd | denied before | denied after | newly denied | newly allowed |
|---|---|---|---|---|
| main agent (unidentified) | 600 | 600 | 0 | 0 |
| sub-agent, cwd in a sibling work directory (outside the install) | 593 | 601 | 8 | 0 |
| sub-agent, cwd `<install>/agents/<name>` (inside the main checkout) | 593 | 641 | 48 | 0 |

The 8 in the work-directory view: 4 are real (a `commit` or `checkout` after a
`cd` into the main checkout), 4 are the `;` chains described under the named
limits (`git worktree add`, then a `cd` into the not-yet-existing worktree).
The 48 in the agent's own directory (inside the main checkout) split into 4 real
(`commit`, `checkout` against the main checkout after a `cd` into it), 4 of the `;`
chains above, and 40 whose `cd` target no longer exists on this disk (deleted
worktrees): at the time they ran, the target existed and the gate would have proven
it. Sam re-measured this with the missing targets treated as existing (outside the
install): 44 of the 48 then pass. The 4 that stay denied are the real
`cd <main checkout> && commit/checkout` calls; the 4 `;` chains pass in that
approximation, because the not-yet-existing worktree they create is treated as
existing too (run for real they would still be denied). That is an approximation,
not a rerun with the targets recreated.

## How it was checked

`scripts/__tests__/destructive-gate.test.py` (section `deecccda`) builds a
throwaway install, a linked worktree and a foreign repo and asserts the verdict
for each case above. 77 one-place mutants of the rule (gate switched off, a check removed, every
element of each kept set mutated: the redirection forms, the closed flag list, the
literal-word conditions, both `cd` landings) were run against that test with a
throwaway runner that is not part of the repo: 75 fail it, 2 do not, and both are
equivalent. One: an unknown git option reaches the later "unknown subcommand" refusal, so
removing the earlier branch only weakens the message. The other is the `CDPATH` give-up,
below.

An independent re-run of 15 of these mutants (by the reviewer, round 5) killed 14. The
survivor was the `CDPATH` give-up: no test failed without it. It is a second lock, not the
first: the base gate's hook-tamper rule already refuses every command line that mentions
git together with `CDPATH` (measured with the give-up removed: `CDPATH=/x cd scripts &&
git reset ...`, `export CDPATH=/x; cd ...; git ...` and the absolute-path form are all still
denied, by that rule), so for a git line the give-up cannot be reached. Test cases were added
afterwards for the combined behaviour; they do not isolate the give-up, and the mutant
that removes it stays alive as a second equivalent mutant. That addition was not part of
the reviewed head.

# A `-c` string is code, whoever the command is (card 7fd3134e)

The gate used to recognise code strings by the NAME of the interpreter in front of them
(`INTERPRETERS`: `bash`, `sh`, `zsh`, `python`, `node`, ...). `dash -c 'git reset --hard
HEAD'`, `ksh -c ...`, `busybox sh -c`, `su -c`, `script -qc`, and a quoted or escaped name
(`"bash" -c`, `'bash' -c`, `ba''sh -c`) were not read at all: a sub-agent in the main checkout
could move HEAD through any of them (measured 2026-10-14, base and head alike).

The rule is the other way round. The word after a `-c` style flag (a short option cluster of
ANY length with a `c` ANYWHERE in it: `-c`, `-lc`, `-ec`, `-ce`, `-cex`, `-eeeeec`; or `--command`) is a shell program,
whatever the command is. The flag is the one outside quotes; `-c1-5` (a digit after the c) is
not a flag. The word is found past blanks, options, `--` and the value of `-o`/`-O`
(`dash -c -e '...'`, `dash -c -o errexit '...'`: the shell's own rule, the first non-option
word is the program). It is then one of three things, and only the first two pass:

- ONE fully quoted string: its content is checked as a shell program (`check_bash`);
- a plain word of letters, digits and `._/=:@%+,~-` (`wc -c f`, `ls -c dir`): a single word with no
  quote, escape or expansion is at most ONE command name or file name, not a command line. (`dash -c ./x.sh` runs the file `./x.sh`: that
  is the named limit "a script file is not read", below, not something this rule proves);
- anything else (`dash -c git\ reset\ ...`, `dash -c $'...'`, `dash -c${IFS}'...'`,
  `dash -c \<newline>'...'`, a concatenation such as `'a'"b"`): not provable, and the whole
  command is DENIED.

No list of those shapes is kept; the test is the three-way split. (Round 1 of Sam's review,
msg 4142, found the first head read only a quoted string directly after the flag.)

The string is not read as code in exactly three cases, and each of them holds only for a tool the gate has anchored to the system tool of that
name (round 3 of Sam's review, SEVERE 1: the first two heads looked at the NAME, so a `python3` that is a symlink to `/bin/sh`, `/tmp/x/python3 -c`,
or `PATH=<dir>:$PATH python3 -c` ran a shell program the gate never read). The anchor (`_anchored_tool`): a plain name or a path in `/usr/bin/`,
`/bin/`, `/usr/local/bin/` without `..`, AND no `PATH=` assignment among the leading assignments, `export` / `env` / `declare` words of any
statement of the command. Everything else is not anchored, and its `-c` string is read as a shell program.

NAMED LIMIT of the anchor (Sam, round 4, SEVERE 1; measured 2026-10-15): a PLAIN name is accepted as "whatever the session's PATH finds first",
and that is NOT proof of the system tool. On this install the PATH has directories the agent can write in front of or next to `/usr/bin`
(`~/.bun/bin` stands before it, `~/.local/bin` is on the PATH, and `node` resolves to `~/.local/bin/node`), so an executable named `python3` placed
there would be taken for python, and its `-c` string would not be read as a shell program. The path forms (`/tmp/x/python3`, a PATH assignment) are
closed; this one is not. Closing it in code (resolve a plain name against the system binary directories only, or deny it when a writable directory
precedes them) would read the `-c` string of every `python3 -c` of such a session as shell, a price to be measured and decided: its own card, not a
round of this one. The three cases:

- the COMMAND of the segment is a known interpreter under its plain name and a script name stands
  between it and the flag (`python3 tool.py -c "x"`, `pytest -c "conf"`): the `-c` is the
  script's argument. "The command" is the first word after env assignments and the wrappers
  `env`, `time`, `nice`, `nohup`, `timeout`, `command`, `exec`, `xargs` with their options
  (and the values of those options: `env -u sh dash -c` runs dash, not sh). The first head looked
  for the interpreter name ANYWHERE in the segment, so `env -u sh dash -c` and
  `su -s /bin/sh -c` were exempt;
- the command is a non-shell interpreter (`python`, `node`, `bun`, `perl`, `ruby`, `php`): the string after its `-c`/`-e` is code of ANOTHER
  language and is read by the interpreter-specific logic, not as a shell program. (Read as shell, Python code has unbalanced quotes: a
  head that did so made the double-quote walk of card f4649c5d deny 30 valid commands of the real corpus.) The shell family `bash`,
  `sh`, `zsh` and every unnamed command get the generic read;
- the command is one of a closed list whose `-c` FLAG is a count, a format, a byte count, a cookie
  file, an archive-create flag or a config assignment, and not a shell program: `grep`, `egrep`, `fgrep`, `rg`, `ag`, `stat`,
  `cut`, `head`, `tail`, `curl`, `sort`, `wc`, `ls`, `uniq`, `diff`, `git`, `tar`, `du`, `sqlite3` (a `-column` is no `-c` cluster;
  `du -ch` is a total). The list says only that THEIR `-c` flag word is not a program. A list of well-defined tools, not of dangerous
  shapes. It does NOT say that the tool cannot run a program through another option, and three of them can: `git` (`-c core.fsmonitor='...'`,
  `core.pager`, `core.sshCommand`, `core.editor`; Sam 4161, closed by card ff9a0528), `tar` (`-I` / `-F` / `--use-compress-program` /
  `--to-command` take a program: `tar -cI 'cmd' -f x.tar` runs it, Sam 1763) and `sqlite3` (`-cmd '.shell cmd'`, `.system`, `.read |cmd`
  run a command, Sam 1763). The tar and sqlite3 forms are NOT read by this rule and an earlier version of this paragraph said they were
  not programs; they are the class "an option VALUE that runs a program", card 0d194126 (with `sort --compress-program`, `rg --pre`,
  `ag --pager`, `git rebase --exec` ...). The name must be PROVEN as above: `./grep -c '...'`, `/tmp/x/grep -c '...'` and
  `PATH=/tmp/x grep -c '...'` are scripts of the caller's choosing and are read as code.

A flag inside a quote (`echo "dash -c '...'"`) is text, not a flag.

Price. Corpus 1, the 3,901-command replay (nothing executed, every row kept for three
views), measured on the FIRST head: the main agent 600 -> 600 denials, a sub-agent in its work
directory 601 -> 601, a sub-agent in its own directory 641 -> 641, none newly allowed. That
head did not yet deny the unprovable word, and it ended the flag at a `c` that had to be the last
letter; it says nothing about this head.

Corpus 2, this head, final verdict (`check_bash`, the main-checkout view, previous head 34546efe against this one, in process):
ALL 31,200 unique Bash commands of the agents' transcripts (main agent, `~/.claude/projects`, every `agents/*/.claude-config`).
29,763 allowed on both, 1,410 denied on both, 11 newly denied, 9 newly allowed. Of the 11, 6 are the unprovable word itself (a
command line that contains `-c` followed by something that is not a plain word, mostly program text that quotes such a line) and 5 are
a `$var` command name inside a `-c` string: the rule the unquoted text always met. The 9 newly allowed are all `wc -lc "$S"`, a false
denial of the first head that the `wc` entry on the closed list removes. (The measurement before `du` and `sqlite3` joined the list
gave 18 newly denied: `sqlite3 -column -header $DB ...` and `du -ch $LOGS` read as `-c` clusters. Before the non-shell interpreters
were left to their own logic it was 40: Python code read as shell. Counted by flag matches rather than by final verdict, the figure
was 66 and then 74; that counts commands another rule had already denied, and is not the price.) Sam's own count on his run was 27 new
and 9 newly allowed on an earlier head; the difference is the head and the corpus snapshot.

Round 4 (the anchored tool, Sam 1763 SEVERE 1), final verdict (`check_bash`, the main-checkout view, in process), the previous head 2bd6c09d
against this one over ALL 31,880 unique Bash commands of the transcripts: 30,433 allowed on both, 1,447 denied on both, **0 newly denied, 0
newly allowed**. No recorded command used a `-c` with a non-system tool name, a path outside the system binary directories or a PATH
assignment next to a `-c`, so the anchoring costs nothing on the real corpus; the 12 and 9 of the previous paragraph are the same set.

Named limits (not shapes to be closed): the first word after the flag is the program, so a
shell that takes the program from somewhere else (stdin, `-s`, a script file, a here-string
`dash <<< '...'`, card 0bc127fc) is not read here; `bash -c -e` is now read, and so is every
known interpreter whose `-c` comes before its script name.

The mutation set (every wrapper of the table dropped in turn, every name of the closed list,
the cluster width, `--command`, the flag lookahead is an optimisation and has no effect,
both exemptions, the std-bin path test, the value of `-o`, `--`, option skipping, the
unprovable branch, the plain-word class, the concatenated-quote check, the command anchoring):
all fail the test except the equivalent ones named here; the runner is not part of the repo. Round 4 added 13 mutants of the anchoring
(the plain-name test, the path test, `..`, the std-bin requirement, the PATH check, `PATH+=`, each kind of leading word, the statement
splitting, and each of the three exemptions): 12 fail the test. The survivor, "plain-name test dropped", is equivalent: a command word that
is not a plain name cannot equal any name on the closed list or in the interpreter table, so the exemptions do not fire for it anyway
(the test stays as a defensive line).

Named limits of the options this rule does NOT read (an option VALUE that runs a program, card 0d194126): `tar -I` / `-F` /
`--use-compress-program` / `--to-command`, `sqlite3 -cmd '.shell ...'` / `.system` / `.read |cmd`, `sort --compress-program`, `rg --pre`,
`ag --pager`, `git rebase --exec` and the like. They were wrongly described as "not programs" in an earlier version of this section.

# A command substitution inside double quotes is code (card f4649c5d)

`X="$(rm -rf <dir>)"` and ``echo "`rm -rf <dir>`"`` ran the command and the destructive gate let them through, while the same
substitution without the quotes was denied (Sam 4128, measured on the live gate). The gate cut quoted text out as prose before
it looked for commands, and a double-quoted string was prose; but in a double-quoted string the shell expands `$(...)`,
`` `...` `` and `$((...))` BEFORE the command it quoted them for runs.

The rule is the inverted one. `dq_subst_programs(cmd)` walks the command (heredoc data and comment lines blanked as before; a
single-quoted string and `$'...'` are literal and are skipped) and, for every double-quoted region, cuts out the program text of
each `$(...)`, backtick pair and `$(( ... ))` (also `${X:-$(...)}` and nested double quotes inside a substitution). Each
program goes through `check_bash` as a command line of its own, exactly as the same text would have outside the quotes. Where
the scanner cannot cut a region out with certainty, it does not guess: the whole command is denied. That covers an unclosed
quote, an unclosed `$(`, nested backticks, a quote inside `${...}`, and a `case` statement inside `$(...)` (its unbalanced `)`
would end the substitution early).

## The heredoc opener (Sam 4152 / 4157 / 4163: the main path too)

The same family hid on the MAIN path: a `<<WORD` that bash reads as text (`echo "<<EOF"`, `echo '<<EOF'`, `# <<EOF`, `git commit -m "x
<<EOF"`) opened a "heredoc" for the gate's lexer, and the lines after it were blanked as its body, a destructive command on them
included. One shared lexer (`_heredocs`, with `_opener_is_real`) now decides, for the body ranges and the foreign-code ranges alike.
Inverted proof: an opener counts only if it is provably one, and the lines after any other `<<WORD` are commands that go through the gate
like any others (stricter, never cut out). The proof is the INNERMOST LEXICAL CONTEXT at the opener (`_in_command_context`, a stack
walked from the start of the command, round 3 of Sam's review, SEVERE 1): bash reads commands at the top level, inside `$( )`, inside a
backtick pair and inside a `( )` group, and reads `<<` as plain text inside a double quote, a single quote, `$'...'`, `${ }`, `$(( ))`,
`$[ ]`, a `#` comment and after a backslash. The contexts nest, so `echo "$(echo "<<EOF")"` (a double quote inside a substitution inside
a double quote), `X=$(echo "<<EOF")`, ``echo `echo "<<EOF"` ``, `echo \<<EOF`, `echo $[1<<EOF]` and `echo ${x:-<<EOF}` are all text, while
`git commit -m "$(cat <<'EOF'` (a substitution inside double quotes, the opener directly in the substitution's command context) is a real
heredoc and is unchanged. A here-string `<<<` and a shift inside `(( ))` are not openers either. The earlier heads counted brackets and
quotes on the opener's line, and that counting took the nested shapes for real openers: the next line's plain `rm` was blanked as a
"body" and ran (bash and dash, measured by Sam). The earlier sentence here, that where the lexer errs a real heredoc is read as
commands "never the other way", was therefore false for those heads. It holds for this one only to the extent the tests and the
mutants below show: the walk answers False wherever it cannot tell (an unterminated quote, a `((` still open), and `case` patterns inside
`$( )` (an unbalanced `)`) are not parsed (named limit).

The body of a heredoc with an UNQUOTED delimiter (`<<EOF`, also fed to `python3` or `bash`) is expanded by the shell exactly like a
double-quoted string, so its `$(...)` and backticks run: `cat <<EOF` / `$(rm -rf <dir>)` / `EOF` was not looked at. The body is
walked in the same way as a double-quoted region now. A quoted delimiter (`<<'EOF'`, `<<"EOF"`) keeps the body literal.

## Price

Measured on the chain head (this card on top of card 7fd3134e's last head), final verdict (`check_bash`, the main-checkout view), the
previous head against this one, in process, over ALL unique Bash commands of the agents' transcripts (main agent, `~/.claude/projects`,
every `agents/*/.claude-config`): 31,966 commands (round 3 of this card, measured against card 7fd3134e's round-4 head 668c7d5e).
30,500 allowed on both, 1,447 denied on both, 19 newly denied, 0 newly allowed. Of the 19: 7 are "cannot be cut out with certainty" (an
unclosed quote, an unclosed backtick, a quote inside `${...}`, long heredoc scripts and `node -e` programs with deep quoting), 5 a command
name that comes from a variable inside a quoted substitution (`"$($c --version)"`), 5 a `$(( $(date +%s) - 1 ))` style arithmetic in quotes
that the same text without the quotes always met, 1 a non-built-in git sub-command, 1 a `.env` read. Every one is a denial in the safe
direction, 0.06% of the corpus. The earlier figures (3,901 commands, 3 new denials; 31,164 commands, 27 new) were a smaller or older set
and are superseded; round 3 changes how an opener is recognised and is what the 0 "newly allowed" confirms: no recorded command became
quieter.

The gate's own test: 1,595 cases with the card-7fd3134e rows (1,430 of those), 0 failing. Mutants (28 of the double-quote walk's and the
opener lexer's branches; runner not in the repo): the escape, the double quote's close, `$(( ))` and its inner parentheses, `$[ ]`, `${ }`,
the comment, the `( )` group, the single quote and its unterminated answer, the backtick, `$'...'`, the final answer, the three command
contexts, the here-string and `((` pre-checks, and the old counting version put back: 23 fail the test. The 5 that survive are covered by
a second defence that gives the same answer: the `(( ... ))` pre-check of `_opener_is_real` and the `$((` arithmetic context of the walk
(its start, and its inner parentheses) cover each other, so removing one leaves the other; a `( )` group inside a `$( )` that sits in
double quotes changes nothing because the text inside double quotes is read as prose by the outer scan and as its own program by the
substitution walk; and the `$'...'` branch could only be told apart by a row (`echo $'a\'<<EOF'`) that hits the separate quote-map hole named
below. They stay in the code as defensive lines. The earlier
two "unclosed double quote / unclosed `$(` -> deny" lines are equivalent for the same kind of reason (the whole gate denies an unclosed
quote on another path first).

Found while writing the rows, NOT closed here and NOT a heredoc matter (card f8acbcb4, measured on the live gate): `echo $'a\'b'` followed
by a new line with a destructive command passes, because the gate's global quote map does not know that `\'` does not end an ANSI-C
string, so the rest of the command is read as quoted prose.

## Named limits

- A substitution is cut out inside double quotes and unquoted-delimiter heredoc bodies. `eval "$(echo <cmd>)"`, `eval $(...)`,
  `eval` + backtick and `source <(echo ...)` run the OUTPUT of a substitution, a different class: card 30500dad.
- `case` inside `$(...)` and nested backticks are denied, not parsed.
- A `-c` program is checked together with this walk only on the chain (card 7fd3134e's last head under it).
- The context walk (`_in_command_context`) does not parse `case ... esac` inside `$( )` (a pattern's `)` closes the substitution early in the
  walk), `[[ ... ]]` or `coproc`; where it errs, the error is measured by the tests above, not claimed in general. A heredoc opener
  behind such a construct may be read as text (stricter) or, for the unbalanced `)` of a `case` pattern, as a command context.
- Not measured: the run semantics of `dash`/`zsh` for these shapes (only `bash` was used for proof).

# Git config values that run programs (card ff9a0528)

`git -c core.fsmonitor='touch /tmp/x' status` was rc 0 on the destructive gate (Sam 4155, HEX 4160). git RUNS the value of a whole class
of config keys as a shell command line whenever the matching subcommand runs: `core.fsmonitor`, `core.pager`, `pager.<cmd>`,
`core.editor`, `sequence.editor`, `core.sshCommand`, `diff.external`, `gpg.program`, `credential.helper=!prog`, an `alias.x=!prog`, and
the environment variables `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_PAGER`, `GIT_ASKPASS`. The gate read the value as text, not as a
program. Measured on the previous head, all rc 0: the keys above through `-c`, through `--config-env=KEY=VAR`, and a persistent
`git config [--global] core.pager 'prog'`.

The rule is the inverted one, not a list of the dangerous keys. A config key handed to git on the command line (`-c`, `--config-env`) or
written with `git config` is silent only when the gate can prove it runs no program:

- it is on the closed list of INERT keys (any literal value): `user.name|email|signingkey`, `commit.gpgsign`, `tag.gpgsign`,
  `core.quotepath|autocrlf|safecrlf|filemode`, `color.*`, `advice.*`, `init.defaultBranch`, `diff.renames|algorithm|context|colorMoved`,
  `merge.ff|conflictStyle`, `pull.rebase|ff`, `rebase.autostash`, `safe.directory`, `gc.auto`, `protocol.file.allow`, `push.default`,
  `fetch.prune`, `credential.*.useHttpPath|interactive|username`; "inert" means no program the COMMAND chose: `commit.gpgsign` and
  `tag.gpgsign` do start `gpg.program` (default `gpg` from `PATH`) and `user.signingkey` can start `ssh-keygen`, but that program comes
  from the config or `PATH`, and a `gpg.program` key or a `PATH=` before git is a deny of its own (Sam 1772, docs only); or
- it is a credential helper whose value is EMPTY (resets the list) or exactly the fork-push recipe `!gh auth git-credential`; or
- it has no `=` at all (`-c KEY` is the boolean true: there is no value to run), or nothing follows the `-c`.

Everything else is a deny: a key the gate does not know, a value from `--config-env` (it comes from an environment variable), a
credential helper with any other value (`store`, `cache`, `!f() {...}`, a variable), `git config --edit` (it starts the configured
editor), `--exec-path=<dir>` (git runs its sub-commands from there). `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_PAGER` and `GIT_ASKPASS`
are a different shape of the same fact, and round 1 got it half right (round 2, below). Reading, `--get*`, `--list`, `--unset*`,
`git config get|list|unset` are silent.

## Round 2 (Sam 1772, `dee3f185` NOT green): the same facts, read at the condition

1. **The four program-valued names are bound by ANY form, not only `NAME=value`.** Round 1 kept them on the environment allowlist and
   judged only the `NAME=value` token. But they are already exported in a normal session (`printenv GIT_EDITOR` = `true`), so every
   other way to give one a value reaches the child git: `GIT_EDITOR+='; touch m'`, `printf -v GIT_EDITOR ...`, `read GIT_EDITOR`,
   `for GIT_EDITOR in ...`. Sam ran all four against real bash and git 2.53: the marker was created, the gate returned 0. Now the four
   names are OFF the allowlist, so the generic binding machinery (`_env_binding_forms`, `_env_verbs_for_git`, `_env_set_for_git`, built in
   card f4057869) judges every form: `+=`, `printf -v`, `read`, `mapfile`, `for`/`select`, `let`/`(( ))`, `${NAME:=x}`, `export`/`declare
   -x`, a prefix, a `source`d file. The one thing let through is the plain word `NAME=<no-op literal>` (`true`, `false`, `:`, `cat`,
   empty) in the prefix, plain-assignment or `export` position (`_prog_env_noop_assignment`); `+=` with a no-op value is a deny (it
   appends to an exported program). The four names count as bound whether or not THIS session exports them (the earlier machinery
   looked at `os.environ`): what the name holds is a program, so there is no value in asking whether it happens to be exported today.
2. **A `-c` pair the gate cannot read is a deny.** `git -c $'core.fsmonitor=touch m' status` (an ANSI-C quoted pair) reached the scanner
   as `$'` + spaces + `'`: no `=`, so it was taken for the boolean `-c KEY`. Now a word with no visible `=` is silent only when it is a
   plain key (`[A-Za-z0-9][A-Za-z0-9._-]*`); `$'...'`, a `=` inside quotes (`core.fsmonitor"=touch m"`) and the glued `-c$'...'` are
   denies. ANSI-C is not decoded here; a deny is the inverted proof.
3. **A global option with a separate value no longer hides the subcommand.** git 2.53 takes `--attr-source status` as an option and its
   value, so in `git --attr-source status -c core.fsmonitor='touch m' status` the scan took `status` for the subcommand and never
   looked at the `-c`. One list now names every global option that takes its value as the next word (`-C`, `-c`, `--git-dir`,
   `--work-tree`, `--namespace`, `--super-prefix`, `--config-env`, `--attr-source`; `_GIT_GLOBAL_VALUE_OPTS`), used by every scanner
   that steps over them. The valueless and glued options are a second closed list. An option on neither list is unprovable: the scan
   cannot tell its value from the subcommand, so it denies when something this rule judges (a `-c`, a `--config-env`, a `config`
   word) stands behind it, and is silent when nothing does (`git --future-option status`).

Measured on real bash and git 2.53 (`git-config-programs.test.py` section 5): the four forms for `GIT_EDITOR` and for
`GIT_SEQUENCE_EDITOR` really ran the probe (8 of 8), as did the ANSI-C pair and the `--attr-source status` form; the gate blocks all ten.
The new rows fail on `0a01fde5` (44 rows) and pass on this head. Named limits added: `git --attr-source HEAD status` (a separate value
that is not a builtin name) stays a deny, as it was, by the hook-class rule that reads `HEAD` as the subcommand; and an option the gate
does not know with a `-c` behind it is a deny even when the option takes no value (a false deny, never a hole).

A quoted value with a space reaches the segment scanner blanked to spaces (prose masking). Such a `-c` pair is read from the raw
command: every typed `-c` word of the same length (and the same key when the key survived) must pass; none found is a deny (an
unreachable defensive branch: no construct was found that blanks a pair the raw text does not contain).

Differential against the real git (the test runs it in a sandbox repo with a probe program): all of `core.fsmonitor`, `core.pager`,
`pager.log` (through a pty, a pager only starts on a terminal), `core.editor`, `sequence.editor`, `diff.external`, `alias.x=!prog`,
`gpg.program`, `core.sshCommand`, `credential.helper=!prog` and the three environment variables really ran the probe and are blocked;
the 31 keys of the inert list (11 sub-commands each, 341 runs) never ran it.

Price, final verdict (`check_bash`, the main-checkout view, in process): chain head (card f4649c5d, `895d76b4`) against this head, over ALL
31,578 unique Bash commands of the agents' transcripts (main agent, `~/.claude/projects`, every `agents/*/.claude-config`): 30,113 allowed on
both, 1,452 denied on both, **12 newly denied, 0 newly allowed** (a 13th row, a Python document that quotes a trailing `git -c`, was a false
denial of the first version and is allowed now). The 12: 9 are a credential helper that is not the recipe (inline `!f() { echo username=...;
echo "password=$GH_TOKEN"; }` helpers of earlier push attempts, and `H='!gh auth git-credential'` kept in a variable: a variable is not
read, name the recipe in the command), 1 `git config diff.hide.textconv`, 1 `git -c url.file://$T/.insteadOf=...` (it re-points a
remote), 1 `core.fsmonitor`. All 12 are measurement commands of the gate's own development or push attempts from before the recipe below was settled on; none is a
command of the normal workflow today (the push recipe `-c credential.helper= -c credential.helper='!gh auth git-credential'` is allowed and has a test row).

Round 2 price, same method (final verdict, in process, the main-checkout view), `0a01fde5` against this head, over ALL 32,477 unique Bash
commands of the transcripts: 30,990 allowed on both, 1,479 denied on both, **1 newly denied, 0 newly allowed**. The one is the
measurement command of Sam's own round-1 probe (a `GIT_EDITOR+=` and an ANSI-C `-c` pair in one line). The first run showed 8 newly
denied: the other 7 were an artefact (the old gate was loaded from a scratch directory, where its own-workdir rule differs; loaded from its
own worktree they are denied on both).

Tests: `scripts/__tests__/git-config-programs.test.py`, 448 rows (345 of round 1, 103 of round 2). The existing suites stay green:
`destructive-gate.test.py` 1,595 and `git-hook-switch.test.py` 439. One row of `destructive-gate.test.py` changed meaning: card 7fd3134e asserted that
`git -c credential.helper="$CH" status` is "not a program"; a helper value IS a program (this card), so the row now uses
`user.email="$EM"` (the same shape for the `-c` reader), and the helper form is a deny row of the new test. Mutants: 27 (every
condition of the key classification, the helper values, `--config-env`, the glued `-c`, `--exec-path`, `config --edit`, `set`, the write
detection, the read flags, the three environment positions, the blanked-pair recovery with its length and key filters, the rule's call
site, the skipped `-C` value and unknown flags): all fail the test except the "no candidates is fine" line, which is the unreachable
defensive branch above. Round 2 added 19 mutants (every new condition: the allowlist, the no-op exemption in the prefix and `export`
positions, the exported-or-not test, each of the four names, the bare-key test, each entry of the shared option list, the unknown-option
rule and both of its two lookups behind the option, the valueless and glued lists): 16 fail the test; the 3 that survive are
equivalent, each is covered by a second independent layer (the no-op test of the `export` position, because `_git_program_env` judges
the same value on the git segment; the `config` word behind an unknown option, because an unknown subcommand is a deny of the hook
class; the shared list inside the push-index scanner, because an unknown global option is a deny of the hook class).

Named limits:

- The config files git reads by itself (a repo's `.git/config`, `~/.gitconfig`, an included file) are not read; the gate judges what the
  COMMAND hands to git. Writing them is the business of the other rules (`core.hooksPath`, `include.path`, `alias`, `check_gitcfg_write`).
- A git option whose VALUE is a program but that is not a config key (`git rebase --exec`/`-x`, `git bisect run`, `git submodule foreach`,
  `git fetch|ls-remote|clone --upload-pack`, `git push --receive-pack`, `git grep -O`, `git difftool --extcmd`, `git filter-branch
  --*-filter`, `git archive --exec`) is a different class, measured rc 0 on this head: card 0d194126.
- `git -c` inside interpreter code is judged only as far as the rest of the gate reads such code.
- `-c` after the subcommand is the subcommand's own option (`git commit -c <commit>`), and is not judged here.

# The shell reader: a quote map is trusted only where it provably agrees with bash (card 798c3c24)

Every step of this gate stands on `_quote_map`, which used to be a two-state toggle (outside / inside a quote). Where it is wrong about one
character, the command on the NEXT LINE is read as quoted data, and a destructive command on it goes through. Measured against the real
bash (the final verdict of `check_bash`; random quote soup + a separator + a final word bash EXECUTES; the same text with that word
replaced by a destructive command; a hole is "bash ran it and the gate passed it"): the rollout tip `da735ad8` passed 30 of 2,564 (alphabet
"wide"), 44 of 4,086 ("comments"), 28 of 1,962 ("heredocs") and 237 of 5,657 (the ANSI-C alphabet of card f8acbcb4), each a fresh seed. The
shapes, each run by bash:

- a comment with a quote in it: `ls # it's`, newline, the command, ` # don't` (an odd quote count was a deny by accident in the
  substitution cutter; an even count went through);
- a backslash-newline, which the gate replaced everywhere by two spaces: `echo \\`, newline, the command (an escaped backslash, then a REAL
  newline, read as one line); `r\`+newline+`m -rf x` (bash joins the halves into `rm`, the gate read `r  m`); a pair inside a comment or
  single quotes (not a continuation at all); `echo $\`+newline+`$'\'` (the continuation hides that the two dollars are the PID);
- `echo &#$'\`+newline+`\' | <cmd>` (a hash after an operator is a comment);
- a double quote inside single quotes inside `$(..)` inside double quotes: `echo "a $(grep 'x"' f)" && <cmd>` (the toggle closed the
  string at the inner `"`; not an ANSI-C or comment matter, found by the corpus price of this very change);
- an ANSI-C string with an escaped apostrophe (card f8acbcb4, carried in this branch as its own first commit).

What changed, in four parts, none of them a list of shapes:

1. **`_shell_scan`**: a second reader that follows bash's word splitting for the subset it models: backslash escapes, single and double
   quotes, `$'..'`, `$".."`, `$$` (the PID, so the quote after it is a plain one), `$(..)`, `${..}`, `$((..))`, backticks, comments (a hash at
   the start of a word, to the end of the line; a backslash-newline inside it does NOT continue it), backslash-newline (also between the
   two characters of `$'`), and heredoc bodies (skipped, and only in the context of their opener). It returns the comments, the real
   continuations, the set of offsets the shell reads as COMMAND text and, on request, the quote map. It raises `_ScanUnsure` on anything it
   does not model: an unclosed quote, a quote or backtick inside `${..}`, a quote or backslash inside `$((..))`, a backslash that escapes
   (`\\`, `\$`, `` \` ``) or a comment inside backticks, a `case` inside `$(..)`, an arithmetic not closed by an adjacent `))`, a
   heredoc body that does not belong to an opener of its own context.
2. **`_quote_map` is now that reader's map** where it can read the text; the old toggle (`_toggle_quote_map`) is only the fallback for text it
   cannot, and `check_bash` refuses a whole command in that state before any step stands on the toggle.
3. **`_normalize_continuations`** (first line of `check_bash`): every REAL backslash-newline is removed, as bash does, and the result is read
   again (nothing may be left). The blind `replace('\\\n', '  ')` of `_check_bash` and `_opaque_substitution` is gone. `_comment_ranges` is
   the reader's comments plus the hash-led lines inside interpreter heredoc bodies; a payload cut out of a `-c` string or a body loses its
   hash-led lines afterwards (`_strip_comment_lines`). The old whole-line rule blanked a `# it's` line inside a single-quoted string and
   took the quote with it.
4. **`_require_same_reading`** (inside `scannable`, so before every later step): every offset the reader calls command text must be
   UNQUOTED in the map the pipeline uses; if it is not, or the reader cannot read the command at all, the command is refused with the
   offset. Silent only on proof.

Effect, same method, fresh seeds, the new head: 0 of 5,657 (ANSI-C alphabet), 0 of 1,962 (heredocs), 1 of 2,564 (wide) and 11 of 4,086
(comments). Every one of the 12 left is `echo &`, backslash-newline, the command (or a variant): a lone `&` (background) is not a segment
border in this gate at all, an older and separate hole, card 95d0cbc5 (`sleep 1 & <cmd>` passes on the live gate; the end-to-end rows of the
test keep `&` out of their alphabet for that reason).

Price, final verdict, in process, the main-checkout view, `da735ad8` (the old gate loaded from its own worktree) against this head, over
ALL 33,097 unique Bash commands of the transcripts: 31,599 allowed on both, 1,486 denied on both, **5 newly denied, 7 newly allowed**. The
5: (a) `python3 - <<'EOF'` whose body has apostrophes, followed by shell lines holding `GATE=...` next to a git word: the old map was
desynchronised by the body and hid the shell text after it (a hole, not a false positive); (b) a python body that itself contains a line
`EOF` (bash ends the heredoc there too, the rest is shell text with a heredoc opener inside backticks: unprovable); (c) `rm node_modules` run inside the old gate's own worktree (loaded from its own root it is a delete under the working directory, loaded from the new root it is a delete outside it: an artefact of the two roots, not of the reader); (d) Sam's own bash probe: a `-c` word with quote juxtaposition and a hash-led line inside
it (the 7fd3134e rule, which the blanked line used to hide); (e) a message with real backticks around a text that holds a backslash. The
7 newly allowed are false positives the toggle made (an apostrophe in an end-of-line comment, a `#` inside a quoted string, a quote in a
`${..}` or `$(..)`). The first run of this method showed 24 newly denied: they were the hash-led lines of Python heredoc bodies, which the
shell steps must keep ignoring (fixed: the whole-line rule stays inside the interpreter bodies).

Tests: `scripts/__tests__/destructive-gate.test.py`, section "798c3c24": 18 fixtures that bash really runs (each is first checked against
the real bash, so a fixture that does not execute cannot pass for a hole), 22 quiet controls (harmless commands the reader must let
through), 17 more rows (the reader's units, the proof called directly with the old toggle map, the quote map of a nested quote, the
payload comment strip) and an end-to-end differential against the real bash (2 x 700 random strings). The suite: 1,692 rows (the tip's
1,595, card f8acbcb4's 10, this card's 87), `git-config-programs.test.py` 448. Mutants (`deecccda-mutants/mutants_798c3c24.py`): 34, 32
killed; the two that live are equivalent or unreachable: a backslash before any character other than `$`, `` ` ``, `"`, `\` and the
newline is lexically inert inside double quotes (skipping it changes nothing), and the second reading of the normalised command can never
find a continuation (defensive).

Named limits:

- **The reader is not a bash parser.** It refuses, and so the command is DENIED, on every construct listed under 1 that it does not model.
  A command that uses one of them legitimately (a quote inside `${x:-'a b'}`, a `case` inside `$(..)`, a heredoc opened inside backticks)
  is refused; the way out is to write it without. The price above counts how often that happens on real commands: 2 of 33,097.
- Aliases, `shopt` (extquote and friends), `set -o posix`, `[[ .. ]]` regex quoting and `coproc` are not modelled; bash is assumed to be
  the non-interactive default.
- **Only `check_bash` and what it calls read the text.** Other hooks that look at the raw command (the egress parser, the outgoing copy
  gate) have their own readers and are not changed here.
- A lone `&` as a segment border: card 95d0cbc5. An ANSI-C word as the COMMAND NAME (`$'\x72m' -rf x`): card 4b42b6b0.
- The hash-led lines of a `-c` string are blanked only in the extracted payload (`_strip_comment_lines`), not in the shell text around it.
- The toggle still exists, as the fallback, and is still wrong where it was wrong; what changed is that a command it would have been
  trusted on is refused first.

## The shell reader, round 2 (card 798c3c24, Sam 4410: three live classes that the first head passed)

The first head refused what its reader could not model, but three constructs were read WRONGLY without raising, each with a comment pair behind
the command (`... # '`). Real shell in a jail, a canary file as the target; the rollout tip, the first head and the 4b42b6b0 head all passed them:

1. **An apostrophe inside backticks** (the card's own case): `` echo `'`; <cmd> # '` ``. The reader paired the quote ACROSS the closing backtick;
   bash ends a backtick substitution at the first backtick whatever quotes stand between. `bt()` now finds the first backtick first and requires the
   inner walk to end exactly there (`_ScanUnsure` otherwise); the same in the double-quoted case.
2. **A heredoc delimiter the pattern read only in part**: `<<\E`, `<<-\E`, `<< \E`, `<<E\x`, `<<"E"x`, `<<$'E'`, `<<\E\F`, `<<'E'x`, `>/dev/null <<\E`.
   The old pattern took `E` and went on to look for a line `E`; bash's delimiter is the whole word (`Ex`), so the gate hid the commands after the
   terminator as heredoc data. Two changes: `_heredocs` does not register a heredoc whose delimiter word goes on past what the pattern read, and
   the reader raises `_ScanUnsure` at every `<<` (not `<<<`) whose body the gate did not find. A fix of the reading and the inverted rule that
   catches the next form nobody listed.
3. **A line continuation in a program cut out of double quotes**: `bash -c "r\\<NL>m ..."` (the double quotes turn `\\` into `\`, the inner shell joins the
   lines), also `sh -c`, `eval`, `bash <<< "..."`, `printf '...' | bash`. `_tokens` and the cut-out runs (`_run_text`, `_pipe_program_text`) now
   take the text as bash hands it on: `\\`, `\"`, `\$`, `` \` `` lose their backslash and a backslash-newline disappears inside double quotes; a
   `printf` FORMAT and the text of `echo -e` are expanded once more with the `$'..'` escape rules (`_ansi_decode`) before the program is read.
   (`bash -c $'...'` is the same case with the ANSI-C word; its expansion is card 4b42b6b0, stacked on this one.)

Found on the way, fixed: the `<<<` here-string was read as a heredoc operator by the new unarmed rule (every `bash <<< "..."` was refused); the
scanner now consumes `<<<` as one operator.

The real-bash runs of this card's tests are jailed: a throw-away working directory, a minimal environment (`PATH=/usr/bin:/bin`, `HOME` in the jail), and
the target of the fixtures is a canary file in that directory, never a real path (`_jail_run`; the older helpers got the same directory and environment).

Measured, same method as round 1 plus the comment-pair suffix (`SUFFIX=1`: ` # '`, ` # "`, ` # don't` behind the final word), fresh seeds, the 4b42b6b0
head against this head: alphabet "backticks and heredoc delimiters" 35 of 2,114 holes -> 0; "wide" 3 of 1,963 -> 3 and "comments" 6 of 3,055 -> 6 (every one of
those has a lone `&`, card 95d0cbc5); "heredocs" 0 of 1,536 and "card" 0 of 3,573 before and after. Sam's 27 runnable shapes of the three classes
(his v3/v5 lists, the shapes that bash really runs): 0 holes, and four more of mine (`echo -e`, `echo -ne`, `printf '%s' "..."`, `echo "..."` into a shell).
Tests: `destructive-gate.test.py` 1,762 rows (1,692 + 70), `git-config-programs` 448.

Price, final verdict, in process, the main-checkout view, the rollout tip `da735ad8` (loaded from its own worktree) against this head, over ALL 33,490
unique Bash commands of the transcripts: 31,988 allowed on both, 1,488 denied on both, **5 newly denied, 9 newly allowed**. The 5: (a) a `python3 -
<<'EOF'` whose body has apostrophes, followed by shell lines holding `GATE=...` next to a git word: the old map was desynchronised by the body and hid
the shell text after it (a hole, not a false positive); (b) a python body that itself contains a line `EOF` (bash ends the heredoc there too, the rest is
shell text with a heredoc opener inside backticks: unprovable); (c) `rm node_modules` run inside the old gate's own worktree (an artefact of the two
roots); (d) Sam's own bash probe: a `-c` word with quote juxtaposition and a hash-led line inside it (the 7fd3134e rule, which the blanked line used to
hide); (e) a message with real backticks around a text that holds a backslash. The 9 newly allowed are false positives the toggle made (an apostrophe in
an end-of-line comment, a `#` inside a quoted string, a quote in a `${..}` or `$(..)`). The first price run of this round showed 14 newly denied: seven
were real commands with a heredoc whose body is EMPTY (the terminator on the next line) or whose opener sits after a quoted `<<EOF` on the same line,
and one a heredoc after a multi-line double-quoted program with `((` in it: fixed (an empty body is a body the gate found; `_heredocs` takes the first REAL
and complete opener of a line; `_opener_is_real` has a second opinion from the shell reader, which counts only the parentheses that are not quoted).

Mutants (`deecccda-mutants/mutants_798c3c24.py`): 48. Last full run: 40 killed. The 41st (the second opinion for the opener) was killed by a row added
afterwards, checked by hand against the mutated copy (the mutated gate refuses the row, the real one passes it), not re-run in full. Seven live: a
backslash before a character other than `$`, `` ` ``, `"`, `\` and the newline is lexically inert in double quotes (equivalent); the second reading of
the normalised command can never find a continuation (unreachable); the body-skip context check, the backslash and the comment inside backticks are
now also refused by the closer-first rule (redundant); and the two escape rules of `_dq_unescape` (measured: the mutated gate still refuses the pipe
fixtures through another path, which I did not locate).

Named limits (new):

- **Only backticks, double quotes, `printf` formats and `echo -e` are expanded for a cut-out program.** Another producer that rewrites its input
  (`sed`, `tr`, `awk`, `base64 -d`, a here-document with an unquoted delimiter: `cat <<EOF | bash` expands `$` and backslashes) is not simulated; its
  output stays opaque, as before.
- A heredoc operator anywhere the reader cannot place a body for is refused, so `(( x << 2 ))` and `let x=1<<2` outside quotes are refused too
  (inside `$((..))` and quotes they are not).
- A printf format with directives is refused when it is piped into a shell (round 3); before that it was expanded for its escapes only, and what its arguments print was not.
- A `$'..'` word as the quoted program (`bash -c $'r\\\nm'`) is expanded by card 4b42b6b0, not by this card.

## The shell reader, round 3 (card 798c3c24, Sam 1885: the heredoc class)

Sam's frozen list left one class open: the end of a heredoc body. His acceptance for this round: the "heredoc" and "heredoc delimiters" alphabets with the comment-pair suffix (`SUFFIX=1`) at 0 head holes on at least six seeds. The six holes he named
reduce (delta-minimised against real bash) to two causes, not one:

1. **The terminator was matched loosely.** `_heredocs` ended a body at the first line whose `strip()` equalled the delimiter. Bash needs the line to be EXACTLY the delimiter; with
   `<<-` only leading TABS are dropped, not spaces, not a trailing space, not a carriage return; and with an UNQUOTED delimiter a backslash-newline in the body is removed first
   (`foo\<NL>E` is the line `fooE`; `E\<NL>` followed by a blank line IS the terminator; with a quoted delimiter nothing is joined). Four of the six holes are ONE heredoc
   (`<<E<NL>E <NL>'<NL>E<NL>MARK #'`: the gate ended the body at `E `, read the lone `'` as an opening quote, and hid `MARK`; bash ran it). `_heredoc_end_line` is the bash rule.
2. **Two operators on one line.** Bash reads the bodies one after the other; the gate read one. `<<E<<E` is refused now (see below); proper modelling of several bodies on a line is not
   attempted: the inverted rule is cheaper and the form is rare.

The reader is also a real second opinion about the BODY now (strict mode, the one with the complete list of bodies): for every `<<` it reads the delimiter word from the TEXT
(`_hd_word`: a plain identifier, bare or in one pair of quotes, followed by a word boundary; anything else, `<<\E`, `<<"E"x`, `<<$'E'`, is `_ScanUnsure`), recomputes where bash ends
the body, and requires the gate's range to be the same one (`_ScanUnsure` otherwise); a second operator on the same line is `_ScanUnsure`. So a future disagreement between the
terminator rule and the shell is a deny, not a hole.

Also in this round (Sam's MEDIUM and two MINOR notes):

- **`echo -e` and the `printf` FORMAT have their own escape rules**, and they differ from `$'..'` and from each other (measured against bash 5.3 on 4,000 random strings each: 0
  differences except `\u`/`\U` in a non-UTF-8 locale, where bash prints the escape unexpanded; the gate assumes the stricter UTF-8 reading). echo: `\0` and up to three octal digits
  (`echo -e 'r\0155'` is `rm`), `\c` ends the output, `\155` and `\"` stay. printf: one to three octal digits (`printf 'r\0155'` is CR and `5`), `\"` `\'` `\?` lose the backslash, `\c` stays.
  `_echo_printf_decode(body, mode)`. `printf -- '...' | bash` is read like `printf '...' | bash`.
- **A printf format with a directive (`%s`, `%b`, `%d`) piped into a shell is refused.** The program is made after the expansion of the arguments, which the gate does not model
  (`printf 'r%sm -rf X' '' | bash` ran `rm`). `%%` is the one percent sign that stays readable. This replaces a named limit of round 2.
- Test hygiene: the older real-bash differential (`_bash_differential`) now runs in the same jail as the others (a throw-away directory, minimal environment, stdin closed), and the
  jail directory is removed at exit (`atexit`; Sam counted 203 left in `/tmp`).

Measured. Sam's two alphabets, `SUFFIX=1`, the round-2 head (`bc87afba`) against this head, ten seeds (77 and 9101 with 6,000 strings, the other eight with 20,000; 2,400 to 3,000 per 20,000 that bash
ran): the round-2 head had 0 to 4 holes per run (33 in all), this head 0 in all 20 runs; `head_not_r2` (a hole of this head that the round-2 head does not have) 0 everywhere. His six named holes: all six refused. Two alphabets of my own that add
parentheses, `$(`, backticks, `<<<`, `E\<NL>` terminators and double operators (`here2`, `here3`; six seeds each, 20,000 strings): round-2 head 18 and 173 holes, this head 0 and 0.
The other six alphabets (card, wide, comments, continuations, backticks, substitutions; seeds 8404 and 77, 12,000 each): 0 holes on the round-2 head and this head, except "wide" seed 77, 3
holes on BOTH heads and in the same shapes (two with a lone `&`, card 95d0cbc5; one with a `${ }` word, card 8ed4c8e8).
Price (the corpus run, OLD = `bc87afba` from its own worktree, 34,067 unique Bash commands of the transcripts): 32,566 allowed on both, 1,500 denied on both, **0 newly denied, 1 newly allowed**.
The one is a false positive that went away: a skill file written with `cat > f <<'EOF'` whose body holds a line `   EOF` (indented with spaces). Bash does not end a plain heredoc there; the old `strip()` match did, and the
gate then read the rest of the body as shell text and refused it.
Mutants (`deecccda-mutants/mutants_798c3c24_r3.py`): 18, 17 killed. The one that lives, the unfolding of `%%` to `%` after a printf format, changes only what a `%` inside the program looks like, never a decision of the gate (equivalent).
Five more were first alive and were killed by rows added afterwards (a quoted delimiter joins nothing, `<<-` drops the tab of the terminator, the strict reader refuses a wrong body range, `_hd_word` unit rows).
Tests: `destructive-gate.test.py` 1,838 rows (1,762 + 76), `git-config-programs` 448, `git-hook-switch` 439.

Named limits (new or changed): two heredoc operators on one line are refused although they are legal (`cat <<A <<B`); the comparison of the body end covers the heredocs the gate registers, so
an operator in a context the reader does not place (inside `$( )` with a `case`, an unclosed construct) stays with the existing `_ScanUnsure` rules; `\u`/`\U` in `echo -e` and `printf`
are read as UTF-8; a printf format with an argument-dependent directive is refused, not simulated; the sentence "A printf format with directives is expanded for its escapes only" in round 2
no longer holds.

# A lone `&` ends a command (card 95d0cbc5)

`sleep 1 & <cmd>`, `echo & <cmd>`, `echo &<cmd>`: the `&` that sends a command to the background ends it, and what stands behind it is a command of
its own. The gate's delimiters (`&&`, `||`, `$(`, `;`, `|`, newline, backtick) did not include it, so the command behind it was read as an argument of
the one in front and never judged (measured on the live gate, the rollout tip and the 798c3c24 head with a real shell in a jail: rc 0; Igor's
differential found it, 12 of the holes it left open on the 798c3c24 head had this shape).

Now every unquoted `&` that is not part of a redirection is a segment border (`_is_background_amp`, used by `segments_pos`). Not a border: the `&` of `>&`,
`<&` (a descriptor duplication), `&>` and `&>>` (a redirection of both streams), and `&&` (its own delimiter); `|&` is the pipe, which the `|` delimiter
already ends. Inverted direction: a doubtful `&` costs one more segment that is checked, never one less.

Measured, same method, fresh seed with the comment-pair suffix, the 798c3c24 head against this head: alphabet "comments" 6 of 3,147 holes -> 0; "wide"
3 of 2,014 -> 1 (the one left is a command word with an embedded expansion, `${ }MARK`: card 8ed4c8e8); "heredocs" 1 of 1,523 -> 1 (two heredoc operators
on one line, `a<<'E'<<E`: a class of the 798c3c24 reader, reported to Sam); "backticks and heredoc delimiters" 0 of 2,023 and "card" 0 of 3,591 before and
after. The end-to-end rows of the tests take the `&` back into their alphabets. Price (final verdict, in process, the 798c3c24 head against this head,
33,532 unique Bash commands of the transcripts): 32,039 allowed on both, 1,493 denied on both, **0 newly denied, 0 newly allowed**. Tests:
`destructive-gate.test.py` 1,801 rows (1,762 + 39: eleven shapes that a real shell runs, fifteen quiet controls for the redirection forms and quoted
ampersands, two units), `git-config-programs` 448. Mutants (`deecccda-mutants/mutants_95d0cbc5.py`): 5, 5 killed.

Named limits: an `&` inside `$(( ))` (a bitwise and) splits the arithmetic into segments like any other (more segments are checked, nothing is hidden); a
command that ends in `&` with nothing behind it is judged as before.


# A redirection in front of the command name, an escaped `<` or `>` in front of `&` (cards 6b631f69 and 95d0cbc5 round 2)

`>/dev/null rm -rf <dir>`, `2>/dev/null rm ...`, `</dev/null rm ...`, `echo a & 2>&1 rm ...`: the shell takes the redirections out of the words before it looks for the
command, wherever they stand, so these run `rm`. The gate read the first redirection as the command name (`command_index` skipped assignments and wrappers, not redirections)
and never met the real one: rc 0 on the live gate, the rollout tip and every head of the chain (Sam 4473, 4482). The same blindness sat behind `env >f rm`, `timeout 5 >f rm`,
`nohup 2>&1 rm`, and behind the other half of Sam's round-1 finding on card 95d0cbc5: `echo \> & rm ...` (an escaped `>` is an argument, the `&` behind it ends the command),
`echo a &</dev/null rm ...` (`&<` is not a redirection in bash: it ends the command), and `>|`, which the `|` delimiter cut in front of the target.

Four changes:
- **`_redirect_len` / `command_index`**: a token that is a redirection (an optional fd number or `{name}`, then `>`, `>>`, `>|`, `<`, `<>`, `<<`, `<<-`, `<<<`, `&>`, `&>>`, `<&`, `>&`) is
  skipped together with its target when the target is a separate word (`> /dev/null`, `<<< x`, `>| f`, `>& f`). It is skipped between assignments, behind the keywords, between a wrapper
  and its options (`env >f -u X rm`, `command >f -- rm`) and inside `_after_wrapper` (`timeout 5 >f rm`, `timeout >f 5 rm`). A word that began with a quote (`'>x'`) is read as a redirection too:
  the cost is one more command name that is checked, never one less.
- **`_redir_char_before`**: is the character in front of the position an unquoted, UNESCAPED `<` or `>`? Read from the quote map and the backslash parity, not from the raw character
  (`\>&` and `'>'&` have an argument in front of the `&`; `\\>&` is an escaped backslash and a real `>`).
- **`_is_background_amp`**: not a border are the `&` of `>&` / `<&` with a real operator in front, `&>` and `&>>`, and `&&`. `&<` IS a border now, and an escaped or quoted operator in front does not make the `&` part
  of a redirection. Inverted direction as before: a doubtful `&` costs one more segment.
- **`segments_pos`**: a `|` behind a real `>` (`>|`) is not a pipe. An escaped `>` in front of `|` (`echo \>| rm`) still is.

Measured: a differential against real bash with a fake `rm` and `git` on PATH that write RAN into a canary file (a redirected stdout cannot hide the run), the command written behind
random redirection spellings (30 forms: `>`, `2>`, `<`, `>>`, `&>`, `&>>`, `2>&1`, `>&2`, `<<<`, spaced targets, `<>`, `>|`, quoted targets, `{fd}>`, ...), 0 to 3 in front and 0 to 1 between the name and its
arguments, behind 25 separators and openers (`;`, `&&`, `||`, `|`, `&`, newline, `(`, `{`, `if`, assignments, `time`, `!`, `\>&`, `\<&`, `'>'&`, `&<`, `&>`), behind 11 wrappers (`env`, `command`, `nohup`, `nice`,
`timeout 5`, `env -i`, `sudo -n`, ...), `rm -rf` and `git push --force`: 5 seeds (61 and 62 x 4,000; 63 to 65 x 6,000; 1,861, 1,817, 2,765, 2,752 and 2,796 that bash ran), the previous head
(f0bb8a9b) 1,562, 1,524, 2,315, 2,332 and 2,338 holes, this head **0 on all five** (and 0 on two more seeds, 66 and 67, after the rebase onto 7a80681c: the head before it 2,257 and 2,291). (A first version without the `>|` and `&<` changes left 366 and then 88 of the 1,852 in seed 61.) Sam's alphabets (`amp`,
`amp2` with the new operators, `wide`, `here`, `cmt`, `card`, `bt`; seeds 77 and 9202; 8,000 to 15,000 strings each): 0 holes on both heads. They do not reach the class (the previous head is 0 there too:
the command stands behind a separator, never behind a redirection), so they show the absence of a regression, not the fix. Price (the corpus run, OLD = 7a80681c from its own worktree, 34,651 unique Bash commands):
33,142 allowed on both, 1,509 denied on both, **0 newly denied, 0 newly allowed**. Mutants (`deecccda-mutants/mutants_redir_6b631f69.py`): 19, 18 killed; the survivor (the quote-map test inside
`_redir_char_before`) is defensive: the character in front of an unquoted `&` or `|` cannot be a quoted operator, a closing quote stands between them. Tests: `destructive-gate.test.py` 2,393 rows (2,272 + 121:
the shapes that a real shell runs, each with its fixture check, quiet controls, three units), `git-config-programs` 450, `git-hook-switch` 439.

Named limits: a substitution in the redirection target or in an assignment in front of the command (`>$(echo f) rm -rf x`, `x=$(date) rm -rf x`) is not part of this section: the segmenter cuts at `$(`; it is
the next section (card 46f43d1a). A redirection
BETWEEN the name and its arguments is left as an argument of the command (unchanged). `>>&`, `<<&` and `<>&` are not duplications (a bash syntax error); they count as redirections in front of the `&` and nothing more is
claimed. `case` branches and the `builtin` wrapper are the cards bdcfa13a and f64fcef1.

# What follows the closing parenthesis of a substitution in an assignment or a redirection target is a command (card 46f43d1a)

`x=$(date) rm -rf <dir>`, `FOO=$(echo a) rm -rf <dir>`, `x=$(date) y=1 rm ...`, `x=$(date) git push --force origin x`, `>$(echo f) rm -rf <dir>`: the shell runs rm. The segmenter cuts the
text at `$(`, so the text behind the matching `)` stayed in the segment of the last command INSIDE the substitution and read as its arguments (`date) rm -rf <dir>`): no rule ever met `rm`
as a command. The quoted form (`x="$(date)" rm`) and the backtick form were already refused; the unquoted `$(` was the blind spot (Sam 4567, measured on the live gate, the rollout tip and every head
of the chain). It is older than the chain and not a regression of any card.

Two changes:
- **`segments_pos`**: when an unquoted `$(` (or `$((`) stands behind a prefix that holds NO command word yet, only assignments and redirections (`_command_still_to_come`: `x=`, `FOO=a y=`, `>`, `2>`, `> `;
  glued to the substitution, or a bare operator ending in a space), the `)` that closes it (`_matching_paren`: unquoted parentheses only, a backslash takes the next character) is a segment border.
  What stands behind it is checked as a command. Where the prefix already holds a command word (`echo $(date) rm -rf x`) the text behind the `)` is an argument and stays one; a spaced `x= $(..)`
  and an empty prefix are the command-word substitution that `_opaque_substitution` already refuses.
- **`_rm_allowed`**: an `rm` whose only operands are redirections (the segment `rm >` that is left of `rm >$(echo f) -rf <dir>` once the substitution has cut the operands off) is refused, as an
  `rm` with no operand at all already was ("it is not visible WHAT it removes"). Refused only: an `rm` with a real operand and a redirection keeps its verdict.

Measured: the redirection differential (diffr2.py) with the new pieces, assignments with substitutions in front of the command (`z=$(date)`, `z=$(echo a) y=1`, `z=$(echo $(echo a))`, `z=$(echo ')')`,
`z=$(echo \)`, `z=$((1+2))`, `z=$(a=1; true)`, two substitutions, `z=${NOPE:-x}$(date)`) and substituted redirection targets (`>$(echo /dev/null)`, `2>$(echo ..)`, `> $(echo ..)`, nested, `&>$(echo ..)`),
also after the command name: 2 seeds x 5,000 (2,103 and 2,127 that bash ran), the previous head (935f702c) 1,649 and 1,672 holes, this head **0 on both**. (A first version without the
arithmetic expansion left 194 of 2,103, the next 43: `rm >$(echo ..) -rf <dir>`, the `_rm_allowed` change.) Price (the corpus run, OLD = the redirection head from its own worktree, 34,730 unique Bash commands: 33,219 allowed on both, 1,510 denied on both, **0 newly allowed, 1 newly denied**: `GH_TOKEN=$(cat <file>) git push fork <branch>` from a worktree directory that no longer exists. The assignment used to hide the `git push`; now the git rules see it, and they refuse it exactly as they refuse the same push without the assignment on the previous head (core.hooksPath cannot be queried in a missing directory). A push of this shape is judged like any other push from now on).
Mutants (`deecccda-mutants/mutants_subst_46f43d1a.py`): 14, 12 killed. One survivor is equivalent (an unmatched `$(` adds a border at offset 0, which the loop has passed before it can be added);
the other (a `--` counted as an operand) is equivalent too: the `-` prefix test excludes `--` already; its control row (`rm -- >$(echo ..) -rf <dir>`) stays. Tests: `destructive-gate.test.py` 2,465 rows (2,393 + 72), `git-config-programs.test.py` 450, `git-hook-switch.test.py` 439.

Named limits: a command substitution inside DOUBLE quotes in an assignment (`x="$(date) rm"`) is one word, nothing runs; a `$(` behind a command word (`echo $(date) rm -rf x`) is an argument. The segments that a
substitution body forms are checked as before. A heredoc body, a `case` branch (card bdcfa13a) and the `builtin` wrapper (card f64fcef1) are other cards.

## Round 2 of card 46f43d1a: characters glued behind the closing parenthesis (Sam, `s4.out a20`)

`x=$(echo a)b rm -rf <dir>`: the shell reads `x=<output>b` as ONE word, the assignment, and runs rm. Round 1 made the `)` a border but started the next segment right behind it, so `b rm -rf <dir>` read as a
command `b` with arguments. The same holds for any glued text: more letters, a quoted string (`"b c"`, `'b c'`), a second substitution (`$(echo b)`), a `${..}`, an arithmetic expansion, `$'..'`, an escaped blank, a
redirection target with a tail (`>$(echo f)g rm`), and an assignment after the tail (`x=$(a)b y=$(c)d rm`).

Change, in `segments_pos` only: the segment that starts right behind such a border is a TAIL segment (`tails`). Its first word, up to the first unquoted, unescaped blank (`_glued_tail_end`; a `${..}` body counts as
part of the word), is the rest of the value and is dropped; the command begins behind that blank. A `$(` met while the tail word is still open is a border again (the word continues after its `)`); behind a
blank the old prefix test applies to what is left (`x=$(a)b y=$(c)`: the prefix ` y=` holds no command word). An empty tail (a blank or a delimiter right behind the `)`) changes nothing.

Measured: 40 shapes of the class against real bash with a canary directory: round-1 head 27 holes, this head 0 (and the 3 shapes added afterwards, `$[ 1 + 2 ]`, `<(echo b)`, `$(( 1 + 2 ))`, also 0);
14 quiet controls (`x=$(echo a)b echo ..`, `x=$(echo a)rm -rf <dir>`, which runs a command called `-rf`, `echo $(echo a)b rm`, a tail and a newline or `;`) allowed on both. Sam's 372 shapes of s1 to s4
(real bash, canary directory): exactly ONE verdict differs between the round-1 head and this head, `s4 a20` (rc 0 -> rc 2); the 99 shapes that still run belong to other cards (6b631f69, e766e16c), the 17 shapes that
do not run and are refused are the same 17. Price (the corpus run, OLD = the round-1 head from its own worktree, 34,588 unique Bash commands): 33,080 allowed on both, 1,508 denied on both,
**0 newly allowed, 0 newly denied**. Mutants (`deecccda-mutants/mutants_subst_46f43d1a_r2.py`): 11, 11 killed (three needed one more row each: a tab alone, the end of the word after a trailing backslash, a nested
`${..}` that closes before a blank of the outer one). Tests: `destructive-gate.test.py` 2,546 rows (2,465 + 81: 33 shapes with their real-bash fixtures and refusals, 14 quiet, the `_glued_tail_end` unit row),
`git-config-programs.test.py` and `git-hook-switch.test.py` pass.

Named limit: the tail word is judged by the quote map and a fixed list of blank-holding constructs (`${..}`, `$[..]`, `<(..)`, `>(..)`; `$((..))` and `$(..)` are cut by the segmenter before). A blank in a
construct outside that list ends the tail early; the text then reads as a command, which is the loud direction. The commands INSIDE a skipped `<(..)` or `$[..]` are not segmented (card e766e16c for the process
substitution).

## Round 3 of card 46f43d1a: function substitutions, `$[ .. ]`, function bodies, escaped separators (Sam's frozen list, cards 40650fd7 and the 95d0cbc5 `x=a\&c` regression)

Sam's round-2 review (`s6.out`, `s7.out`) froze the list: a20, t13, t38, c6, w6, c4, c12, c13, B1 `x=$[ 1 + 2 ] rm`, C1 `x=${ echo b; }d rm`, C2 `x=a${| REPLY=b c; }d rm`. Four causes, one head:

- **A function substitution is a command list** (`${ cmd; }`, `${|cmd;}`, bash 5.3). `segments_pos` cut it at the inner `;` and left `}d rm ..` as a segment whose command word was `}d`. Met where a command is still to come
  (or while a glued tail word is open) it is now cut like `$(..)`: the body is segmented, the matching brace (`_matching_brace`) is a border, the glued rest behind it is dropped, the command comes after the next blank.
- **The legacy `$[ .. ]` nests brackets** (`$[ a[1] + 2 ]`, measured with bash) and is ONE word part: `_legacy_arith_end` serves `_glued_tail_end` and `_token_spans`, which took the blanks inside for word breaks (`x=$[ 1 + 2 ] rm` read `1` as the command).
- **A function header in front of the assignment** (`f() { x=$(echo a) rm .. }`, `g() ( .. )`, `function f { .. }`) made `_command_still_to_come` see a command word; the header (`_FUNC_HEAD`) is taken off the prefix first (keywords and braces are skipped by `command_index`).
- **An escaped separator is a letter of the word** (card 40650fd7): `x=a\;c rm`, `x=a\|c rm`, `>a\;c rm`, `FOO=a\;b rm`. `segments_pos` skips an escaped `;`, `|`, `&` (a backslash pair is taken as a pair, so `x=a\\;rm` still cuts), and `_is_background_amp` refuses an escaped `&` (the `x=a\&c rm` regression of 95d0cbc5, since 44fac9eb).

Measured (real bash, canary directory, Sam's 156 shapes of s4 to s7): holes on the round-2 head 24, on this head 3: `x=<(true) rm` (process substitution body, card e766e16c) and `x=${Y:-a b} rm`, `x=${Y:-a b} y=1 rm` (the tokenizer, card 6b631f69, closed on that line).
All 21 shapes of the frozen list and of the escaped-separator class are refused and the shell really ran each of them. One verdict goes from refused to allowed, `echo a\;rm -rf <dir>` (the shell does NOT run it: `a;rm` is an argument of echo);
so do the `find .. -exec echo {} \; rm -rf <dir>` forms (find rejects the stray `rm` as a path). Price (corpus run, OLD = the round-2 head from its own worktree, 34,588 unique Bash commands): 33,080 allowed on both, 1,508 denied on both, **0 newly allowed, 0 newly denied**.
Mutants (`deecccda-mutants/mutants_subst_46f43d1a_r3.py`): 18, 15 killed. The 3 survivors are equivalent: the escaped `&` is guarded twice (in the segmenter and in `_is_background_amp`; each alone is covered by the other), and the keyword strip I first wrote in front of `command_index`
was dead code (`command_index` skips keywords and braces itself), so it was removed rather than kept. Tests: `destructive-gate.test.py` 2,630 rows (2,546 + 84: 27 shapes with real-bash fixtures and refusals, 3 escaped-argument controls with fixtures that the shell does NOT run them, 18 quiet controls, 6 unit rows),
`git-config-programs.test.py` and `git-hook-switch.test.py` pass.

Measured outside the list: the backtick form of the class (`` x=`echo a`b rm ``, also inside a function body) is refused on this head (the live gate allows the glued forms, rc 0 with the shell running rm; why this head refuses them was not analysed, so there is no row pinning it).
Named limit: the commands inside a skipped `<(..)` / `$[..]` are not segmented (card e766e16c for the process substitution).
## Round 2 of card 6b631f69: the shell cuts a word at `<` and `>` too (Sam 4575)

Round 1 read a redirection that stands BEHIND a blank. The tokenizer (`_token_spans`) cut words at blanks only, but bash cuts them at the metacharacters `<` and `>` as well: `nohup>f rm -rf x`,
`rm>f -rf x`, `env>f rm`, `if>f rm; then :; fi`, `git>f push --force`, `env -u>f X rm`, `timeout -s>f KILL 5 rm` are a word and a redirection, and the command runs. The glued word (`nohup>f`) matched no
rule, so the real command name was never met. A `${..}` with a blank in it (`>${X:-a b} rm`, `x=${Y:-a b} rm`) was cut at the blank, so the redirection target ate the first half and `b}` read as the command.

Three changes, all in the token reading:
- **`_token_spans`** cuts a word at an unquoted `<` or `>` that is not a `<(` / `>(`. The digits or `{name}` in front of the operator (`2>`, `{fd}>`) and the `&` of `&>` stay with it; an operator run
  (`>>`, `>|`, `<<<`, `&>>`) is not cut inside; a backslash-escaped `\>` is a letter of the word.
- **`${..}`** is ONE word part (`_param_brace_end`: unquoted braces, nesting, a backslash takes the next character). `${ cmd; }` and `${|cmd;}`
  (bash 5.3 function substitutions, card 8ed4c8e8) are NOT word parts: a blank or a bar right after `${` leaves them to the old reading. (The first version also marked such a word as "spaced", like a
  quoted blank; that was wrong, see round 3 below.)
- **`command_index` and `_after_wrapper`**: a redirection between an option and its value (`env -u >f X rm`, `exec -a >f nm rm`, `timeout -s >f KILL 5 rm`, `xargs -I >f {} rm`) is taken out before the value is skipped.

Measured (real bash with a canary directory, Sam's 317 shapes of s1 to s3, `lp-935f`): holes 108 on 935f702c, **14** on this head. The 14 belong to two other cards: `cat <(rm ..)` and `echo >(rm ..)` (the process
substitution body, e766e16c) and twelve `>$((1 + 1)) rm` targets (the `$(` cut of the segmenter, card 46f43d1a). Shapes that bash does not run and the gate refuses: 15 -> 26; the eleven new ones are
`<${X:+a b} rm`-like (an input redirection from a file that does not exist: the shell stops, the gate cannot know). Corpus price (OLD = 935f702c from its own worktree, 34,588 unique Bash commands):
33,075 allowed on both, 1,507 denied on both, **0 newly allowed, 6 newly denied**, all six the same kind: a python heredoc with a line that glues a comparison to a variable named dd (`if dd>10: ...`; one of the six is `if dd<=7`). The gate reads the body lines of an
interpreter heredoc as shell segments too, and `if dd > 10:` with blanks was refused on 935f702c already; the glued spelling now follows it (dd is a forbidden command name). Mutants
(`deecccda-mutants/mutants_6b631f69_r2.py`): 14, 13 killed; the survivor (the `|` in the operator-run pattern) is equivalent: the pattern is only asked when a `<` or `>` is met, and a `|` in front of one
belongs to an operator that is already inside the run. Tests: `destructive-gate.test.py` 2,497 rows (2,393 + 104), `git-config-programs` and `git-hook-switch` pass.

Named limits: a glued `<(` or `>(` (`cat<(ls)`) stays one word (bash itself reports a syntax error there); the commands INSIDE a process substitution are card e766e16c. An unterminated `${` stays as before.
The python-heredoc `if dd>10` false deny above is the old line-as-shell reading of interpreter bodies, not changed here.

## Round 3 of card 6b631f69: an unquoted `${X:-rm -rf x}` is a command built by an expansion (Sam, 3ff20e4d)

Round 2 made `${..}` one word and, with a blank inside it, flagged the word as "spaced" (the quoted-blank flag). Both hid a command from the rule of card 8ed4c8e8 (a command word built by an expansion is
refused): `${X:-rm -rf x}`, `${X:- rm} -rf x`, `${X:=..}`, `${X-..}`, behind `nohup`, `env`, `if`, `time`, an assignment, a separator, with a tab for the blank, nested (`${X:-${Y:-rm} -rf x}`) and the git
push form ran in bash (X unset: the expansion is word-split) and were refused on 935f702c. The reason is not the flag alone: `_bare_expansion_flags`, which tells the rule which token holds an expansion, still
split the text at the blanks inside the braces, so its list was longer than the token list and the rule stayed silent (it needs both lists to agree).

Two changes: the "spaced" flag for a `${..}` word is gone (the shell word-splits an UNQUOTED expansion; only a quoted blank is inert), and `_bare_expansion_flags` reads a `${..}` as one word exactly as
`_token_spans` does (same `_param_brace_end`, same function-substitution exception), so the two lists agree again.

Measured: Sam's regression list (`lp-3ff2` s4 and s5, 106 shapes, real bash with a canary directory) and the 317 of round 2: no shape that bash runs and the previous head refused is allowed any more; the remaining
runs-and-allowed shapes belong to other cards (`case` arms bdcfa13a, process substitution body e766e16c, `>$((..))` and `x=${X:-$(echo a)}b` targets 46f43d1a). Tests: `destructive-gate.test.py` 2,526 rows (2,497 + 29:
14 shapes with their real-bash fixtures and refusals, two units). Price and mutants: see the commit message.

# A heredoc body handed on to a shell or an interpreter (card 6a6191f4)

`cat <<EOF | sh` followed by a plain `rm -rf <protected>` in the body was rc 0 on the destructive gate and on every head of the chain
(Sam 4218, measured in the first round of card f4649c5d), while `echo 'rm -rf <protected>' | sh` was denied only while the shell word was bare (Sam, round 1: `| sh 2>&1`, `| "sh"`, `| s\h` and
`| . /dev/stdin` passed on the live gate too; the second round of this card closes them). The gate read the
opener COMMAND (`cat`) to decide whether the body is a program or data, and `cat` only copies it; the shell at the other end of the
pipe is what runs it. The body of a heredoc is a program when ANY consumer of it runs it, not only the command written in front of `<<`.

What is read now (`_heredoc_piped_to_program`, `_heredoc_opener_runs_body`, `_shell_s_flag`; the body goes the same way as the body of
`bash <<EOF`, which was always judged):

- **A later stage of the same pipeline** is a shell or an interpreter that takes its program from stdin (`_stdin_program_sites`: no
  program file named, no `-c` string): `| sh`, `| bash -s`, `| bash -`, `| env sh`, `| tee x | sh`, `| tr a b | sh`, the group forms
  `{ cat <<EOF; } | sh` and `( cat <<EOF ) | sh`, and the pipe that ENDS the opener line with the reader on the line after the
  terminator (`cat <<EOF |` ... `EOF` `sh`). A stage that names a program FILE (`| sh x.sh`) or carries its code in `-c` reads the body as
  data. `||` and `&&` are not pipes. A `|` inside quotes is text.
- **`-s` means stdin whatever follows** (`bash -s -- x`, `sh -s a b`; `-o posix -s`): the words after it only set the positional
  parameters. Measured with real bash: `printf 'echo hi' | bash -s -- x` runs it. The file-name test below `_interp_opts_scan` took `x`
  for a program file, so `echo 'rm -rf <protected>' | bash -s -- x` was rc 0 too, with or without a heredoc (found while testing this
  card). A `-c` in the same group wins, as in bash.
- **The program file is the stdin device or a substitution**: `bash /dev/stdin <<EOF`, `sh /dev/fd/0 <<EOF`, `. /dev/stdin <<EOF`,
  `source /dev/stdin <<EOF`, `sh <(cat <<EOF` ... `)`, `source <(cat <<EOF` ... `)`.
- **A redirection on a compound command** feeds what is inside it: `{ sh; } <<EOF`, `if ...; sh; fi <<EOF`.

Measured against the real bash (`destructive-gate.test.py`, the "6a6191f4" block): for each of 37 shapes the same text with a `touch`
body was run, and the gate blocks EXACTLY those where the file appeared (37 of 37 agree, 23 really ran). 27 of the new rows fail on the
chain head `8d8a6700` and pass on this one.

Named limits, measured rc 0 on this head and NOT closed here: (a) an UNKNOWN shell reading stdin (`dash <<EOF`, `ksh`, `cat <<EOF |
dash`): the family list is not extended (card 7fd3134e's lesson); a known-data-consumer allowlist for heredoc openers is the inverted
fix and its price is not measured; (b) the body passed on as an ARGUMENT or through a loop (`... | xargs -0 sh -c`, `| while read l; do
$l; done` is denied but by another rule), or written to a file and run afterwards (`tee x.sh <<EOF; sh x.sh`); (c) `eval "$(cat <<'EOF'`
... `)"` and the substitution forms of `eval` (card 30500dad).

Price, final verdict (`check_bash`, the main-checkout view, in process), chain head `8d8a6700` against this head, over ALL 32,632 unique Bash
commands of the agents' transcripts: 31,144 allowed on both, 1,488 denied on both, **0 newly denied, 0 newly allowed**: no command of the
corpus has a heredoc piped into a shell, so the price of this card is zero by measurement and the rows above are the proof the rule fires.
Mutants (13 of 14 killed): the one survivor, the `-c` check inside `_shell_s_flag`, is redundant by construction (a `-c` group already
returns `code` from `_interp_opts_scan` before that function is asked).
Tests: `destructive-gate.test.py` 1,640 PASS (was 1,595), `git-config-programs.test.py` 448, `git-hook-switch.test.py` 439, 0 FAIL.

## Round 2 of card 6a6191f4 (Sam 4358 / comment 1837: the frozen list)

Round 1 closed `cat <<EOF | sh` and 40 neighbours; Sam's class measurement found more shapes of the same class, all run by a real shell and all passed:

- **Redirections after the shell word** (CRITICAL 1, also on the live gate): `| sh 2>&1`, `| sh 2>/dev/null`, `| bash 0<&0`, `| sh 1>/dev/null`, `| sh &>/dev/null`.
  `_interp_opts_scan` took `2>&1` for a program FILE. Now an output redirection (`>`, `N>`, `>&N`, `&>`, `{fd}>`) is skipped with its target word and the scan goes on
  (also after `--`); one that re-points stdin (`<`, `N<`, `<&N`, `<<`, `<<<`) ends the scan: the program then comes from somewhere the gate does not read, a site.
- **The shell word quoted or escaped** (SEVERE 1): `| "sh"`, `| s\h`, `| 'bash' -s`, `| b"as"h`. `_stdin_program_sites` reads an UNQUOTED, UNESCAPED view of the
  text and takes a match only as a whole word (the characters on both sides are real separators or the slash of a path, never the inside of a quote).
- **Sourcing stdin on the pipe side** (SEVERE 2): `| . /dev/stdin`, `| source /dev/stdin`, `/dev/fd/0` are sites (round 1 had only the opener side).
- **`-c` code that itself reads stdin** (SEVERE 3): `| bash -c 'source /dev/stdin'`, `| sh -c 'cat | sh'`: the outer shell is a site when its `-c` code contains one.
- **A group closed on a later line** (SEVERE 4): `( cat <<EOF` ... `EOF` newline `) | sh`, the same with `{ }`: `_heredoc_piped_to_program` reads the pipe that follows the closer.
- **Numbered descriptors** (SEVERE 5): `bash /dev/fd/3 3<<EOF`, `exec 3<<EOF` ... `sh <&3`, `. /dev/fd/4` (`_heredoc_fd_read`: the body is a program when a shell or interpreter
  reads that descriptor; `cat <&3` leaves it data).
- **The false sentence** (SEVERE 6): "`echo '...' | sh` was always denied" is gone from this section and from the code comment; it was denied only while the shell word was bare.

Measured, a real shell with a `touch` body for every shape: Sam's two lists (74 + 16 shapes) and the 43 shapes of this round leave only the named limits below; a random
differential of 3,000 producer | wrapper shell-word option redirection shapes (2,673 of which the shell ran): round 1 passed 2,335, this head 0. 40 shapes are refused although
the shell does not run them (`sh - 2>&1 -s`, an option after the lone `-`; `sh -c 'source /dev/stdin'`, where `sh` is dash and has no `source`): loud, named.
Price (final verdict, in process, the round-1 commit against this head, over ALL 33,619 unique Bash commands of the transcripts): 32,126 allowed on both, 1,493 denied on both, **0 newly denied, 0 newly allowed**.
Tests: `destructive-gate.test.py` 1,904 rows (1,801 + 103: round 1 45, round 2 58), `git-config-programs` 448. Mutants (`deecccda-mutants/mutants_6a6191f4_r2.py`): 17, 16 killed;
the one alive (the character after the word is not checked) is equivalent: a quoted character after the word is taken for an argument word by the option scan anyway.

Named limits (unchanged, other cards): an unknown shell reading stdin (`| dash`, ksh: card 664e45dd; on this machine `/bin/sh` is dash and `sh` is covered), `xargs sh -c`, a script written
and then run (`tee x.sh` / `. ./x.sh`), `eval "$(cat)"` (card 30500dad).

# A `$'..'` word is what bash makes of it (card 4b42b6b0)

`$'\x72m' -rf <dir>` runs `rm`: inside `$'..'` bash expands the escapes (`\xHH`, `\NNN`, `\uHHHH`, `\UHHHHHHHH`, `\cX`, `\n`, `\t`, `\\`,
`\'` ...) before the word is used. The gate's tokenizer dropped the quote characters and kept the spelling, so the command word was
`$\x72m`: a word no rule knew, and the shape of a variable name test (`$rm`) it did not match either. `$'rm'` was refused only because
its spelling looked like the variable `$rm`; `r$'m'`, `$'r'm`, `$'\162m'`, `env $'\x72m'`, `x=1 $'\x72m'`, `$'g\x69t' push --force` all went
through (measured on the live gate by Sam, 4320, and again here against the real bash: the word `rm` or `git push` written in random
encodings, bash defines `rm()` / `git()` as functions that print RAN, a hole is "bash ran it and the gate passed it": the previous head
passed 5,110 of 6,442).

What changed: `_shell_scan` reports every `$'..'` it meets at command level (the offset of the `$` and the span of its inside), and
`_tokens` replaces each by its VALUE (`_ansi_decode`: simple escapes, octal up to three digits, hex up to two, `\u` up to four, `\U` up to
eight, `\cX`, the bytes read as UTF-8, the word ending at a NUL byte, an unknown escape kept as it is), glued to the plain parts around it. Every
rule that reads tokens (the command name, the wrappers, the paths, the git subcommand, `git -c`) now sees what the shell passes. A
`$'..'` inside double quotes is plain text (the shell does not expand it there) and stays so, also inside a `$(..)` that sits inside double
quotes.

Measured with the same method after the change: 0 of 8,000 random encodings (6,442 that bash ran). One row of
`git-config-programs.test.py` changed meaning ON PURPOSE: `git -c $'user.name=a' status` was pinned as a deny because the ANSI-C word could
not be read ("harmless today, but not READABLE here"); it is read now and harmless, so it moved to the allowed list, and two deny rows were
added for the same word with a dangerous key spelled with an escape (`core.fsmonitor\x3dtouch m`, `core.\x66smonitor=touch m`).

Named limits: only `$'..'` is expanded (the other forms of word expansion are as before: `$"..."` and variable names are still refused as a
command name, a brace expansion is not read); the decode does not claim locale-specific behaviour for bytes that are not valid UTF-8 (they are
kept as bytes); a `$'..'` that the shell reader cannot place (`_ScanUnsure` unsure) is not expanded, and the command is refused one step
earlier (card 798c3c24) for the whole command.

Price, final verdict, in process, the main-checkout view, the head of card 798c3c24 (`3d947cce`, loaded from its own worktree) against this
head, over ALL 33,160 unique Bash commands of the transcripts: 31,669 allowed on both, 1,491 denied on both, **0 newly denied, 0 newly allowed**.
Tests: `destructive-gate.test.py` 1,736 rows (1,692 of the previous head and 44 new: nine command-name fixtures that bash really runs,
the refusals behind `env`, an assignment, a separator, the git word, a path argument, six quiet controls, the decoder and tokenizer units, a
500-string end-to-end differential of random encodings), `git-config-programs.test.py` 450 (448 + the row above and its two new rows).
Mutants (`deecccda-mutants/mutants_4b42b6b0.py`): 14, 13 killed; the one that lives (the closing quote not skipped by `_tokens`) is
equivalent, the quote is then skipped by the ordinary quote-character rule one step later.

## Round 2 of card 4b42b6b0 (Sam 4426 / comment 1859: the frozen list)

Round 1 made a `$'..'` word its value. Sam's class measurement (a real shell and a jail canary) found the same command written two more ways that the
gate still passed, and the decoder differing from bash:

- **A brace expansion in the command word** (live hole): `{rm,-f,X}`, `r{m,} -f X`, `{r,}m -f X`, `{r..r}m -f X`, `{git,push,--force,origin,main}`, `gi{t,} push --force`.
  The shell expands the word into the command and its arguments; the gate read it as one unknown word. (Round 1 named it as a limit; Sam showed it is the same class.)
- **A glob in the command path** (live hole, not named before): `/usr/bin/r[m]`, `/usr/bin/[r]m`, `/usr/bin/r?`.
- **`_ansi_decode` against bash** (MEDIUM): `\\c?` is 0x7f (not 0x1f); `\\c\\\\` is ONE control-backslash that takes both backslashes; `\\u` / `\\U` write any
  value the way bash does (a surrogate, a value past U+10FFFF, up to six bytes); in a printf format or `echo -e` text `\\c` ends the output instead.

Inverted direction (card 4b42b6b0's own rule): the command word of a segment (behind `env`, an assignment and the other wrappers too) that is written as a brace expansion
(`{rm,-f,x}`, `r{m,}`, `{r,}m`, `{r..r}m`: a `{..}` with a `,` or `..` inside, in a word made of name characters with at least one letter) or as a glob in a PATH (`/usr/bin/r[m]`,
`/usr/bin/r?`, `./x*`: a word that starts with `/`, `./`, `../` or `~/`) is not provable, so it is refused. `_bare_meta_flags` keeps the information the token list drops (whether the
character stood in a quote; round 3 below replaces both helpers). The first, wider form (any unquoted brace or glob character in a command word) refused 66 of 33,712 real commands: python text split into "commands", case arms
(`*) ...`), jq filters, `${x%%|*}` pieces; the shapes were narrowed to the spelled-out ones and the lossy payload reconstruction (`_HM_LOSSY`: the string literals of a python shell-out joined
without their context) is not checked. The shell's own words `[`, `[[`, `]`, `]]`, `{`, `}` and `!` and all arguments stay untouched (brace and glob arguments of `ls`, for instance).

The third item of the list, an ENCODED path to `.env` (`cat $'.\\x65nv'`, `cat .{e,}nv`), is NOT closed here: the `.env` rule of this gate is a pattern over the raw text, the decoded
word does not reach it, and the credential gate covers the file (named limit, as Sam suggested).

Measured: the decoder against the real bash on 800 random `$'..'` bodies in the test (0 byte differences) and on Sam's differential (4,000 bodies per seed: 747 differences before,
none that bash itself accepts as one word after: the few left are bodies where an unescaped quote ends the word early, which the gate's scanner sees the same way); the brace and
glob shapes run by a real shell in a jail: all refused; the random encodings of the word `rm` / `git push` (rounds 1 and 2 together) against the previous head: 3,715 of 4,761 holes -> 0.
Price (final verdict, in process, the 6a6191f4 head `9582e493` against this head, over ALL 33,760 unique Bash commands of the transcripts; it includes the whole card, round 1 too): 32,266 allowed on both, 1,493 denied on both, **1 newly denied, 0 newly allowed**. The one: a jq filter `{id,label,createdAt,updatedAt}` that the old segmenter cuts out of its single-quoted program and that has the shape of a brace expansion (loud, named).
Mutants (`deecccda-mutants/mutants_4b42b6b0.py`): 23, 20 killed on the last full run; the lossy-payload one was killed by a row added afterwards (checked by the suite, not re-run in full); the other two live: the closing quote is not skipped (equivalent) and a reserved word is flagged (now redundant: the narrowed shapes never match the shell's own words).
Tests: `destructive-gate.test.py` 1,988 rows (1,948 + 40), `git-config-programs` 450.

Named limits (new): the check looks at the command word only (a glob or brace in an argument is the argument's business: it is judged by the rules of the command; a bare-name glob such as `r[m]` needs a file of that name in the working directory and is not checked; a python payload that shells out a brace-named command is not checked, see `_HM_LOSSY`); an encoded or globbed `.env`
path (the credential gate); (round 3 closed: a word the token list and the quote scan count differently, an empty `$''`.)

## Round 3 of card 4b42b6b0 (Sam 1901: brace and glob in the command word, fail-open on a count mismatch)

Round 2 closed the shapes the card named; Sam's class measurement (a real shell and a jail canary) found the same hole open in forms neither the card nor the docs named. The round-2
check was a narrow regular expression over the word the token list handed over, and that was the weakness: it gave up when the word held a `$`, an `=` or a quoted space, it did not run at
all when the token count and the word count differed (a closing `$''` or `$'\0'`), and it knew a glob only in a path that starts with `/`, `./`, `../` or `~/`. Round 3 replaces the
expression by a reading, in the direction of the card's own rule (silent only on proof). It supersedes the round-2 paragraphs about `_bare_meta_flags` and the narrow shapes.

1. **`_unreadable_command_word`** looks at the command word (token `idx` of the segment, behind `env`, an assignment, `command` and the other wrappers) and refuses it when it holds
   - an UNQUOTED brace expansion: a `{..}` with a `,` or `..` at its own level, whether or not the word also holds a `$`, an `=`, quotes (`{r"m",-f,X}`) or an escaped space; `${..}` and
     `$(..)` are skipped as the shell skips them, so `${x:-a,b}` is no brace expansion; or
   - an UNQUOTED glob character (`*`, `?`, a `[` with a `]` behind it) in a word that holds a slash. That covers a relative path after a `cd` (`bin/r[m]`), `~user/..`, a class with a comma,
     a `$` or an `=` (`[,r]m`, `[=r]m`), a path through a variable (`$D/r[m]`) and anything behind `command`.
2. **The quote state is the shell's, read from the whole command.** The segments of the old loop come from `scannable` (prose and comments blanked), whose quote map is not the shell's; the
   first price runs of this round refused a `grep -o '...="/...[^"]*..."'` after a python heredoc, a `python3 -c "..."` inside `"$(..)"` and a `declare -A F=( ["k"]="a/b" )` for that
   reason. The check has its own loop over the REAL command (only the data heredoc bodies and the other languages' bodies blanked: they are not shell text; a `-c` program stays, it is
   QUOTED and the recursion checks its content). `_proof_of` gives the quote map and the set of offsets that are command text (`_shell_scan`, strict, the same call
   `_require_same_reading` makes). A word is looked at only if it begins as command text and not inside a place where words are not commands (`_words_not_commands_at`: the elements of
   `name=( .. )`, the inside of `${ .. }`, where a `|` or `;` splits the segmenter's text and not the shell's; a `$(`, a plain `(` and a `{ ..; }` group ARE command positions). The word is
   also read from its segment alone and the two quote maps must agree over it, otherwise it is refused (defensive; no word in the measured corpus reaches it).
3. **A count mismatch is no longer a skip.** `_token_spans` is `_tokens` with the position of every word; `_tokens` is its projection (equal on 68,134 corpus strings), so the command
   word is located by construction and an empty `$''` or `$'\0'` anywhere in the segment cannot move it.
4. `jq -c` is compact output, not a program flag: `jq` joins the closed list of tools whose `-c` string is not code (`_C_FLAG_NOT_CODE`). The jq filter `{id,label,createdAt,updatedAt}`
   that round 2 named as its one false positive was read as a shell program by `_generic_c_ranges`; it is gone with it.

Sam's git side: `{git,push,--force,origin,main}`, `g{i,}t push --force`, `bin/g[i]t push --force` and the spellings with a brace or a class INSIDE the arguments (`git pus{h,}`,
`git push --forc{e,}`, `git push -{f,}`, `git p[u]sh`) were run through a real shell with a recording stub `git`, together with every prefix (`env`, `command`, `exec`, a group, a pipe,
an assignment) and suffix (an escaped space, a quoted space, `$''`, `$'\0'`, an empty word, `--`).

Measured. Real shell in a jail, a canary file for `rm` and a recording `git` for the push; HOLE = the shell really runs the command and the gate passes the same text with the canary
replaced by a protected path. `rm`: 27 spellings (brace in every position, class, star, `?`, with `$`, `=`, quotes, a variable path, `~bin/`, a relative path after `cd`) x 11 prefixes x 10
suffixes, eight seeds of 3,000 (2,833 to 2,855 that bash ran per seed): the previous head 1,455 to 1,536 holes per seed, this head 0. The same inside a wrapper (`bash -c`, `sh -c`, `eval`,
`$( )`, `x=$( )`, `bash <<<`, `| bash`), five seeds of 3,000: previous head 1,381 to 1,446, this head 0. `git push --force`: 22 spellings x the same prefixes and suffixes, seven
seeds of 2,500 (1,925 to 1,957 ran): previous head 482 to 568, this head 0. The older random encodings of `rm` / `git push` (the test's `_name_differential`, `$'..'` pieces): 0.
Price (the corpus run, OLD = the re-picked 6a6191f4 head `362cebbe` from its own worktree, 34,285 unique Bash commands of the transcripts; it includes the whole card): 32,783 allowed
on both, 1,502 denied on both, **0 newly denied, 0 newly allowed**. The first versions of the rule priced 2, then 4 false positives on real commands (the vault listing's `jq -c` filter; a
`grep` pattern with double quotes in single quotes after a python heredoc; a `python3 -c` program inside `"$(..)"`; a `declare -A` literal; each with a row above); round 2's one
(the jq filter) is gone.
Mutants (`deecccda-mutants/mutants_4b42b6b0_r3.py`): 27, 23 killed. The four that live: the disagreement of the two quote readings (defensive; 0 firings on 23,475 corpus commands with a
brace or glob character, as are the two placement errors); the funcdef offset and the placement error, each equivalent ALONE and killed together by a row (`f(){ {rm,-f,X}; }; f`); the data
heredoc bodies left in the real text (redundant: the shell reader skips the body and the command-text test refuses a word that is not command text).
Tests: `destructive-gate.test.py` 2,123 rows (2,064 on the re-picked stack + 59), `git-config-programs` 450, `git-hook-switch` 439.

Found on the way, NOT this card: a single quote inside the program word of `eval` or of a here-string, written as `'"'"'` or as `$'\x27'`, hides the program from the gate:
`eval 'r'"'"'m'"'"' -rf X'`, `bash <<< 'r'"'"'m'"'"' -rf X'`, `sh <<< $'r\x27m\x27 -rf X'` pass on the rollout tip for plain `rm`; `bash -c`, `sh -c`, a pipe into a shell and
adjacent quoted runs WITHOUT the embedded quote are refused. The differential above leaves that spelling out of its wrappers.

Named limits (changed): a count mismatch is closed (by construction); the encoded `.env` path stays with the credential gate; a bare-name glob (`r[m]` with no slash) needs a file of that
name in the working directory and is not checked; a python payload that shells out a brace-named command is not checked (`_HM_LOSSY`); a brace or a glob in an ARGUMENT is judged by the
rules of the command it belongs to (measured for `git`: 0 holes); the shell's own words (`[`, `[[`, `{`, `}`) need no exemption any more (no brace expansion, no glob with a slash).

path (the credential gate); a word the token list and the quote scan count differently (an empty `$''`) is not checked.

# The last part of a command word must not be built by an expansion (card 8ed4c8e8)

`${NOPE}rm -rf <dir>`, `r${NOPE}m`, `"${NOPE}"rm`, `${ }rm`, `r$(echo)m`, ``r`echo`m``: an expansion that expands to nothing (or to the missing letter) in front of or inside
the name makes the shell run `rm`. The gate refused a word that IS a variable (`$x -rf ...`) but not one that merely CONTAINS an expansion, and its segmenter cut
`r$(echo)m` at the substitution, so `rm` never stood in front of a rule (Igor's differential, seed 77: it passed on the live gate, the rollout tip and every head of the chain).
The same cut hid the git subcommand: `git $(echo)push --force origin x` handed the git rules a segment `git` and another that began with `)push`.

Three changes, all in the direction of "a name the gate cannot read is refused":

- **`_bare_expansion_flags`**: for each token of the command segment, does its BASENAME (the part after the last slash) hold an expansion (`$name`, `${..}`, `$(`, a backtick),
  outside single quotes? A dollar before a quote (`$'..'`, `"$'"`) is not one. The part before the last slash may be anything (`$HOME/bin/ls`, `"$D"/run.sh`). A word that is
  a whole variable (`$x`) stays with the rule that already judges it (it passes when the variable was assigned a literal earlier in the same command).
- **`_opaque_substitution`**: a substitution GLUED to a literal in front of it, in the basename of the word that is the command (`r$(echo m) -rf x`, ``r`echo m` ``,
  `/usr/bin/$(echo rm)`), is refused; a substitution in an argument (`echo foo$(date)`), behind an assignment (`x=$(date)`), in a directory part (`/usr/bin$(echo)/ls`) or inside
  `$(( ))` is not.
- **`_git_subcommand_slot`**: a substitution or backtick that stands where the git SUBCOMMAND belongs (`git $(echo)push`, `git -C /tmp $(echo)push`, `git push$(echo) --force`) is refused;
  a substitution that is the value of a global option (`git -C $(pwd) status`, `git -c user.name=$(echo a) status`) or an argument of a subcommand that is already there is not.
  The git word is read with `_cname` (backslashes gone), as everywhere else.

Round 1 measured: the command-name differential with embedded expansions added to the encodings (`${NOPE}c`, `c"${NOPE}"`, `$(echo)c`, `c` + backtick, `${ }c`; `rm` and `git push --force`
in random spellings, bash defines `rm()` / `git()` as functions that print RAN): the previous head passed 2,686 of 4,797 that bash ran, this head 0. The first version of the git rule
left 44 holes of 4,770 (`g\it $(echo)push`: the raw spelling of the word); the second 13 (the same, with `_cname`): 0 now, and 0 on three further seeds (4,762, 4,879 and 4,798 that bash ran) after the price-run fixes.
Price (the corpus run, OLD = 3571373a from its own worktree, 34,441 commands): 32,936 allowed on both, 1,503 denied on both, **2 newly denied, 0 newly allowed**. The two are probe commands of this
card that really do run a command named by `${ }` (bash 5.3.9 prints RAN for `bash -c 'MARK(){ echo RAN; }; ${ }MARK'`), so they are true positives. The first versions of the rule priced 4 and then 3 false positives on real commands
(a `$(grep ..)` glued to a quote in a command whose quote map had lost sync; a `\\$h` and a `[${p:0:1}]${p:1}` in python text); each was fixed with a row (below).

Round 2 (Sam 1903, NEM ZOLD on round 1): the check lives in the real-text loop `_built_by_expansion` (token list plus `_bare_expansion_flags`), and three things were wrong.
- KRITIKUS: a locale string `$"..."` in the command name was not an expansion for the flag (`$"r"m`, `r$"m"`, `'r'm$""`: bash 5.3.9 runs `rm`). An unquoted dollar before a double quote now sets the flag. The token list drops the quotes
  and keeps a bare dollar, so the word-shape check (`_name_built_by_expansion`) learned two more loud cases: a dollar no expansion owns (`rm$""` reads `rm$`; escaped dollars are not counted), and `$$` glued to `{` or `(`
  (`r$""${X}m` reads `r$${X}m`, a PID plus literal text to the old reader).
- SULYOS: three test rows spelled the install path with the user name in it; they use the `GROOT` constant like the rest of the file.
- The chain was built on a head that was not green (30cb91d2); it is rebuilt on the SAM-ZOLD line (798c3c24 round 4, 3432a966, then 95d0cbc5, 6a6191f4, 4b42b6b0).
Measured: the command-name differential (`rm` and `git push --force` in random spellings, now with `$"c"`, `$""c`, `c$""` and the other encodings; bash defines `rm()` / `git()` as functions that print RAN), 4 seeds x 6,000
(51 to 54; 4,757, 4,773, 4,834 and 4,756 that bash ran): the previous head passed 2,954, 2,992, 3,028 and 2,948, the first round-2 draft still 246 to 256 a seed, this head **0 on all four**.
Mutants (`deecccda-mutants/mutants_8ed4c8e8.py`): 26, 24 killed (seven new, for the locale-string clause, the bare dollar, its escape exception and the `$$` glue). Two survive as redundant, checked with candidate rows that did not tell them apart from the real gate: the `endswith('=')` clause
of the glued rule (`command_index` already treats `x=` as no command) and the glued branch of the git slot (`git p$(echo)ush` is refused by the segment rules anyway).
Tests: `destructive-gate.test.py` 2,212 rows, `git-config-programs.test.py` 450, `git-hook-switch.test.py` green.

Round 3 (Sam 4555, NEM ZOLD on round 2; the list is frozen: v10, v11, set1 to set4 of his `lp-8ed4r2` folder, the shapes of this card). Two things were open.
- KRITIKUS: a `/` INSIDE a `${ ... }` in the command word (`r${X/y/z}m`, `r${X%/}m`, `r${X:+a/b}m`, `${X##*/}rm`, `rm${X%/*}`, `g${X/a/b}it push --force`: 21 shapes bash ran).
  `_bare_expansion_flags` cleared its flag at every unquoted slash ("the basename starts here") and did not follow the `${ }` depth, so the `}m` behind the slash was
  read as the whole basename. The slash now counts as a directory border only outside an expansion (a depth counter over `${`, a plain `{` and `}`; spaces inside a
  funsub `${ cmd; }` still split the tokens, as before). The same blindness sat in the glued-substitution rule: `g$(echo)it${X%/*}` was exempt as "a slash behind the
  substitution, a directory part"; `_slash_outside_braces` reads the rest of the word with the expansions skipped, and starts behind the substitution (a slash INSIDE
  it, `"r$(echo a/b)m"`, no longer exempts the word).
- SULYOS: `"r$(echo)m" -rf <dir>`, a substitution glued to a literal inside a double-quoted command word, was the named limit of round 1. It is closed, not accepted:
  `_opaque_substitution` no longer skips a `$(` that stands inside double quotes behind a literal, and closes the quote the word opened (`"r` -> `"r"`) before it reads the prefix.
  A substitution in an ARGUMENT of a command (`echo "a$(date)b"`, `x="a$(date)b"`, `git commit -m "x$(date)y"`, `cat "$(pwd)/f"`) stays quiet.
Measured: the generator of the command-name differential learned the pieces Sam named (`${X/a/b}`, `${X%/*}`, `${X:+a/b}`, `${X//\//}`, `"${X/y/z}"`, `$"${X##*/}"`, a nested
default with a slash, `$(echo a/b)`, a double-quoted glued substitution, a whole word in double quotes): 4 seeds x 6,000 (71 to 74; 3,265, 3,304, 3,292 and 3,274 that bash ran),
the previous head (3571373a) 2,666, 2,665, 2,705 and 2,690 holes, this head **0 on all four** (a first version of the fix left 3, all `g$(echo)it${X%/*}`). Sam's own list
(set1 to set4, 189 shapes): every shape of this card is refused; the 25 still passing belong to other cards (redirection in front of the name 6b631f69, `case` bdcfa13a, `builtin`
f64fcef1). Price (the corpus run, OLD = 3571373a from its own worktree, 34,588 unique commands): 33,081 allowed on both, 1,504 denied on both, **3 newly denied, 0 newly allowed**; the three are probe commands of this card (two as in round 2, one run in this round) that really run a command named by a funsub, so they are true positives. Mutants: 35, 31 killed (nine new). Two survivors are the known redundant ones; two are defensive: the brace counters count a plain `{` inside
`${ }`, which bash does not, and only in the direction of more flagging (checked with candidate rows: none tells the counted from the uncounted reading apart).
Tests: `destructive-gate.test.py` 2,272 rows (2,212 + 60), `git-config-programs.test.py` 450, `git-hook-switch.test.py` 439.

Named limits: an expansion in an ARGUMENT is the business of the rules of the command it belongs to (this card covers the command word and the git subcommand); a python payload that shells
out such a word is not checked (`_HM_LOSSY`); a word whose directory part is built by an expansion is allowed when the basename is literal; `'$x'rm` (a single-quoted dollar, then letters)
is refused although it names no command (loud). (The round-1 limit "a double-quoted glued substitution keeps the old stray-quote guard" is closed in round 3.)

## Round 2 of card 40650fd7: an escaped blank, tab or parenthesis is a letter of its word (Sam, `lp-18b2` s2.out)

Round 1 made `\;`, `\|` and `\&` one letter of the word. Sam measured the whole class ("escaped shell metacharacter", the owner's rule 11 b) and found the rest: `x=a\ b rm -rf X`, `x=a\(b`, `x=a\)b`, `x=a\<TAB>b`, `>a\ b`, `FOO=a\ b\ c`, `f() { x=a\ b rm; }; f`, `x=a\\\ b` all ran `rm` and passed the live gate, the base and the head (not a regression of round 1). The cause was in the two word readers, not in the
segmenter: `_token_spans` ended a word at every unquoted blank, so `x=a\ b rm` became the words `x=a\`, `b`, `rm` and the command was `b`; `_bare_tokens` turned every parenthesis into a blank before the words were read, so `x=a\(b rm` became `x=a\`, `b`, `rm` as well.

Fix: in `_token_spans` an unquoted backslash takes the next character with it, a blank or a tab too (that sets the quoted-blank flag of the word, as a quoted blank does); `_bare_tokens` turns only an unquoted, unescaped parenthesis into a blank (a quoted one keeps the old behaviour). The unit is "an unquoted backslash makes the next character a letter", not a list of characters.

Measured against real bash with a canary directory (`lp-18b2` s1 and s2, 86 shapes; the 11 frozen shapes of 46f43d1a included): every shape that bash runs is refused (holes 8 -> 0). Two shapes go from refused to allowed, `x=a\ rm -rf X` and `x=\ rm -rf X`: the escaped blank ends the VALUE, the command word is `-rf`, bash runs nothing (fixtures). The controls (`x=a\ b echo ok`, `cp a\ b c\ d`, `x=a\ b python3 -c pass`, `ls My\ Documents`) stay quiet.
Price (34,588 unique recorded commands, the 13,000 that contain a backslash, OLD = 18b2357d from its own worktree): 12,344 allowed on both, 655 denied on both, **0 newly allowed, 1 newly denied**: `cat .. 2>&1 | sed 's/\(_authToken=\).*/\1<redacted>/' | head; ..; bash -lc '..'`. The cause is NOT this change: `_stdin_pipe_ranges` takes the sed script for a shell program when a `bash -lc` follows the pipeline after a `;` (the same command without the `\(` shows the range too, `cat x | sed 's/a/b/' | head; bash -lc 'ls'` returns `(True, 's/a/b/')`), and the script was only passed before because its `\(` was read as a blank. Named limit, owned by the heredoc / pipe-into-shell cards (6a6191f4, cfef60f8); the direction is loud.
Tests: `destructive-gate.test.py` 2,677 rows (2,630 + 47), `git-config-programs` and `git-hook-switch` pass.

# The commands behind a case pattern are commands (card bdcfa13a, Sam 4553)

`case x in x) rm -rf <dir>;; esac` ran rm and passed the live gate. The segmenter cut the text at `;` and `;;` only, so the first segment was `case x in x) rm -rf <dir>`: the keyword `case` is skipped, the first word after it (`x`) was read as the command and everything behind the pattern's `)` was its arguments. The same for every later arm (` y) rm ..` has the pattern as its first word), for `;&` and `;;&`, for `(x)` patterns, for `esac` on the next line, inside `if`, `{ }`, `( )`, a function, a loop, behind `time` / `!` / `command` / `env`, and nested.

Fix (`_case_pass`, called at the end of `segments_pos` when the text holds the word `case`): the segments are read in order with a small state machine. A segment whose first word (behind `if then elif else while until do ! { time` and a function header) is `case` must hold `case WORD in`; that head is dropped. What follows is a PATTERN LIST: it ends at the first unquoted, unescaped `)` that is not inside an extglob `@(..)`, `*(..)`, `+(..)`, `?(..)`, `!(..)` (a leading `(` is the optional opener of the arm); the segmenter cuts a pattern at its `|`, so a list may span several segments, joined only by `|`. The text behind the closing `)` is a segment of its own, a COMMAND POSITION: it gets the verdict a top-level command gets. After `;;`, `;&` and `;;&` the next segment starts a pattern list again, `esac` (at a list start or at the start of a body) closes the statement, a statement inside an arm nests. A python / node heredoc body (the foreign ranges of the command) is not read: a line that starts with `case` there is prose or code of another language.
Inverted direction (the owner's rule 11): what the reading does not hold with certainty is refused. That is: a head without `case WORD in` in one segment (an unquoted `$(..)` or backtick in the word cuts it), any delimiter in a pattern list other than `|` (a `$(` there would run), a bare parenthesis in a pattern that is no extglob, and a statement that is not closed by the end of the text. Quoted words (`case "$(uname)" in`) are fine: they are not cut.

Measured against real bash with a canary directory: 48 `case` shapes (arms, alternations, extglob, newlines, `;&`, `;;&`, nested, in `if` / group / subshell / function / loop / pipe, glued `x)rm`, `command` / `env` / `nohup` / `time` / `!` behind the pattern, a group, a subshell, an `if` and a `bash -c` in the arm, after an empty arm, `esac` without `;;`, git push in an arm): shapes that bash runs and the live gate allowed 36 -> **0**. Seven controls (start/stop scripts, `case "$X" in *.txt)`, quoted `case` inside an `echo`, `grep -n case`, `git log --grep=case`, `(a|b)` patterns, an empty arm, a pattern named `esac`) stay quiet. Two shapes are refused that bash does not run, both loud: an arm whose pattern does not match (`case x in y) rm ..;; esac` is judged like the command at the top level) and `case $(uname) in` with an UNQUOTED substitution as the word (named below).
Price (the whole corpus, 34,588 unique recorded Bash commands, OLD = 18b2357d from its own worktree): 33,079 allowed on both, 1,508 denied on both, **0 newly allowed, 1 newly denied**: `case "$SNAP" in /tmp/igor-serve-*) rm -rf -- "$SNAP" && echo torolve;; esac`, a command of this agent that really ran an `rm -rf` of an unresolvable path through the hole; the same `rm` at the top level is refused, so this is a true positive. The 385 commands that contain the word `case` are the only ones the change can move; a first version refused a python heredoc line `case 1: pass` (a false deny, 1 of 385) and now skips the foreign ranges.
Mutants (`deecccda-mutants/mutants_case_bdcfa13a.py`): 22 of this card, 22 killed (the first run left 5: a quoted `)` in a pattern, an escaped `)`, `esac` without `;;`, the offset of a body behind blanks, and a reset of the previous-end offset that turned out to be dead and was removed; each live one got a row). Tests: `destructive-gate.test.py` 2,929 rows (2,810 + 119), `git-config-programs` and `git-hook-switch` pass.

Named limits: `case $(cmd) in` and `` case `cmd` in `` with an UNQUOTED substitution as the word are refused (the head is cut by the substitution; `case "$(cmd)" in` is allowed); a `$(` or backtick inside a pattern is refused; every arm body is judged as a top-level command, also an arm that cannot match; `select NAME in` is not a case statement and is untouched; a `case` inside a `$(..)` is the business of the substitution scanner, which refuses it already.

# builtin is a wrapper, a wrapper chain is followed to its end (card f64fcef1, Sam 4553)

`builtin command rm -rf <dir>`, `builtin exec rm ..`, `command builtin command rm ..` ran rm and passed the live gate: `command` and `exec` were wrappers the command-word reader steps over, `builtin` was not, so the command word was `builtin` itself. Two more spellings in the same family: `builtin eval '..'` (the script of an eval is checked, but only once `eval` is the command word) and a chain of more than twelve wrappers: `command_index` took twelve steps and then returned `None`, "there is no command", which is an ALLOW.

Fix: `builtin` joins `command`, `exec`, `time`, `nohup`, `env` in `_TRANSPARENT` (the command-word reader), in `_ASSIGN_LEAD` (a `PATH=` behind `builtin export` is a PATH assignment) and in `_C_WRAPPERS` (an interpreter behind `builtin` is read like the one behind `command`); and a chain that is not followed to its end is refused (inverted direction): after twelve keywords, assignments and wrappers in front of the command `command_index` blocks instead of returning "no command". Eleven wrappers and the command are followed, twelve are refused.

Measured against real bash with a canary directory (`builtin-f64f.json`, 25 attack shapes and 12 controls: `builtin command`, `builtin exec`, `command builtin command`, `builtin eval`, a built name behind `builtin eval`, thirteen `command`s, `time` / `x=1` / `if` / `&&` / `;` in front, `--`, `-p`, alternating chains, a redirection in the chain, a nested eval): shapes that bash runs and the live gate allowed 18 -> **0**. Twelve controls (`builtin cd`, `builtin echo`, `command -v rm`, `builtin command -v rm`, `builtin type rm`, `builtin printf`, `command ls`, a ten-wrapper chain, `builtin read -r x <<< hi`, `echo builtin command rm`) stay quiet. Two shapes are refused that bash does not run (`builtin rm ..`: "not a shell builtin"; `exec builtin command rm ..`): the command behind `builtin` is judged like the command itself, loud. `builtin source /dev/stdin <<< '..'` and `builtin . ..` were refused already (the here-string rule); the output class of `eval` / `source` stays with card 30500dad.
Price: the same full-corpus run as the case card (0 newly allowed, 1 newly denied, the `case` command named there): the `builtin` entries and the chain bound move nothing in 34,588 recorded commands.
Mutants (`deecccda-mutants/mutants_case_bdcfa13a.py`): 6 of this card (builtin out of each of the three tables, the exhausted chain returning `None`, thirteen steps, eleven steps), 6 killed. Tests: `destructive-gate.test.py` 2,986 rows (2,929 + 57), `git-config-programs` and `git-hook-switch` pass.

Named limits: other wrappers that run their arguments (`sudo`, `su -c`, `doas`, `setsid` chains through unknown programs) keep the rules they had; a chain of more than eleven known wrappers is refused although it may be harmless.

# The first word of a case arm built by a substitution (card bdcfa13a round 2, Sam 2026)

`case x in x) r$(echo)m -rf <dir>;; esac` ran rm and passed round 1, with the variants `$(echo rm) -rf`, `` r`echo`m ``, `r$(:)m`, `"r$(echo)m"`, `x=$(echo) rm -rf` and `g$(echo)it push --force`. At the top level every one of them is refused (the command word is built by an expansion, `_opaque_substitution`; an assignment with an empty substitution in front is `_command_still_to_come`). In an arm the two readers looked at the text from the start of the SEGMENT, which still holds `case x in x)`: the head's words made the prefix of the substitution "a command that is already there", so the substitution was read as an argument.

Fix, two places, both reading from the arm instead of from the segment: (1) `_case_pass` runs `_opaque_substitution` on the text from the first character behind the pattern's closing `)` (blanks and newlines skipped) and refuses with the top-level message; (2) `segments_pos` takes the prefix in front of a glued `$(` / `${ ` from `_arm_cut`, the position behind the last unquoted `)` of the segment so far, so `x=$(echo) rm` in an arm gets the border the same text has at the top level. `_arm_cut` runs only when the text holds the word `case` (`has_case`); every other text is read exactly as before.

Measured against real bash (a canary file in a scratch jail; the gate sees the same text with the canary replaced by `<install>/backups`): Sam's frozen sets (`c`, `o2c`, `o4c`, the 69 + 38 + 16 shapes) plus his z-rows, 137 shapes, 111 of which bash runs: the ones round 1 let through (P5, z1 to z4, z6, z11) are refused, 0 shapes opened, the quiet controls stay quiet. The one shape still open there is `2>&1 r$(echo)m -rf` (a redirection in front of a substituted command word, card 6b631f69, Sam 4740), a different class. In the test file: 12 word shapes (`r$(echo)m`, `$(echo rm)`, a backtick, `r$(:)m`, a quoted word, an assignment with an empty substitution, with a function substitution, two assignments, behind `command`, `env`, a redirection, a substituted `git`) in 11 arm positions (first, glued, parenthesised, second, behind `;&`, newline layout, alternation, in an `if`, in a function, nested, no terminator): each is checked against the real bash and against the same word at the top level, and 13 shapes where the substitution is only an argument or a value stay quiet.

Price (the whole corpus, 36,361 unique recorded Bash commands, OLD = 8100dd3e from its own worktree, both gates loaded in-process with the same cwd): 34,818 allowed on both, 1,543 denied on both, **0 newly allowed, 0 newly denied**, 0 error rows. Mutants (`deecccda-mutants/mutants_case_bdcfa13a_r2.py`): 11 of this round, 6 killed (no check on the arm; the check reading from the case head; the check reading from the next segment; the cut finding no parenthesis; the cut unused; the cut taking the first parenthesis). 5 survive, none a hole: the blank skip in front of the arm (`_opaque_substitution` ignores leading blanks), the cut ignoring quotes (a quoted `)` leaves a stray quote in the prefix, which the reader does not take for a command either way), the funsub branch keeping the old prefix (the `;` inside `${ ..; }` cuts a second segment that is refused on its own), the cut applied to texts without a `case` (stricter, not looser: it is scoped on purpose so that no other text changes) and the cut starting at the parenthesis itself (`_bare_tokens` turns it into a blank).

Named limit: `2>&1 r$(echo)m -rf` (a redirection in front of a substituted command word) is still open outside a case as well; it is card 6b631f69 round 4 (Sam 4740).

# The & of a redirection is not a border (card 6b631f69 round 4, Sam 4740)

`2>&1 r$(echo)m -rf <dir>` ran rm and passed the whole chain, with eleven siblings: `1>&2`, `>&2`, `<&0` and `2>&-` in front, `` r`echo`m ``, `r$(:)m`, `$(echo rm)`, `"r$(echo)m"`, `command r$(echo)m`, `x=1 2>&1 r$(echo)m`, and `g$(echo)it push --force`. Behind `>/dev/null`, `2>/dev/null` and `&>/dev/null` the same words were already refused, and so was `2>&1` behind the command (`ls 2>&1 r$(echo)m` is an argument), which is the boundary Sam measured: the lead has to be a duplicating redirection (`>&`, `<&`) and the word has to be built by a substitution.

Cause: `_opaque_substitution` finds where the command's own words begin by walking back from the substitution to the nearest unquoted `;`, `&`, `|`, newline, `(` or `{`. The `&` of `2>&1` stopped the walk, so the prefix it read was `1 r`: `1` was taken for the command and `r$(echo)m` for one of its arguments (nothing to say, the glued substitution is an argument). The same set of characters decided the "a separator inside the glued prefix means the quote map lost sync, nothing is known" skip, which dropped the finding a second time.

Fix: `_border_at` (a `&` ends a command only where `_is_background_amp` says so, the helper the segment splitter has used since card 95d0cbc5; `;`, `|`, newline, `(`, `{` as before) replaces the character set in both back-walks, and `_has_separator` replaces the `any(c in ';&|\n')` tests of the glued prefix in both branches (the plain glued one and the double-quoted glued one). Nothing else changes: a lone `&`, `&&`, `|&` and an unquoted `;` are borders as before.

Measured: Sam's twelve shapes are refused now; a probe of 11 shapes against the real bash (a canary) found 0 holes. Mutants (`deecccda-mutants/mutants_amp_6b631f69_r4.py`): 9 of this round, 9 killed. Metamorphic check over the denied corpus (1,547 commands, each behind 9 redirection and assignment leads, 13,923 variants): one variant is allowed, a `for .. do` compound behind a lead, which is a shell syntax error in bash and was allowed by the old gate as well. Price: one corpus run covers both rounds, it is in the next section.

# A closed substitution in front of the command word (card 8c16a013, Sam 4779)

`x=$(echo) r$(echo)m -rf <dir>` ran rm and passed round 4. `x=1 r$(echo)m`, `` x=`echo` r$(echo)m `` and `x="$(echo)" r$(echo)m` were refused already (no parenthesis in front, or a quoted one), so only an assignment or a redirection target holding a `$(..)`, `$((..))` or `${ .. }` value slipped through.

Cause: the back-walk of `_opaque_substitution` stopped at the inner `(` of a substitution that was already closed in front of the word. For `x=$(echo) r$(echo)m -rf X` it read the prefix `echo) r`, found `echo` to be the command and `r..` one of its arguments, while the shell runs rm.

Fix: `_walk_back` steps over each closed `$(..)`, `(..)` or `${ .. }` behind the word (its opener is found by `_open_of`, nesting and quotes counted) and returns the prefix with every such group replaced by one word `X`: the prefix of `x=$(echo) r$(echo)m` is `x=$X r`, and the command is `r..`. An unmatched opener is still a border. Both back-walks (the glued word and the substitution as the word) use it.

Measured against real bash (a fake rm and git on PATH, a canary file): 7 words x 13 leads x 4 wrappers, plus 15 quiet controls, all as expected. Mutants (`deecccda-mutants/mutants_closedgroup_8c16a013.py`): 10, 10 killed (the first run left one in the quote handling of the group opener; quoted-parenthesis leads were added to the tests).

Price (the whole corpus, 36,933 unique recorded Bash commands, OLD = 645172b0 from its own worktree, NEW = the head with both rounds): 35,386 allowed on both, 1,547 denied on both, **0 newly allowed, 0 newly denied**. Tests: `destructive-gate.test.py` 4,352 PASS, 0 FAIL.

Named limit: `source <(echo rm ..)` and the `eval` output class are open with or without a lead (cards 30500dad and e766e16c); this change does not touch them.

# Round 2 of card 8c16a013: a process substitution as the value of an assignment (Sam 4854 / comment 2074)

`x=<(echo) r${X}m -rf <dir>` ran rm and passed every earlier head (the live gate, 645172b0, 3806b44e, 894e0686). Nine shapes in Sam's list, all with a command word built by `${..}` behind an assignment whose value is a process substitution: `x=>(cat) r${X}m`, `x=<(:) r${X}m`, `x=<(echo) r${X:-}m`, `x=<(echo) y=1 r${X}m`, `y=1 x=<(echo) r${X}m`, `x=<(echo) "r${X}m"`, `x=<(echo) r${X}m${X}`, the same in a case arm, and `x=<(echo) g${X}it push --force origin main`. The round-1 forms with a substitution (`x=<(echo) r$(echo)m`, `x=$(echo) r${X}m`, `x=<(echo) ${X:-rm}`) were refused already.

Two causes, both closed:

1. **The list of flags and the list of spans disagreed, and the disagreement read as "no expansion".** `_built_by_expansion` takes the expansion flag of the command word from `_bare_expansion_flags(seg)` and the word from `_token_spans(bare)`, and trusted the flag only when the two lists had the same length. Since round 2 of card 6b631f69 `_token_spans` cuts a word at an unquoted `<` or `>` (`x=<` becomes `x=`, `<`), the flag reader does not, so `x=<(echo) r${X}m -rf x` had six spans and five flags, the test failed and the function answered `None`: an ALLOW, found nowhere because no earlier shape had a `<` glued to a word AND a built command word. Fix (inverted): when the lists disagree, the flag is read from the command word's own span, from the part after its last slash (a `$` or a backtick outside single quotes). The agreement path is unchanged.
2. **A nested `$(..)` inside the process substitution cut the text at the inner opener.** `x=<(echo $(date)) r${X}m -rf x` was segmented as `x=<(echo ` and `date)) r${X}m -rf x`: `date` was the command and the word behind the `))` an argument, so cause 1 was not even asked. `segments_pos` already marks the `)` that closes a `$(..)` in an assignment or a redirection target as a border, so the command behind it is its own segment (card 46f43d1a); a `<(..)` or `>(..)` there gets the same border (when no command word stands in front of it yet: `_command_still_to_come`). `diff <(ls) <(ls -a)`, `echo $(date) r${X}m`, `cat <(echo a) r${X}m` have a command in front and are untouched.

Measured against real bash (a canary file in a scratch jail, a fake rm and git on PATH; the gate sees the same text with the canary replaced by `<install>/backups`): 20 leads (`x=<(echo)`, `x=>(cat)`, `x=<(:)`, `x=<(echo) y=1`, `y=1 x=<(echo)`, `x=<(echo $(date))`, `x=<(echo) 2>&1`, `2>&1 x=<(echo)`, `x=<(echo) x=>(cat)`, `env x=<(echo)`, `command x=<(echo)`, a glued `<` or `>` in a value or in front (`x=<f`, `x=>f`, `x=a<f`, `x=a>f`, `>f`, `<f`, `2>f`, `>>f`), a here-string value `x=<<<a`; the backtick lead ``x=<(echo `date`)`` is in the 18 nested shapes, not among the 20) x 9 words (`r${X}m`, `r${X:-}m`, `"r${X}m"`, `r${X}m${X}`, `${X}rm`, `/bin/r${X}m`, `$X`, `r${X}m; true`, ...) x 6 wrappers (top level, case arm, brace group, subshell, if, behind a separator) = 1,080 shapes, 12 more with the git word (`g${X}it push --force`, `git p${X}ush --force`), 140 quiet controls (the same leads in front of `echo ok`, `ls /tmp`, `echo ${X}`, `cat $X`, `echo r${X}m`, `ls ${X}/a`, `true`) and 18 nested-substitution shapes: 1,250 shapes in all, bash runs 808 of them. Holes at the old head (894e0686) **632**, at this head **0**; shapes opened (old refused, new allowed) **0**; quiet controls refused **0**.

Price (the whole corpus, 37,294 unique recorded Bash commands, OLD = 894e0686 from a pinned copy, NEW = this head, both in-process): 35,739 allowed on both, 1,555 denied on both, **0 newly allowed, 0 newly denied**. Mutants (`deecccda-mutants/mutants_psvalue_8c16a013_r2.py`): 9, 6 killed, 3 survive (named below). Tests: `destructive-gate.test.py` 5,046 PASS, 0 FAIL (4,352 + 694: 14 leads x 6 words x 4 wrappers against the real bash with a fake rm / git on PATH and a canary, 3 refusals without a bash fixture, 18 quiet controls, unit checks of `_built_by_expansion` and `segments_pos`).

Named limits: three mutants survive. Each was probed directly with the mutant applied, and the verdicts of the shapes aimed at it do not change: the backtick branch of the own-span flag (the backtick word shapes of the set, `x=<(echo) r`echo`m` and its relatives, are refused at the old head already, by the opaque-substitution rule), the single-quote guard of the own-span flag (`x=<(echo) r'${X}'m`, `'r${X}m'`: allowed with and without it), and the basename cut (`x=<(echo) ${D}/run.sh`, `/usr/${D}/ls`: allowed with and without it). They are not proven equivalent in general, only unreachable by the shapes of this card. The `/bin/r${X}m` and `$'r'${X}m` words are in the test file as refusals without a bash fixture (the fake rm is not on /bin).

# eval joins the EXPANDED words, source runs what a process substitution prints (card 30500dad, Sam 4157)

`eval "$(echo rm -f <dir>)"`, `eval $(..)`, `` eval `..` ``, `eval "echo $x"` (x holding `; rm -f <dir>`), `source <(echo rm -f <dir>)` and `. <(..)` ran the command and passed the whole chain, while `sh -c "$(echo rm -f <dir>)"` and the bare `$(echo rm -f <dir>)` were refused (the command word is built by an expansion). The same family also passed one level down: `eval 'eval "$(echo rm ..)"'`, `eval "eval \"\$(echo rm ..)\""`, `eval 'source <(echo rm ..)'`.

Cause: the script the recursion judged for an `eval` came from `_sub_scripts(toks, idx)` with the tokens of `_bare_tokens`, which blanks every parenthesis. `$(echo rm -f X)` reached the recursion as `$ echo rm -f X `, a command called `$`, and the rule that refuses a command word built by a substitution never met a substitution. `sh -c` was refused by a different path (the quoted `-c` ranges are recursed with their real text). And nothing looked at a process substitution given to `source` or `.` as the file: the existing source reader took only the quoted runs inside `<(..)` as programs, so an unquoted `echo rm ..` in it was not judged.

Fix, inverted proof (rule 11: loud by default, silent only on provably clean), three places:
- **`_dynamic_program_argument`** (called next to `_unreadable_command_word`, from the shell reader's quote map of the real command): the command word is `eval` and its arguments hold anything the shell expands before it uses the words as a program (`_dynamic_in`: `$(`, a backtick, `${`, `$name`, `$1`, `$@`, `$'..'` and `$".."`, `<(` and `>(`; a single-quoted character is literal, in double quotes only `$` and the backtick act, a backslash takes the next `$`, backtick, quote or backslash), or the command word is `source` / `.` and its file (after an optional `--`) is a process substitution. The text is read up to the end of the simple command. A word the reader cannot place, or a command it cannot read, falls back to a plain screen of the line for `$`, backtick and `<(`.
- **`_check_bash`** feeds the REAL words of an `eval` (`_tokens(seg)`, parentheses intact) into the recursion next to the bare ones, so a literal (single-quoted or escaped) `$(..)` / `<(..)` in the argument is judged where it becomes a command.
- A literal `eval` and a `source` of a file go on exactly as before.

Measured against real bash with a fake rm on PATH and a canary file (`probe.py`, the gate sees the same text with the canary replaced by `<install>/backups`). The first 33 shapes of the card (10 `eval`, 8 `source` / `.` and wrapper forms, 3 variables, 12 controls): bash runs 19 of them, the live gate allowed **15**, this head **0**; the six controls that are now refused are the intended price (`eval "$(echo true)"`, `eval "$(ssh-agent -s)"`, `eval "$(pyenv init -)"`, `eval "$(direnv hook bash)"`, `eval "$(date +%F)"`, `source <(echo true)`). The matrix: 17 payloads x 24 wrappers (top level, behind a separator, newline, brace group, subshell, if, for, while, case arm, function, `&&`, `||`, `time`, `!`, `builtin`, `command`, an assignment, two redirection leads, `bash -c`, `sh -c`, a substitution, a backtick, a pipe group), 408 shapes: bash runs 398, holes at this head **0**, shapes opened (old refused, new allowed) **0**. Nested and odd forms (20): bash runs 18, holes 4 on the first head (`eval 'eval ..'`, `eval "eval \"..\""`, `eval 'source <(..)'`, `eval "source <(..)"`: the bare-token recursion), **0** after the real words were fed in. Controls that stay quiet (20 probed against the old and the new gate, 22 in the test file, among them `source ~/.bashrc`, `. ./venv/bin/activate`, `source "$HOME/.bashrc"`, `eval "echo hi"`, `eval 'echo $x'`, `eval "echo \$HOME"`, `eval "true"; echo $(date)`, `diff <(ls) <(ls -a)`): unchanged.

Price (the recorded unique Bash commands that the change can move, those that hold the word `eval` or `source` or a standalone dot: 7,096 of 37,200; OLD = 894e0686, NEW = this head, both in-process): 6,766 allowed on both, 327 denied on both, **0 newly allowed, 3 newly denied**. Two of the three are the same command family: a python or node heredoc (an edit of the egress parser tests) that quotes `eval "$(ssh-agent -s)"` as prose or as a test string; the gate reads the body lines of an interpreter heredoc as shell segments too (the old line-as-shell reading named under round 2 of card 6b631f69), and the real words of that `eval` are now judged. The third is a real use: `eval "python3 scripts/fal.py $args --dry-run"` in a loop over literal argument strings, refused because of `$args`; the same loop without `eval` (an array, or `python3 scripts/fal.py $args` unquoted) is not touched. That is the price of the rule, not a defect of it: an `eval` whose words are not literal is exactly what the gate cannot read.

Mutants (`deecccda-mutants/mutants_dynarg_30500dad.py`): 16 of this card (the rule never fires, the dot dropped, each expansion kind dropped one by one, `isalnum` narrowed to digits, single quotes not protecting, a backslash not escaping, the source operand not looked at, `source --` not skipped, the real words not fed to the recursion, the scan running past the end of the command, the call site gone, the scan starting at the end of the segment), 16 killed. Tests: `destructive-gate.test.py` 5,123 PASS, 0 FAIL (4,352 + 771: 21 payloads x 18 wrappers against the real bash, 22 quiet controls, a unit check of `_dynamic_in`).

Named limits: the nearest neighbours are NOT part of this change and stay open: an unquoted producer word piped into a shell (`echo rm .. | sh`, card cfef60f8) and a shell given a process substitution as its script (`sh <(echo rm ..)`, `bash <(..)`); `trap '..' EXIT` and the other deferred-text commands (card 2bdf8865); brace expansion and a glob in an `eval` word are judged by the old rules only (`eval {rm,-f,x}` is refused by the command-word rule of the script, measured in the nested set above). A legitimate `eval "$(tool init -)"` (ssh-agent, pyenv, direnv, conda) is refused now, in every wrapper: the message says to write the command out, or to ask HEX.
