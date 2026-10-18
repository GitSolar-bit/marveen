#!/usr/bin/env node
// PreToolUse hard-gate: blocks SELF-PACE for sub-agents.
//
// Governance control (2026-06-26, after the autonom-kor incident: a sub-agent
// scheduled its own wakeups via ScheduleWakeup, fed itself prompts, and acted
// on a SELF-GENERATED "A) zárjuk le" decision -- dispatching real development
// -- while the operator slept. Two independent adversarial audits confirmed the
// root cause is the agent's own self-pace loop, not an external vector).
//
// A sub-agent must be INPUT-DRIVEN: it acts on operator / peer messages, never
// on prompts it scheduled for itself. This gate blocks every self-pace path:
//   - the Claude Code runtime tools ScheduleWakeup / CronCreate / CronList /
//     CronDelete / RemoteTrigger (the autonomous-loop machinery), AND
//   - the Bash escape routes that achieve the same self-injection: writing the
//     Claude scheduled_tasks.json directly, tmux send-keys into a session, or
//     POSTing a new schedule to the dashboard.
//
// Why a hook and not only a permissions deny-list: permissive profiles launch
// with --dangerously-skip-permissions. A whole-tool-name deny DOES survive that
// (deny is checked before the bypass allow), so the scaffold also adds these
// names to permissions.deny -- but the Bash-command routes can ONLY be caught
// by a PreToolUse hook, which runs regardless of permission mode. Defense in
// depth: deny-list for the tool names, this hook for the Bash routes (+ the
// names again, redundantly fail-closed).
//
// Wired into every sub-agent's .claude/settings.json by
// writeAgentSettingsFromProfile() (agent-scaffold.ts), guarded by
// name !== MAIN_AGENT_ID, re-applied on every spawn (respawn-safe).

import { spawnSync } from 'node:child_process'
import { readFileSync, realpathSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// The allowlist this install's egress-gate.mjs reads (scripts/ -> repo root -> store/).
const DEFAULT_ALLOWLIST_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'store', 'egress-allowlist.json')

// Claude Code runtime self-pace / scheduling tools. A sub-agent has no
// legitimate need to schedule its own future turns -- it is input-driven.
const SELF_PACE_TOOLS = new Set([
  'ScheduleWakeup',
  'CronCreate',
  'CronDelete',
  'CronList',
  'RemoteTrigger',
])

// Bash command patterns that achieve self-pace by another route. These are
// tested per COMMAND SEGMENT (see splitSegments), so a token in one part of a
// compound command never trips a pattern that belongs to another part.
const SELF_PACE_BASH_PATTERNS = [
  // tmux pane injection -- every write-subcommand that can push keys/text/commands
  // into a pane (the actual incident vector), not just send-keys. [\s\S] (not
  // [^\n]) so an intra-segment newline cannot split the match.
  /\btmux\b[\s\S]*\b(send-keys|paste-buffer|run-shell|set-buffer)\b/i,
  // self-backgrounding that relaunches claude (nohup/setsid/disown + claude)
  /\b(nohup|setsid|disown)\b[\s\S]*\bclaude\b/i,
  // the loop slash-skill driven from a shell. `/loop` must be in SLASH-COMMAND
  // position -- a standalone token (segment-start / whitespace / quote before it,
  // whitespace / quote / end after it) -- never a PATH segment. The old
  // `\/loop\b` fired on any `loop`-prefixed path component whenever `.claude` was
  // in the same command (\bclaude\b matches the `.claude` in every memory/skill
  // path), so reading `.../memory/loop-stop-...md` or `~/.claude/skills/loop/...`
  // was denied (measured 2026-07-26, found by pg: Heli denied a harmless memory
  // read). Same bug class as the at/batch and launchctl fixes below: a keyword in
  // a PATH collided with a call pattern; the fix is to match the invocation SHAPE.
  // Every real form stays denied: `claude /loop 5m`, `claude -p "/loop x"`,
  // `claude '/loop'`, bare `claude /loop`.
  /\bclaude\b[\s\S]*(?:^|[\s'"])\/loop(?=[\s'"]|$)/i,
]

// OS-level schedulers + delayed exec (cron / launchd / systemd / at / batch): the
// shell route to the same self-pace the CronCreate tool-deny blocks at the runtime
// layer. Anchored to command position (segment start), but a leading wrapper is
// allowed before the binary -- sudo/env/command/nice, a VAR=val environment, and
// an absolute/relative path -- so `sudo crontab -r`, `/usr/bin/at now`,
// `PATH=/bin crontab -` are all caught. Trailing \b(?!-) so it never fires on
// "netstat" / "crontab-helper.sh"; (?!\s*=) so a bare NAME=value assignment
// (`at=$(...)`) is not mistaken for the `at` binary.
const SCHED_PREFIX = String.raw`(?:(?:[A-Za-z_]\w*=\S*|sudo|env|command|exec|nice|builtin|time)\s+)*(?:\S*/)?`
// The command-boundary anchor includes `(` so a $(...) command substitution
// (`X=$(crontab -)`) is caught, AND a backtick so a legacy `...` substitution
// (`X=`crontab -r``) is caught too -- both run the enclosed command in a shell
// context, so a scheduler binary immediately inside either is a real self-pace.
const SCHED_BOUNDARY = '[;&|(`]'
// `at` and `batch` are also ordinary English words, and splitSegments splits on
// NEWLINES -- so a PROSE line inside a multi-line commit body ("at least 80% of
// entries", "batch size is 50") lands at a segment start and looked exactly like
// the at(1)/batch(1) binaries. Measured 2026-07-25 (found by JogAsz): a heredoc
// commit message was denied for the words "at least"; the identical command
// passed after rewording that one line. The `-m "$(...)"` form is deliberately
// NOT blanked by stripGitCommitMessages (a real substitution could hide there),
// so the body does reach the splitter -- the fix belongs here, not there.
//
// For these two words ONLY, also require something that looks like an actual
// invocation: end of segment (a bare `batch` reads stdin -- still a real vector),
// a flag, an input redirect, or an at(1) TIMESPEC (which at(1) requires anyway,
// so a real submit can never omit it). crontab/launchctl/systemd-run keep the
// plain match: they are not English words, so prose cannot collide with them.
const AT_INVOCATION = String.raw`(?=\s*$|\s+-|\s*<|\s+(?:now|noon|midnight|teatime|today|tomorrow|next\b|\+\s*\d|\d{1,2}:\d{2}|\d{3,4}\b|\d{1,2}\s*(?:am|pm)\b|\d{1,2}[./]\d{1,2}|(?:mon|tue|wed|thu|fri|sat|sun)|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)))`
// `launchctl` needed the SAME narrowing, for a different reason than at/batch, and
// the comment above ("not English words, so prose cannot collide") was measured
// wrong on 2026-07-26 (found by Hacker). It is not an English word -- but the
// fleet's own heartbeats ORDER every agent to report `launchctl list | grep
// com.jarvis.channels` output, so a launchd JOB LABEL appears in prose constantly.
// splitSegments splits on `;`, so a report line "...; launchctl com.jarvis.channels
// PID 555" put `launchctl <label>` at a segment start and it read as a real
// invocation. His status message was denied; the finding is systemic, not his.
//
// The narrowing mirrors AT_INVOCATION: instead of enumerating dangerous
// subcommands (a denylist -- miss one and it is a hole), require the SHAPE of a
// real invocation. Every launchctl self-pace vector (load/bootstrap/submit/
// kickstart/start/enable/...) takes a SUBCOMMAND word first, so demand that the
// next token could be one: a bare lowercase word, no dot and no slash. A job
// label (`com.jarvis.channels`) and a path both fail that and pass through as
// prose. End-of-segment and a flag stay DENIED -- a bare `launchctl` is
// interactive, still a real vector.
const LAUNCHCTL_SUBCOMMAND = String.raw`(?=\s*$|\s+-|\s+[a-z][a-z-]*(?:\s|$))`
const SCHEDULER_RX = new RegExp(
  String.raw`(^|${SCHED_BOUNDARY}\s*)${SCHED_PREFIX}(?:(?:crontab|systemd-run)\b(?!-)(?!\s*=)|launchctl\b(?!-)(?!\s*=)${LAUNCHCTL_SUBCOMMAND}|(?:batch|at)\b(?!-)(?!\s*=)${AT_INVOCATION})`,
  'i',
)
// ...but allow a pure READ-listing of one's own schedule (parity with the store /
// schedule-API read exemptions): crontab -l, launchctl list/print, atq.
const SCHEDULER_READ_RX = new RegExp(String.raw`(^|${SCHED_BOUNDARY}\s*)${SCHED_PREFIX}(crontab\s+-l\b|launchctl\s+(?:list|print|dumpstate|blame|examine)\b|atq\b)`, 'i')

// The Claude self-schedule store. Blocked for WRITE on any route (a Bash write,
// or the native Write/Edit/NotebookEdit tool); a read/grep is legit diagnostics.
const SCHEDULE_STORE_RX = /scheduled_tasks\.json/i
// Write-intent shell tokens (redirect / tee / in-place edit / dd / copy-move).
const WRITE_INTENT_RX = /(>>?|\btee\b|\bsed\b[\s\S]*\s-i|\bdd\b|\bcp\b|\bmv\b)/i
// Dashboard schedule API. A WRITE method (POST/PUT/PATCH/DELETE) creates/edits a
// self-paced cron; a GET (list / pending / agents) is legit diagnostics -> allowed.
const SCHEDULE_API_RX = /\/api\/schedules\b/i
const HTTP_WRITE_RX = /(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|(^|\s)(--data\b|--data-\w+\b|-d\b))/i

// THE EGRESS ALLOWLIST IS A GATE ON THE SUB-AGENT ITSELF (EGRESSSELFEDIT824).
// store/egress-allowlist.json decides which hosts egress-gate.mjs lets through, and it
// was a plain writable file in the sub-agent's own tree: on 2026-08-24 a nested
// sub-agent added a domain to reach it and removed it afterwards. Its legitimate
// writers are the MAIN agent (on the owner's go) and the owner by hand -- neither runs
// this gate (it is wired for sub-agents only), so neither is affected.
//
// Native file tools: denied on the file name AND on the resolved real path, so a
// relative path or a symlink created earlier does not walk past the name check.
// Bash: FAIL-CLOSED. A segment that mentions the file may only be a plain READ
// (cat/grep/jq/...), and an output redirect in it may not point at the file. An
// interpreter (python/node/...), cp/mv/tee/sed/ln/... or anything else that names the
// file is denied, because whether it writes cannot be read off the command string.
//
// What this gate CANNOT see -- a script that builds the path at runtime, a glob that
// does not spell the name -- is written down, not hidden: the dashboard keeps a hash
// baseline of the file and reports every change, whoever made it, by whatever route
// (src/egress-allowlist-baseline.ts). This gate narrows the casual route; that one
// catches the rest after the fact.
const ALLOWLIST_BASENAME = 'egress-allowlist.json'
// The STORE objects, not the concept: the file and its history directory, or a glob that
// starts on the name (egress-allow*, egress-allowlist.*). A plain /egress[-_]?allow/ also
// matched this gate's own source and test names (egress-allowlist-baseline.ts), so no
// sub-agent could run, stage or diff them -- review on #1678.
const ALLOWLIST_MENTION_RX = /egress[-_]?allowlist(?:\.json|\.history)|egress[-_]?allow[\w.]*[*?[]/i
const ALLOWLIST_READERS = new Set([
  'cat', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'jq', 'wc', 'ls', 'stat',
  'file', 'shasum', 'sha256sum', 'md5', 'md5sum', 'diff', 'cmp', 'echo', 'printf',
])
// Output redirects: `>`, `>>`, `>|`, `&>`, `&>>`, `N>`. The target is the next word.
const OUTPUT_REDIRECT_RX = /(?:&>>?|\d*>>?\|?)\s*([^\s;&|<>]+)/g

export function allowlistBashSegmentAllowed(seg) {
  const s = String(seg ?? '').trim()
  if (!ALLOWLIST_MENTION_RX.test(s)) return true
  const words = s.split(/\s+/)
  let i = 0
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++ // leading VAR=x
  const cmd = (words[i] ?? '').replace(/^.*\//, '')
  if (!ALLOWLIST_READERS.has(cmd)) return false
  for (const m of s.matchAll(OUTPUT_REDIRECT_RX)) {
    const target = m[1]
    if (/^&?\d+$/.test(target) || target === '/dev/null') continue // 2>&1, >/dev/null
    if (ALLOWLIST_MENTION_RX.test(target) || /[$`]/.test(target)) return false
  }
  return true
}

function expandHome(p) {
  return p.startsWith('~/') ? join(homedir(), p.slice(2)) : p
}
function realOrSelf(p) {
  try { return realpathSync(p) } catch { return p }
}

// Does a native file-tool call target the allowlist? `allowlistPath` is the real file
// this install's egress-gate reads; tests pass a tmp one.
export function fileToolTargetsAllowlist(toolInput, allowlistPath = DEFAULT_ALLOWLIST_PATH, cwd = process.cwd()) {
  const raw = String(toolInput?.file_path ?? toolInput?.notebook_path ?? '')
  if (!raw) return false
  if (basename(raw).toLowerCase() === ALLOWLIST_BASENAME) return true
  const abs = resolve(cwd, expandHome(raw))
  return realOrSelf(abs) === realOrSelf(allowlistPath)
}

// Split a compound command into individual simple commands, so a token in one
// segment cannot trip a check anchored in another (e.g. `cat store && cp a b`).
// Line-continuations (backslash-newline) are collapsed FIRST so a single command
// continued across lines stays ONE segment (this is what keeps the
// tmux\<newline>send-keys vector closed); only real separators split.
//
// KNOWN LIMITATIONS (accepted, defense-in-depth -- the runtime tool-deny is the
// primary guard, this Bash hook is a second layer; a sub-agent is not adversarial
// to its own gate, it just must not casually self-pace):
//   - Not quote-aware: a separator INSIDE quotes (e.g. a commit message
//     `git commit -m "fix; crontab -r"`) splits and could false-deny. Rare
//     enough (the quoted ; must be immediately followed by a blocked binary at a
//     segment start) that a full shell-tokenizer is not warranted here.
//   - A $(...) or backtick substitution that assigns a scheduler result
//     (`X=$(crontab -)`, `X=`crontab -``) is caught by SCHEDULER_RX's boundary
//     anchor, which now includes both `(` and the backtick.
export function splitSegments(command) {
  return String(command ?? '')
    .replace(/\\\r?\n/g, ' ')
    .split(/&&|\|\||[;&|]|\r?\n/)
    // trim so a leading-separator segment (" at now") anchors at ^ correctly
    .map((s) => s.trim())
}

// Split like splitSegments, but ONLY on separators the shell would actually
// treat as separators -- never on one that sits inside a quoted string or a
// heredoc body. Returns null when the quoting cannot be resolved with
// confidence, and every caller must then fall back to the naive splitter.
//
// WHY THIS EXISTS (measured 2026-08-05, five denials in one morning -- three
// mine, two taric's): splitSegments is not quote-aware, so PROSE can manufacture
// a command position that never existed. All five denials had the same cause: a
// grep pattern quoted inside an inter-agent message,
//   Minta: stop.sh <bar> launchctl <bar> com.janna.dashboard
// The `<bar>` split it, the middle piece trimmed down to the bare word
// `launchctl`, and SCHEDULER_RX's end-of-segment branch reads a bare `launchctl`
// as a real (interactive) invocation -- correctly, for a real command line.
// Nothing was scheduled; five messages simply never went out. From outside, a
// hard-gate denial is indistinguishable from an agent that stayed silent.
//
// The route decided it: the SAME text passes as `curl -d '<json>'` (the payload
// is blanked by stripDataPayloads) and is denied when sent from a python
// heredoc, which has no -d argument to blank. Choosing how to send a message
// had quietly become a security decision. stripDataPayloads' own comment names
// this false-positive class as its target -- it is implemented for exactly one
// route, so the gap is unfinished work, not an oversight.
//
// SCOPE, and this is the part that matters: the result feeds ONLY the anchored
// scheduler check. The unanchored patterns (tmux+send-keys, nohup+claude,
// claude+/loop) keep scanning naive segments, quoted regions included, because
// they do NOT depend on a command position that prose can fake -- and because
// measurement showed the naive scan is what catches a real
// `subprocess.run(['tmux','send-keys',...])` hidden in a heredoc body. Handing
// them quote-aware segments would have removed the detection of the very
// incident vector this gate was built for, under the banner of a structural fix.
//
// FAIL-CLOSED in three places, because "could not parse" must mean "scan more",
// never "scan less":
//   - unterminated quote or heredoc -> null (caller uses the naive split)
//   - a double-quoted region containing $(...) or a backtick -> null; the shell
//     runs what is inside, so a `;` in there IS a real separator
//   - a heredoc with an UNQUOTED tag whose body contains $(...) or a backtick
//     -> null, same reason (an unquoted tag expands the body)
// NOTE ON THE SHAPE OF THIS FIX. The first attempt made the SEGMENTER
// quote-aware and left the regexes alone. It failed one corpus case:
//   echo 'grep: foo <bar> crontab <bar> bar'
// stayed denied, because SCHEDULER_RX carries its OWN boundary anchor
// (SCHED_BOUNDARY includes the bar), so it re-finds a command position INSIDE a
// segment. Keeping the quoted text in the segment at all was the mistake. The
// `launchctl` cases passed only by luck -- LAUNCHCTL_SUBCOMMAND's lookahead
// happened to reject the following bar. So the primitive is not "split more
// carefully", it is "the inert text must not be there": mask it out, then let
// the existing splitter and regexes run unchanged on what remains.
export function maskInertLiterals(command) {
  const src = String(command ?? '').replace(/\\\r?\n/g, ' ')
  let cur = ''
  let i = 0

  // Inert regions collapse to spaces: the text is gone, and with it every
  // separator inside it -- which is precisely what prose was faking.
  const blank = (s) => ' '.repeat(s.length)

  while (i < src.length) {
    const c = src[i]

    // backslash escape outside quotes: consumes the next character
    if (c === '\\' && i + 1 < src.length) { cur += src.slice(i, i + 2); i += 2; continue }

    // heredoc: <<TAG / <<-TAG / <<'TAG' / <<"TAG"
    const here = /^<<-?\s*(?:'([^']*)'|"([^"]*)"|([A-Za-z_]\w*))/.exec(src.slice(i))
    if (here) {
      const tag = here[1] ?? here[2] ?? here[3]
      const quotedTag = here[1] != null || here[2] != null
      cur += here[0]
      i += here[0].length
      // the body starts after the rest of THIS line
      const nl = src.indexOf('\n', i)
      if (nl === -1) return null // heredoc announced but no body -> cannot resolve
      cur += src.slice(i, nl + 1)
      i = nl + 1
      // find the terminator line (leading tabs allowed for <<-)
      const endRx = new RegExp(`^[ \\t]*${tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*$`, 'm')
      const rel = endRx.exec(src.slice(i))
      if (!rel) return null // unterminated heredoc
      const body = src.slice(i, i + rel.index)
      if (!quotedTag && /\$\(|`/.test(body)) return null // unquoted tag expands the body
      cur += blank(body) + rel[0]
      i += rel.index + rel[0].length
      continue
    }

    if (c === "'") { // literal until the next ' -- a backslash is NOT special here
      const end = src.indexOf("'", i + 1)
      if (end === -1) return null
      cur += blank(src.slice(i, end + 1)); i = end + 1; continue
    }

    if (c === '$' && src[i + 1] === "'") { // ANSI-C: \' does escape
      let j = i + 2
      while (j < src.length && src[j] !== "'") { j += src[j] === '\\' ? 2 : 1 }
      if (j >= src.length) return null
      cur += blank(src.slice(i, j + 1)); i = j + 1; continue
    }

    if (c === '"') {
      let j = i + 1
      while (j < src.length && src[j] !== '"') { j += src[j] === '\\' ? 2 : 1 }
      if (j >= src.length) return null
      const inner = src.slice(i + 1, j)
      if (/\$\(|`/.test(inner)) return null // may run a command -> not inert
      cur += blank(src.slice(i, j + 1)); i = j + 1; continue
    }

    cur += c; i++
  }
  return cur
}

// Blank out curl/HTTP DATA-PAYLOAD arguments before self-pace matching. A -d /
// --data body is data sent over the wire, NEVER a shell invocation, so a trigger
// token that only appears INSIDE the payload must not false-deny. The classic
// false-positive: an /api/messages inter-agent dispatch (a legit peer message in
// a green, operator-authorised review-loop) whose JSON body happens to mention
// "/api/schedules", "tmux send-keys", "scheduled_tasks.json" or "/loop" -- pure
// text, not an invocation. Only PROVABLY-LITERAL payloads are stripped:
// single-quoted '...', ANSI-C $'...', and double-quoted "..." WITHOUT
// $(...)/backtick. A payload that can run a command substitution (double-quoted
// with $(...) / backticks) is left intact so a real command-substitution payload
// is not blanked. Such a payload is then still denied by SCHEDULER_RX, whose
// boundary anchor recognises both `$(` and the backtick as a command boundary,
// so a scheduler binary inside either substitution form is caught. The data FLAG
// itself is kept, so HTTP-write detection (-d /
// --data) is unchanged; the URL and method args live OUTSIDE the payload, so a
// real WRITE to /api/schedules is still denied.
//
// Quote classes match BASH parsing, not C. Inside a plain '...' a backslash is
// LITERAL and the FIRST following ' always closes the string, so the class is
// '[^']*'. A C-style '(?:[^'\\]|\\.)*' would treat \' as an escaped quote and
// scan PAST bash's real closing quote -- e.g. `curl -d 'x\' ; crontab -r` would
// blank the out-of-band `; crontab -r` and let a real self-pace command slip.
// ANSI-C $'...' DOES process \', so that branch keeps the \\. escape form; "..."
// keeps it too (backslash is special inside bash double quotes).
// Human prose in a command-argument position is DATA, not commands. The heredoc
// fix closed one wrapper; this closes the rest of the family: a PR body, a PR
// comment, a release note. The failure mode is identical -- a sentence like
// "runs at the same time" reads as the `at` scheduler at a segment start, and
// the better the prose, the likelier it contains words like at / cron /
// schedule. Same literal-only rule as the other strippers: a double-quoted
// value with $( or ` may substitute, so it is left alone.
const PROSE_FLAGS = String.raw`--body|--message|--notes|--title|--subject|-b|-m|-t`

export function stripProseArguments(seg) {
  const s = String(seg ?? '')
  // Scoped to the tools these prose flags were written for: gh, git, glab (a PR
  // body, a PR comment, a release note). A short flag means different things to
  // different binaries (`tar -t`, `cut -b`, `sort -t`), so blanking it on an
  // unrelated tool would hide real data from the gate (PR #770 review, Szotasz).
  // Same coarse command-word guard as stripGitCommitMessages just below.
  if (!/\b(?:gh|git|glab)\b/i.test(s)) return s
  return s.replace(
    new RegExp(String.raw`((?:^|\s)(?:${PROSE_FLAGS})(?:\s+|=))('[^']*'|\$'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")`, 'gi'),
    (full, flag, arg) => {
      const dq = arg.startsWith('"')
      if (dq && (arg.includes('$(') || arg.includes('`'))) return full
      return flag + (dq ? '""' : "''")
    },
  )
}

export function stripDataPayloads(seg) {
  return String(seg ?? '').replace(
    /((?:^|\s)(?:-d|--data(?:-(?:raw|binary|ascii|urlencode))?)(?:\s+|=))('[^']*'|\$'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/gi,
    (full, flag, arg) => {
      const dq = arg.startsWith('"')
      if (dq && (arg.includes('$(') || arg.includes('`'))) return full // may substitute -> keep
      return flag + (dq ? '""' : "''") // literal payload -> blank the content
    },
  )
}

// Blank out git commit/tag/stash -m/--message LITERAL text before self-pace
// matching. A commit message is prose, NEVER a shell invocation, so a trigger
// token that only appears INSIDE the message must not false-deny (2026-07-13,
// DrCode: a long `git commit -m "...batch...; at..."` blocked twice, the short
// one passed -- the message text was split as shell segments). Same principle
// and same literal-only quote handling as stripDataPayloads: single-quoted,
// ANSI-C $'...', and double-quoted WITHOUT $(...)/backtick are blanked; a
// double-quoted message that CAN command-substitute (`git commit -m "$(crontab
// -r)"`) is left intact so SCHEDULER_RX still catches the real substitution.
// Scoped to git commit/tag/stash so a `-m` on an unrelated binary is untouched.
// Heredoc bodies are DATA, not commands. A worker writing a real commit message
// through `git commit -F - <<EOF … EOF` had the turn denied because one prose
// line happened to start with "at " -- which SCHEDULER_RX reads as the `at`
// scheduler at a segment start. A heredoc body is data, so blank it before any
// pattern runs. Handles <<- for tab-indented bodies.
//
// EXCEPT when the body can still run something. A QUOTED marker (<<'EOF' or
// <<"EOF") is literal: the shell performs no expansion inside it, so blanking is
// safe. An UNQUOTED marker (<<EOF) is not -- the shell expands $(...) and
// backticks in that body at exec time, so blanking one would hide a live
// command substitution from SCHEDULER_RX and the gate would stop seeing
// something that really runs:
//
//     git commit -m "$(cat <<EOF
//     fix
//     $(at now)
//     EOF
//     )"
//
// This is the same rule the other strippers already apply: stripDataPayloads,
// stripGitCommitMessages and stripProseArguments all leave a double-quoted
// value alone when it contains `$(` or a backtick. An unquoted heredoc is the
// same category; it was simply missing the guard. Reported on PR #770.
// Whether the command word owning a heredoc redirect EXECUTES the body. The
// shell-literal guard above is not enough: a quoted marker (<<'EOF') is literal
// to the SHELL, so blanking looks safe, but `bash <<'EOF'`, `sh`, `ssh box`,
// `python - <<'EOF'` feed the body to an interpreter that runs it -- blanking
// would hide a live scheduler command from the gate (PR #770 review, Szotasz).
// `git commit -F - <<'EOF'` feeds the body to git as DATA, so that stays safe to
// blank. So: keep the body visible when its redirect owner is an interpreter or
// remote/container executor.
const HEREDOC_INTERPRETER_RX = /^(?:bash|sh|zsh|dash|ksh|ash|python[0-9.]*|node|nodejs|ruby|perl|php|ssh)$/

function heredocOwnerRunsBody(before) {
  // `before` is the command text up to the << redirect; the owner is the first
  // word of the last command segment.
  const seg = before.split(/\n|;|\|\|?|&&?|\(|\{/).pop() ?? ''
  const tokens = seg.trim().split(/\s+/).filter(Boolean)
  // Pass-through prefixes that do not change what runs the body.
  while (tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]) ||
    ['sudo', 'env', 'nice', 'time', 'exec', 'command', 'nohup', 'stdbuf'].includes(tokens[0]))) {
    tokens.shift()
  }
  if (!tokens.length) return false
  const word = tokens[0].split('/').pop()
  if (HEREDOC_INTERPRETER_RX.test(word)) return true
  // docker/podman/kubectl exec run the body through a shell in the target.
  if (['docker', 'podman', 'kubectl'].includes(word) && tokens.slice(1).includes('exec')) return true
  return false
}

export function stripHeredocBodies(command) {
  const cmd = String(command ?? '')
  if (!/<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*/.test(cmd)) return cmd
  return cmd.replace(
    /(<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2)([\s\S]*?)(^\s*\3\s*$)/gm,
    (full, open, quote, _marker, body, close, offset, string) => {
      const literal = quote === "'" || quote === '"'
      if (!literal && (body.includes('$(') || body.includes('`'))) return full
      // A quoted body the shell will not expand is still executed when an
      // interpreter/remote-executor owns the redirect -- keep it visible then.
      if (heredocOwnerRunsBody(string.slice(0, offset))) return full
      return `${open}\n${close}`
    },
  )
}

export function stripGitCommitMessages(command) {
  const cmd = String(command ?? '')
  if (!/\bgit\b[\s\S]*\b(commit|tag|stash)\b/i.test(cmd)) return cmd
  return cmd.replace(
    /((?:^|\s)(?:-m|--message)(?:\s+|=))('[^']*'|\$'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/gi,
    (full, flag, arg) => {
      const dq = arg.startsWith('"')
      if (dq && (arg.includes('$(') || arg.includes('`'))) return full // may substitute -> keep
      return flag + (dq ? '""' : "''") // literal message -> blank the content
    },
  )
}

// Normalise two shell-level obfuscations that bash resolves at EXEC time, so an
// invocation whose SHAPE is a real self-pace cannot dodge the slash-command match
// with quoting the shell undoes anyway. Measured end-to-end through the gate hook
// (upstream review, 2026-07-27): `claude \/loop` and `claude$IFS/loop` BOTH run
// `claude /loop` in bash but slipped the `(?:^|[\s'"])\/loop` match -- the char
// before `/loop` was `\` and `S` (end of `$IFS`), neither in the [\s'"] class.
// The fix is NOT to widen that class (that would let more prose through); it is to
// resolve what the shell resolves before matching: `$IFS`/`${IFS}` word-splits to
// a space, and a backslash escape `\X` collapses to `X`. Side effect: also closes
// `claude /lo\op`. Applied ONLY to the self-pace bash patterns below; the
// scheduler/store/API checks keep the raw segment (upstream measured them clean,
// and this PR is scoped to these two loop regressions). This cannot introduce a
// false positive: collapsing escapes / dropping `$IFS` never synthesises the
// literal `tmux`+send-keys, `nohup`+claude, or `claude`+`/loop` tokens out of
// prose -- it only removes an evasion.
export function normalizeShellEvasion(seg) {
  return String(seg ?? '')
    .replace(/\$\{IFS\}|\$IFS\b/g, ' ') // $IFS / ${IFS} -> the space it expands to
    .replace(/\\(.)/g, '$1') // \X -> X (bash unescape of a backslash-escaped char)
}

// THE tmux WRITE PRIMITIVE, BY INVERTED PROOF (card 9f57f705, the owner's rule 11: loud by default,
// silent only on provably clean, never a list of shapes).
//
// SELF_PACE_BASH_PATTERNS[0] needs the literal word `tmux` AND one of four literal subcommand names in
// ONE segment. Measured offline on the live gate (probe.mjs, nothing executed): 20 of 32 cases got through, and
// most of them are not interpreters -- tmux's own aliases (`send`, `pasteb`, `run`, `send-prefix`,
// `source-file`, `if-shell`, `respawn-pane`), the command or the subcommand in a shell variable, an `env` /
// `xargs` / `-S socket` prefix, a python list split over two lines, and a script FILE whose content nobody
// reads. Adding those names would be the shape list again; the next alias gets through.
//
// So the question is turned round. For a sub-agent the word `tmux` may appear in a Bash command only as
//   (a) the command word with a READ subcommand (list-*, has-session, display-message, capture-pane,
//       show-*, info), no `#(shell)` format expansion, no chained second tmux command, and none of tmux's
//       own -c (runs a shell command), -C (reads commands from stdin) or -f (loads a config that runs commands); or
//   (b) an argument of a plain reader (grep, cat, ls, jq, echo, pgrep, which ...) in a command that has no
//       executing sink (a pipe into a shell/interpreter, xargs, eval, source, a command substitution that says tmux).
// Every other mention -- a variable, an interpreter body, a wrapper, a write subcommand -- is a deny. Quotes
// are dropped before the word is looked for, because bash joins tm''ux and "tm"ux into one word.
//
// A SCRIPT an interpreter runs is read the same way (see interpreterRunVerdict): the gate reads the file, or the
// text the SAME command writes to it (`cat > F <<'EOF' ... EOF; python3 F`), and the file may mention tmux only in
// the two forms above.
//
// WHAT THIS DOES NOT CLOSE, said here and not hidden: a name that is never spelled `tmux` once the shell has
// joined the quotes and escapes (built at run time, 'tm'+'ux' inside a python string, a decoded string), a script
// that runs another script, a wrapper this gate does not know (WRAPPERS below), `python3 -m pytest x.py` and
// the like (a module runner that imports a file), a binary run by a computed direct path, a file written by an
// EARLIER command and replaced before it runs, and a binary that drives tmux without the word in its own command line.
// The gate's own header says a sub-agent is not adversarial to its gate: this closes the CASUAL routes.
const SHELL_KEYWORDS = new Set(['do', 'then', 'else', 'elif', 'if', 'while', 'until', '!', '{', '('])
const TMUX_WORD_RX = /(?<![\w.$-])(?<!\$\{)tmux(?![\w*/-]|\.\w)/i
const TMUX_READ_SUBCOMMANDS = new Set([
  'list-sessions', 'ls', 'list-windows', 'lsw', 'list-panes', 'lsp', 'list-clients', 'lsc', 'list-buffers', 'lsb',
  'list-commands', 'lscm', 'list-keys', 'lsk', 'has-session', 'has', 'display-message', 'display', 'capture-pane',
  'capturep', 'show-options', 'show', 'show-window-options', 'showw', 'show-environment', 'showenv',
  'show-messages', 'showmsgs', 'show-hooks', 'show-buffer', 'showb', 'server-info', 'info',
])
const TMUX_OPTS_WITH_VALUE = new Set(['-L', '-S', '-T'])
// -c runs a shell command, -C reads tmux commands from stdin, -f loads a config file that runs commands (man tmux)
const TMUX_UNSAFE_OPT_RX = /^-[A-Za-z0-9]*[cCf]/
const TMUX_PASS_THROUGH = new Set(['sudo', 'command', 'exec', 'nice', 'time', 'builtin', 'nohup'])
const TMUX_READERS = new Set([...ALLOWLIST_READERS, 'pgrep', 'which', 'whereis', 'type'])
// something that EXECUTES what it is fed, for the reader exemption (b): a pipe into a shell / interpreter, eval / source /
// xargs / `. file` in command position, or a command substitution that itself contains the word. (An unrelated
// `$(...)` elsewhere in the command is not a sink for a tmux word that sits in an `echo` -- measured on the replay.)
const TMUX_SINK_RX = /\|\s*(?:\S*\/)?(?:sh|bash|zsh|dash|ksh|python[0-9.]*|node|nodejs|ruby|perl|php)\b|(?:^|[;&|\n(`]|\$\()\s*(?:eval|source|xargs)\b|\$\([^)]*\btmux|`[^`]*\btmux|(?:^|[;&|\n])\s*\.\s/i
// tmux chains commands with an escaped (or quoted) semicolon; the part after it is a second command
const TMUX_CHAIN_RX = /\btmux\b[^\n]*(?:\\;|(['"]);\1)/i
const SCRIPT_SCAN_MAX_BYTES = 4 * 1024 * 1024

const stripQuoteChars = (t) => String(t ?? '').replace(/['"]/g, '')

// `tail` is what follows the word `tmux`; `whole` is the segment.
function tmuxCallIsRead(tail, whole) {
  if (/#\(/.test(whole)) return false // a format expansion runs a shell command
  const words = String(tail).replace(/[)`;]+$/, '').trim().split(/\s+/).filter(Boolean)
  let j = 0
  while (j < words.length && words[j].startsWith('-')) {
    if (TMUX_OPTS_WITH_VALUE.has(words[j])) { j += 2; continue }
    if (TMUX_UNSAFE_OPT_RX.test(words[j])) return false
    j++
  }
  const sub = (words[j] ?? '').replace(/[)`;]+$/, '')
  return TMUX_READ_SUBCOMMANDS.has(sub)
}

function tmuxSegmentAllowed(seg, hasSink) {
  const s = stripQuoteChars(normalizeShellEvasion(seg)).trim()
  if (!TMUX_WORD_RX.test(s)) return true
  const re = new RegExp(TMUX_WORD_RX.source, 'gi')
  for (const m of s.matchAll(re)) {
    const before = s.slice(0, m.index).replace(/\$\(|`|\(|\{|\)/g, ' ').trim()
    const toks = before ? before.split(/\s+/) : []
    const rest = toks.filter((t) => !/^[A-Za-z_][A-Za-z0-9_]*=\S*$/.test(t) && !SHELL_KEYWORDS.has(t) && !TMUX_PASS_THROUGH.has(t) && t !== 'env')
    if (rest.length === 0) { // command position
      if (!tmuxCallIsRead(s.slice(m.index + m[0].length), s)) return false
      continue
    }
    // argument position: only a plain reader's argument, in a command with no executing sink
    const cmd = rest[0].replace(/^.*\//, '').toLowerCase()
    const isTypeProbe = toks.length === 2 && toks[0] === 'command' && /^-[vV]$/.test(toks[1]) // `command -v tmux`
    if (hasSink || !(TMUX_READERS.has(cmd) || isTypeProbe)) return false
  }
  return true
}

export function tmuxMentionAllowed(command) {
  const raw = String(command ?? '')
  if (!TMUX_WORD_RX.test(stripQuoteChars(normalizeShellEvasion(raw)))) return true
  if (TMUX_CHAIN_RX.test(raw)) return false
  const hasSink = TMUX_SINK_RX.test(stripQuoteChars(raw))
  return splitSegments(raw).every((seg) => tmuxSegmentAllowed(seg, hasSink))
}

// WHAT SCRIPT DOES AN INTERPRETER RUN? (owner's decision, rule 11: "cannot be proven = deny").
// The gate can only judge what it can read. An interpreter (python / node / bash / ...) that runs a script FILE is
// therefore allowed only when the gate can name and read that file, or the text the same command writes to it:
//   - a literal path (`python3 /abs/x.py`, `bash ./x.sh`), or a `$NAME` / `${NAME}` that the SAME command set to a literal
//     earlier (`S=/abs/dir; python3 $S/x.py`), with `cd <literal>` followed for a relative path; and
//   - the file is readable, not a directory, not bigger than SCRIPT_SCAN_MAX_BYTES, and its code lines mention tmux only
//     in the two provable forms (tmuxMentionAllowed). Comments are skipped per LANGUAGE: `#` for shell / python / ruby /
//     perl / php, `//` and a one-line `/* */` for node / ts (a `#x` in JS is a class field, a `*)` in bash is a case arm).
// Anything else is a deny with reason 'script-path': a computed path ($VAR from the environment or from a loop, a glob,
// a substitution), a path that cannot be read (missing file, directory, too large), or a relative path after a `cd` the
// gate cannot follow. Inline code is not a file and is read as text: `-c`, `-e`, `-m`, a heredoc, `bash -c '...'`.
// The interpreter may sit behind WRAPPERS (env, timeout, stdbuf, nice, sudo, npx, uv run ...) and `source F` / `. F` is
// a shell run of F. The price is in the replay numbers of the commit; the way out is always the same: give the path
// literally (or set it in the same command).
const WRAPPERS = new Set([
  'env', 'timeout', 'stdbuf', 'nice', 'ionice', 'nohup', 'sudo', 'time', 'command', 'exec', 'setsid', 'taskset', 'chrt',
  'unbuffer', 'xvfb-run', 'npx', 'uv', 'uvx', 'pipx', 'builtin',
])
const WRAPPER_VALUE_FLAGS = new Set(['-n', '-u', '-g', '-c', '-k', '-s', '-p', '-C', '-D', '-R', '-t'])
const INTERPRETER_VALUE_OPTS = {
  python: new Set(['-W', '-X', '-Q']),
  node: new Set(['-r', '--require', '--import', '--loader', '--conditions', '-C', '--input-type']),
  perl: new Set(['-I', '-M', '-m']),
  ruby: new Set(['-I', '-r']),
  php: new Set(['-c', '-d']),
  shell: new Set(['-o', '-O', '+o', '+O', '--rcfile', '--init-file']),
}
const INTERPRETER_INLINE_OPTS = {
  python: new Set(['-c']), // -m is handled below: runpy and friends take a script file
  node: new Set(['-e', '-p', '--eval', '--print']),
  perl: new Set(['-e', '-E']),
  ruby: new Set(['-e']),
  php: new Set(['-r']),
  shell: new Set(['-c']),
}
const MODULE_RUNNERS_OF_A_FILE = new Set(['runpy', 'cProfile', 'profile', 'pdb', 'trace'])
const EXT_FAMILY = { py: 'python', js: 'node', mjs: 'node', cjs: 'node', ts: 'node', mts: 'node', sh: 'shell', bash: 'shell', rb: 'ruby', pl: 'perl', php: 'php' }
function interpreterFamily(base) {
  if (/^python[0-9.]*$/.test(base)) return 'python'
  if (/^(?:node|nodejs|tsx|ts-node)$/.test(base)) return 'node'
  if (base === 'perl') return 'perl'
  if (base === 'ruby') return 'ruby'
  if (base === 'php') return 'php'
  if (/^(?:bash|sh|zsh|dash|ksh)$/.test(base)) return 'shell'
  if (base === 'source' || base === '.') return 'shell'
  return null
}
function familyFromShebang(text) {
  const m = /^#!\s*(?:\/usr\/bin\/env\s+)?(\S+)/.exec(text)
  return m ? interpreterFamily(m[1].replace(/^.*\//, '').toLowerCase()) : null
}
const COMPUTED_RX = /[$`*?[\]{}()~;&|<>]/
// `command -v NAME...` / `command -V NAME...` (optionally `-p`) only prints how a name resolves: no program is run, and the
// names after it are not scripts. A bare `command node x.js` still runs node and is judged as before.
const COMMAND_TYPE_PROBE_RX = /^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:builtin\s+)?command\s+(?:-p\s+)?-[vV]\s/

// Index of the command word: past shell keywords, VAR= assignments and wrappers (with their options and values).
function commandWordIndex(words) {
  let i = 0
  for (;;) {
    while (i < words.length && (SHELL_KEYWORDS.has(words[i]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]))) i++
    if (i >= words.length) return -1
    const base = words[i].replace(/^.*\//, '').toLowerCase()
    if (!WRAPPERS.has(base)) return i
    i++
    while (i < words.length) {
      const w = words[i]
      if (w.startsWith('-')) { i += WRAPPER_VALUE_FLAGS.has(w) ? 2 : 1; continue }
      if (/^\d+(?:\.\d+)?[smhd]?$/.test(w) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i++; continue }
      break
    }
    if ((base === 'uv' || base === 'uvx' || base === 'pipx') && words[i] === 'run') i++
  }
}

// `NAME=value` / `export NAME=value` at the start of a segment: the literal value, or null when it is computed.
function literalAssignment(words) {
  let k = 0
  if (words[0] === 'export' || words[0] === 'declare' || words[0] === 'local' || words[0] === 'readonly') k = 1
  const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(words[k] ?? '')
  if (!m) return null
  const raw = m[2].replace(/^(['"])(.*)\1$/, '$2')
  return { name: m[1], value: COMPUTED_RX.test(raw) ? null : raw }
}

function substituteKnown(target, vars) {
  let ok = true
  const out = target.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, a, b) => {
    const v = vars.get(a ?? b)
    if (typeof v !== 'string') { ok = false; return _m }
    return v
  })
  return ok ? out : null
}

// Files the command WRITES ITSELF, so that `cat > F <<'EOF' ... EOF; python3 F` is judged on the text it writes, not on a
// file that does not exist yet when the hook runs: `cat > F <<EOF`, `cat <<EOF > F`, `tee F <<EOF`, `echo '..' > F`,
// `printf '..' > F`. Returns [{ target, content }] with the target as written (not yet resolved).
function writtenFiles(raw) {
  const out = []
  const heredoc = /(?:^|[;&|\n]\s*)(?:cat|tee)\b([^\n]*?)<<-?\s*(['"]?)([A-Za-z_]\w*)\2([^\n]*)\n([\s\S]*?)\n[ \t]*\3[ \t]*(?=\n|$)/g
  for (const m of raw.matchAll(heredoc)) {
    const line = m[0].split('\n')[0] // the command word, its arguments and the redirect, up to the end of the line
    const t = /(?<![0-9&])>>?\s*(["']?)([^\s"'<>|;&]+)\1/.exec(line) ?? /\btee\s+(?:-a\s+)?(["']?)([^\s"'<>|;&]+)\1/.exec(line)
    if (t) out.push({ target: t[2], content: m[5] })
  }
  const echo = /(?:^|[;&|\n]\s*)(?:echo|printf)\b([^\n]*?)(?<![0-9&])>>?\s*(["']?)([^\s"'<>|;&]+)\2\s*(?=$|[;&|\n])/g
  for (const m of raw.matchAll(echo)) out.push({ target: m[3], content: stripQuoteChars(m[1]).replace(/\\n/g, '\n') }) // printf / echo -e: a \n is a line break
  return out
}

function codeLines(text, fam) {
  const keep = []
  for (const l of text.split(/\r?\n/)) {
    const t = l.trimStart()
    if (fam === 'node' ? (t.startsWith('//') || /^\/\*.*\*\/\s*$/.test(t)) : t.startsWith('#')) continue
    keep.push(l)
  }
  return keep.join('\n')
}

// The repo this gate was installed from. The waiver below is bound to it (HEX 3999, widened by HEX 4015): a file in any OTHER
// git repo proves nothing about itself.
const INSTALL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function gitIn(dir, ...args) {
  const r = spawnSync('git', ['-C', dir, '-c', 'core.fsmonitor=false', ...args], { encoding: 'utf8', timeout: 3000 })
  return r.status === 0 ? String(r.stdout).trim() : null
}

// Is `abs` a file of the install's repo: its main checkout or a LINKED WORKTREE of it (the same git common dir)? A review
// worktree must be able to run the suites it reviews (HEX 4015).
function inInstallRepo(abs, installRoot = INSTALL_ROOT) {
  try {
    const mine = gitIn(dirname(abs), 'rev-parse', '--path-format=absolute', '--git-common-dir')
    const theirs = gitIn(installRoot, 'rev-parse', '--path-format=absolute', '--git-common-dir')
    return !!mine && !!theirs && realpathSync(mine) === realpathSync(theirs)
  } catch {
    return false
  }
}

// A file of the install repo (main checkout or linked worktree) that is byte-identical to the blob committed in the HEAD of
// the work tree it sits in is code that went through the history: the fleet's own daemon and hook scripts (channels.sh,
// watchdog.sh, scripts/hooks/destructive-gate.py ...) say tmux send in earnest, and reviewers replay the hooks and run the
// suites in their worktrees. Only the tmux scan is waived for such a file; an untracked, edited, or foreign-repo file (the
// agent's own driver) is still scanned. NAMED LIMIT (measured 2026-10-14): the agent can commit a driver in its OWN linked
// worktree (the prod-tree-guard covers only the main checkout), and the main checkout's HEAD can be moved without a hook (a
// worktree branch fast-forwarded in); then the HEAD blob is the driver. Card deecccda closes only the second route; the first
// is a standing limit (a commit in a worktree is ordinary work), unless the owner widens that card. Not this gate's job.
// Cost: two git calls, only for a script that mentions tmux.
function committedAndClean(abs, installRoot = INSTALL_ROOT) {
  if (!inInstallRepo(abs, installRoot)) return false
  const dir = dirname(abs)
  const here = gitIn(dir, 'hash-object', '--', abs)
  const there = gitIn(dir, 'rev-parse', '--verify', '-q', `HEAD:./${basename(abs)}`)
  return !!here && here === there
}

// A shell that is given a script FILE (`bash agent-msg.sh sam hex - <<'EOF'`) does not read its heredoc as commands: the body is
// the script's stdin, here a message text. The shell reads the body as code only when it reads its program from stdin: no
// positional word, or `-s`, `-` (and `-c` takes its program from the argument, the body is that program's stdin, kept as text).
// `words[at]` is the shell word.
function shellRunsAScriptFile(words, at) {
  for (let k = at + 1; k < words.length; k++) {
    const w = words[k]
    if (w === '-' || w === '--' || w.startsWith('<') || w.startsWith('>')) return false
    if (w.startsWith('-') && !w.startsWith('--') && /[sc]/.test(w.slice(1))) return false // -s, -c, or a cluster with one
    if (INTERPRETER_VALUE_OPTS.shell.has(w)) { k++; continue }
    if (w.startsWith('-') || w.startsWith('+')) continue
    return true
  }
  return false
}

// The body of a python / node / ruby / perl / php heredoc is that language's code, not shell lines: a line of it that begins
// with `node = ...` or `bash is ...` (prose) must not be read as an interpreter run. (A shell heredoc, `bash <<EOF`, stays:
// its lines ARE commands. The tmux text rule reads every body, whatever the language.)
function blankNonShellHeredocBodies(command) {
  const cmd = String(command ?? '')
  if (!/<<-?\s*['"]?[A-Za-z_]/.test(cmd)) return cmd
  return cmd.replace(/(<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2)([\s\S]*?)(^\s*\3\s*$)/gm, (full, open, _q, _m, _body, close, offset, whole) => {
    const seg = whole.slice(0, offset).split(/\n|;|\|\|?|&&?|\(|\{/).pop() ?? ''
    const words = seg.trim().split(/\s+/).filter(Boolean)
    const at = commandWordIndex(words)
    const fam = at < 0 ? null : interpreterFamily(words[at].replace(/^.*\//, '').toLowerCase())
    if (fam === 'shell' && shellRunsAScriptFile(words, at)) return `${open}\n${close}` // the body is that script's stdin, not code
    return fam && fam !== 'shell' ? `${open}\n${close}` : full
  })
}

// Returns null (nothing to say) or { deny: true, reason }. `rawCommand` is the command BEFORE heredoc bodies were blanked.
export function interpreterRunVerdict(command, cwd, rawCommand = command, installRoot = INSTALL_ROOT) {
  const vars = new Map()
  const writes = writtenFiles(String(rawCommand ?? ''))
  let cur = cwd || process.cwd() // null once a `cd` the gate cannot follow has happened
  for (const seg of splitSegments(blankNonShellHeredocBodies(command))) {
    const words = normalizeShellEvasion(seg).trim().split(/\s+/).filter(Boolean)
    if (!words.length) continue
    const asg = literalAssignment(words)
    if (asg) { vars.set(asg.name, asg.value); if (words.length === 1 || words[0] === 'export') continue }
    if (words[0] === 'cd' || words[0] === 'pushd') {
      const sub = words[1] ? substituteKnown(words[1].replace(/^['"]|['"]$/g, ''), vars) : null
      const arg = sub ? expandHome(sub) : null // `~/x` is a known path once the home is expanded
      cur = arg && !COMPUTED_RX.test(arg) && arg !== '-' ? resolve(cur || '/', arg) : null
      continue
    }
    // `command -v node pytest` names programs, it runs none (not when a substitution or redirect rides along: that may run one)
    if (COMMAND_TYPE_PROBE_RX.test(words.join(' ')) && !/[$`()<>]/.test(words.join(' '))) continue
    const i = commandWordIndex(words)
    if (i < 0) continue
    const first = words[i]
    const base = first.replace(/^.*\//, '').toLowerCase()
    let fam = interpreterFamily(base)
    let target = null
    if (fam) {
      const valueOpts = INTERPRETER_VALUE_OPTS[fam]
      const inlineOpts = INTERPRETER_INLINE_OPTS[fam]
      if (base === 'source' || base === '.') {
        target = words[i + 1] ?? null
      } else {
        for (let k = i + 1; k < words.length; k++) {
          const w = words[k]
          if (w === '-' || w.startsWith('<') || w.startsWith('>')) { target = null; break } // stdin / heredoc: read as text
          if (fam === 'shell' && /^-[A-Za-z]*s[A-Za-z]*$/.test(w)) { target = null; break } // `sh -s arg`: the program is stdin, `arg` is its $1
          if (fam === 'python' && w === '-m') { // a module runner of a file takes it as the next positional, anything else is inline
            if (MODULE_RUNNERS_OF_A_FILE.has(words[k + 1] ?? '')) { target = words[k + 2] ?? null }
            break
          }
          if (fam === 'php' && w === '-f') { target = words[k + 1] ?? null; break }
          if (inlineOpts.has(w) || (w.length > 2 && w.startsWith('-') && inlineOpts.has(w.slice(0, 2)) && fam !== 'shell')) { target = null; break }
          if (valueOpts.has(w)) { k++; continue }
          if (w.startsWith('-') || w.startsWith('+')) continue
          target = w
          break
        }
      }
      if (target == null) continue // no file argument: interactive, stdin or inline code
      if (/^[=(]/.test(target)) continue // `node = Node()`, `sh (x)`: not a command line
    } else if (EXT_FAMILY[(/\.([A-Za-z0-9]+)$/.exec(first.replace(/[)`]+$/, ''))?.[1] ?? '').toLowerCase()] && !first.startsWith('-')) {
      target = first // `uv run drv.py`, `pipx run drv.py`: a script by extension behind a wrapper this gate does not know
      fam = EXT_FAMILY[/\.([A-Za-z0-9]+)$/.exec(first.replace(/[)`]+$/, ''))[1].toLowerCase()]
    } else if (first.includes('/') && !first.startsWith('-')) {
      target = first // a path run directly
    } else {
      continue
    }
    // the word may carry the closing of a substitution or a quote: `$(... | node x.mjs)`
    target = target.replace(/[)`]+$/, '').replace(/^(['"])(.*)\1$/, '$2')
    const subbed = substituteKnown(target, vars)
    const resolved = subbed == null ? null : expandHome(subbed)
    // A path run DIRECTLY (not through an interpreter) is judged only when the gate can read it: a computed path or a
    // binary is not a deny (named limit; most direct paths are binaries such as /usr/bin/git).
    const direct = !interpreterFamily(base) && !EXT_FAMILY[(/\.([A-Za-z0-9]+)$/.exec(first)?.[1] ?? '').toLowerCase()]
    if (resolved == null || COMPUTED_RX.test(resolved)) {
      if (direct) continue
      return { deny: true, reason: 'script-path', detail: 'computed' }
    }
    const abs = resolve(cur ?? '/', resolved)
    if (cur == null && !resolved.startsWith('/')) {
      if (direct) continue
      return { deny: true, reason: 'script-path', detail: 'cd' }
    }
    // the text this very command writes to the file wins over (and is judged besides) what is on disk
    const texts = []
    let fromDisk = -1 // index of the on-disk text in `texts`, -1 when there is none
    for (const w of writes) {
      const ws = substituteKnown(w.target, vars)
      if (ws == null) continue
      const wp = expandHome(ws)
      if (!COMPUTED_RX.test(wp) && resolve(cur ?? '/', wp) === abs) texts.push(w.content)
    }
    try {
      const st = statSync(abs)
      if (!st.isFile() || st.size > SCRIPT_SCAN_MAX_BYTES) {
        if (!texts.length) { if (direct) continue; return { deny: true, reason: 'script-path', detail: 'unreadable' } }
      } else {
        texts.push(readFileSync(abs, 'latin1'))
        fromDisk = texts.length - 1
      }
    } catch {
      if (!texts.length) { if (direct) continue; return { deny: true, reason: 'script-path', detail: 'unreadable' } }
    }
    // There is NO exemption for test files (round 5, Sam's K13). The round-3 one (`<dir>/__tests__/<name>.test.<ext>`) was
    // narrowed to the install checkout's tracked files in round 4 and then did nothing the HEAD-blob waiver below does not
    // already do, except let an EDITED or merely `git add`-ed test through. A test file that mentions tmux is judged like any
    // script: byte-identical to the install checkout's HEAD blob, or scanned.
    for (const text of texts) {
      const f = fam ?? familyFromShebang(text)
      if (direct && !fam && !f) continue // a binary run by a literal path: not a script the gate can read
      const code = codeLines(text, f)
      if (TMUX_WORD_RX.test(stripQuoteChars(code)) && !tmuxMentionAllowed(code)) {
        // the committed-and-clean waiver applies to the on-disk file only; the text this command writes is scanned on its own
        if (texts.indexOf(text) === fromDisk && committedAndClean(abs, installRoot)) continue
        return { deny: true, reason: 'tmux-script' }
      }
    }
  }
  return null
}

// Pure decision: does this tool call set up self-pace / self-injection?
export function gateDecision(toolName, toolInput, opts = {}) {
  const name = String(toolName ?? '')
  if (SELF_PACE_TOOLS.has(name)) return { deny: true }
  // Native file tools writing the self-schedule store would bypass any Bash regex.
  if (name === 'Write' || name === 'Edit' || name === 'MultiEdit' || name === 'NotebookEdit') {
    const fp = String(toolInput?.file_path ?? toolInput?.notebook_path ?? '')
    if (SCHEDULE_STORE_RX.test(fp)) return { deny: true }
    if (fileToolTargetsAllowlist(toolInput, opts.allowlistPath, opts.cwd)) return { deny: true, reason: 'egress-allowlist' }
  }
  if (name === 'Bash') {
    // Strip -d/--data payloads on the WHOLE command BEFORE splitting. A payload is
    // data, not an invocation; and since splitSegments is NOT quote-aware, a shell
    // separator (; && | &) INSIDE a dispatch body would otherwise orphan a fragment
    // that false-matches. Stripping first blanks the body (incl. any separators in
    // it), so the URL/method args still match but the body text never does. A
    // separator OUTSIDE the payload still splits, so `curl -d '' x ; crontab -r`
    // is still caught.
    const safeCommand = stripProseArguments(stripDataPayloads(stripGitCommitMessages(stripHeredocBodies(String(toolInput?.command ?? '')))))
    // Per-segment so an unrelated token elsewhere in a compound command cannot
    // turn a legit read (store inspection, schedule-API GET) into a false deny.
    const naiveSegs = splitSegments(safeCommand)
    for (const seg of naiveSegs) {
      // Match the self-pace bash patterns against the shell-normalised segment so a
      // `\/loop` / `$IFS/loop` evasion (which bash resolves to `/loop` at exec) is
      // still caught; the scheduler/store/API checks below use the RAW seg (scoped).
      //
      // These stay on the NAIVE segments ON PURPOSE. They are unanchored, so a
      // quoted region is not a hiding place for them -- and the naive scan is
      // what catches a real `subprocess.run(['tmux','send-keys',...])` inside a
      // heredoc body (measured 2026-08-05). Quote-aware segments here would have
      // dropped the detection of this gate's own founding incident vector.
      if (SELF_PACE_BASH_PATTERNS.some((re) => re.test(normalizeShellEvasion(seg)))) return { deny: true }
      // self-schedule store: block WRITE only (a read/grep is legit diagnostics)
      if (SCHEDULE_STORE_RX.test(seg) && WRITE_INTENT_RX.test(seg)) return { deny: true }
      // dashboard schedule API: block WRITE methods only (GET list/pending is legit)
      if (SCHEDULE_API_RX.test(seg) && HTTP_WRITE_RX.test(seg)) return { deny: true }
      // the egress allowlist: a plain read only (EGRESSSELFEDIT824)
      if (!allowlistBashSegmentAllowed(seg)) return { deny: true, reason: 'egress-allowlist' }
    }
    // AFTER the per-segment checks above, so their specific reasons (the egress allowlist) still win. The tmux write
    // primitive by inverted proof (card 9f57f705): the word may only appear as a read call; an interpreter may run a script
    // file only when the gate can name and read it, and that file may mention tmux only as a read. Whole-command.
    if (!tmuxMentionAllowed(safeCommand)) return { deny: true }
    const run = interpreterRunVerdict(safeCommand, opts.cwd, String(toolInput?.command ?? ''), opts.installRoot)
    if (run) return run

    // The scheduler check is the ANCHORED one -- it fires on what sits at a
    // segment START -- so it is the one a fake segment boundary can mislead, and
    // the only one that gets quote-aware segments. Null (unresolvable quoting)
    // falls back to the naive split, i.e. to scanning strictly more.
    const masked = maskInertLiterals(safeCommand)
    for (const seg of (masked == null ? naiveSegs : splitSegments(masked))) {
      // scheduler binaries: deny the exec/submit forms, allow pure read-listing
      if (SCHEDULER_RX.test(seg) && !SCHEDULER_READ_RX.test(seg)) return { deny: true }
    }
  }
  return { deny: false }
}

const GATE_MSG =
  'Self-pace TILTOTT (governance hard-gate). Sub-agentkent NEM utemezhetsz sajat ' +
  'jovobeli turn-t: se ScheduleWakeup/Cron*/RemoteTrigger, se tmux send-keys, se ' +
  'scheduled_tasks.json iras, se /api/schedules POST, se /loop self-pace. Input-vezerelt ' +
  'vagy: csak az operator (channel) vagy egy peer (inter-agent) uzenete inditson. Ha varakozol, ' +
  'maradj idle a prompt-on -- a beerkezo uzenet majd ujrainditja a turn-t. SOHA ne valaszolj ' +
  'magadnak es SOHA ne dontsd el az operator helyett egy hozza intezett kerdest.'

const ALLOWLIST_GATE_MSG =
  'Egress-engedelylista TILTOTT (governance hard-gate). Sub-agentkent NEM irhatod a ' +
  'store/egress-allowlist.json-t: ez a kapu RAD vonatkozik. Ha egy domain kell, kerd a fo ' +
  'agenst (inter-agent uzenet: domain + miert); o a gazda jovahagyasaval veszi fel. ' +
  'Olvasni szabad: cat / grep / jq a fajlra (ertelmezo -- python, node -- nem).'

const SCRIPT_PATH_GATE_MSG =
  'Interpreter egy szamitott vagy olvashatatlan szkript-uton TILTOTT (governance hard-gate, kartya 9f57f705). A kapu ' +
  'csak azt engedi lefutni, amit el tud olvasni: adj LITERALIS utat (python3 /abs/ut/x.py), vagy allitsd be a valtozot ' +
  'UGYANABBAN a parancsban literal ertekkel (S=/abs/ut; python3 $S/x.py). A relativ ut egy kovethetetlen cd utan, egy ' +
  'glob, egy kornyezetbol vagy ciklusbol jovo valtozo, egy hianyzo vagy tul nagy fajl nem bizonyithato. Inline kod (-c, ' +
  'heredoc) szovegkent olvasott, az nem erinti.'

function allow() { process.exit(0) }

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }))
  process.exit(0)
}

function isInvokedDirectly() {
  try {
    const self = realpathSync(fileURLToPath(import.meta.url))
    const entry = process.argv[1] ? realpathSync(process.argv[1]) : ''
    return self === entry
  } catch {
    return false
  }
}
if (isInvokedDirectly()) {
  let payload
  try {
    payload = JSON.parse(readFileSync(0, 'utf-8'))
  } catch {
    allow() // malformed/empty input must never break the agent's tool calls
  }
  const { deny: shouldDeny, reason } = gateDecision(payload?.tool_name, payload?.tool_input, { cwd: payload?.cwd })
  if (shouldDeny) deny(reason === 'egress-allowlist' ? ALLOWLIST_GATE_MSG : reason === 'script-path' ? SCRIPT_PATH_GATE_MSG : GATE_MSG)
  allow()
}
