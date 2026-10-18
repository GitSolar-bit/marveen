#!/usr/bin/env node
// PreToolUse hook: WebFetch egress allowlist enforcement.
//
// Any WebFetch call from the main agent must target a known, legitimate API
// endpoint. Arbitrary web content (RSS feeds, docs, news pages, public APIs
// not in the allowlist) MUST go through the quarantine-reader sub-agent
// instead, so the fetched content is quarantined, wrapped, and never executed
// as instructions in the main agent's context.
//
// Two-tier allowlist:
//   1. Built-in (ALLOWED_PREFIXES): hard-coded, always enforced.
//   2. Runtime (store/egress-allowlist.json): operator-managed, loaded on each
//      invocation. Shape: { "domains": ["example.com"], "prefixes": ["https://host/path/"],
//      "quarantine_domains": ["feeds.example.org"], "quarantine_reader_posture": "allowlist"|"denylist" }
//      All keys are optional. Missing file or malformed JSON -> treated as empty
//      lists (FAIL-OPEN on the file, FAIL-SAFE on the decision: the built-in list
//      still guards; no extra URLs are allowed merely because the file is missing).
//
// When a URL is not on either allowlist:
//   - The tool call is HARD-BLOCKED (decision: deny).
//   - The blocked call is appended to EGRESS_BLOCK_LOG for operator review.
//   - The operator can approve the URL/domain: add it to store/egress-allowlist.json,
//     then re-run the WebFetch. No restart required for THIS hook (it re-reads
//     the JSON on every invocation).
//   - GRANT LATENCY for the quarantine-reader (EGRESSRENDER824): the reader's
//     own prompt-level list is a RENDERED copy of this JSON, refreshed by a
//     file-watcher within ~5s of a JSON change and read at the reader's next
//     SPAWN. A denial from the reader's prompt copy produces NO line in the
//     block log below (it rejects without a network call) -- if a freshly
//     granted domain is still refused, wait a few seconds and spawn a new
//     reader; a session restart is NOT needed.
//
// The log is separate from the main Marveen log so operators can grep it
// independently: `tail -f store/egress-blocked.log`
//
// THE PONDER TIER (kanban c1dc4109, owner decision TG 3041 #67, permission_change). One agent, the
// research agent `agents/ponder`, may READ the public web without an allowlist: WebFetch to any
// public http(s) URL, and Playwright navigation. Everybody else is byte-identical to before. It is
// built from three parts, all of which must hold:
//   1. IDENTITY: the payload's `transcript_path` lies under <install>/agents/ponder/.claude-config/
//      AND the payload carries no `agent_type` / `agent_id` (the top-level session, not a helper it
//      spawned). The path is written by the harness from the session's own isolated CLAUDE_CONFIG_DIR,
//      which an agent cannot change from inside a session; a payload field the CALLER composes (cwd
//      follows a `cd`, a prompt, a tool argument) is not used. Same basis as the destructive gate's
//      own-workdir right (FLEETOWNDIR1003, _agent_from_transcript).
//   2. SWITCH: store/egress-allowlist.json { "ponder_posture": "open" }. Only the literal string
//      "open" opens it; anything else, including a missing key or file, is closed. Same shape as
//      quarantine_reader_posture: an explicit per-install operator act, reported by the allowlist
//      baseline watcher like every other change to that file.
//   3. RULES, applied BEFORE every allow path: public http(s) only, no userinfo, ports 80/443 only, no
//      IP literals, no internal/private/loopback/link-local/metadata hosts, no single-label names, and
//      a URL length / query length cap. WebFetch is a GET-only tool by construction (its input is a
//      url and a prompt, never a method or body), so reading is all it can do; the URL itself is the
//      one thing a poisoned page could abuse to carry data OUT, hence the caps and the audit.
// Playwright for Ponder (identity only, the switch is not needed because these are RESTRICTIONS): an
// ALLOWLIST of reading tools (PONDER_BROWSER_ALLOWED), not a deny list: every other mcp__playwright__
// tool is refused, so a tool a later package version adds is closed by default. The navigation URL (the
// browser_navigate url, and the browser_tabs url of action "new", the second way @playwright/mcp 0.0.82
// navigates) gets the same rules as WebFetch. browser_press_key passes only a key that prints nothing. Click, hover and press_key stay (they are how a page is
// read), so the browser is NARROWER, not read-only: a click can submit a form the page itself prepared.
// RESOLVED ADDRESS: for Ponder, a public-looking NAME is also resolved and refused when ANY address it
// resolves to is non-public (ponderResolvedDenied). That is a point-in-time check on the hook's own
// lookup: the tool resolves again when it fetches, so a name that answers differently the second time
// (DNS rebinding) is NOT closed, and neither is a redirect or a navigation the PAGE starts.
// EVERY Ponder call that reaches this hook, allowed or denied, is appended to store/ponder-egress.jsonl.
//
// Scope: this guard covers the Claude Code WebFetch tool only -- it is wired
// with matcher "WebFetch" and sees no other tool. It does NOT intercept
// WebSearch or MCP-server outbound requests.
//
// The SHELL half is a separate control: BASH_EGRESS_DENY in
// src/web/agent-scaffold.ts puts a small permissions.deny list on every agent
// (curl to https://, plus wget/nc/ncat/telnet outright), because a fetched page
// telling an agent to run a curl would otherwise walk straight past this file.
// That list is a deny list, not a sandbox, and its limits are written down in
// docs/security-hardening.md. The two halves are deliberately separate: this
// one decides on a URL, that one on a command string.

import { readFileSync, appendFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import dns from 'node:dns'
import { isIP } from 'node:net'
import { dirname, join, normalize, sep } from 'node:path'

// Derive repo root from this script's location (scripts/hooks/egress-gate.mjs).
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const EGRESS_BLOCK_LOG = join(REPO_ROOT, 'store', 'egress-blocked.log')
const RUNTIME_ALLOWLIST_PATH = join(REPO_ROOT, 'store', 'egress-allowlist.json')

// Dashboard port: env WEB_PORT, else the install .env, else the 3420 default.
// A fixed 3420 in the allowlist below blocked the agent's own dashboard as soon
// as the install moved to another port.
// SECURITY: the value is interpolated into an allowlist PREFIX (`http://localhost:${PORT}/`), so it
// must be digits ONLY. An unvalidated value containing `@` turns the whole `localhost:<value>` part
// into a URL userinfo section -- `http://localhost:3420@evil.com/` resolves to host evil.com, which
// would put an attacker-chosen host on the built-in allowlist and defeat the egress gate entirely.
// Anything that is not 1-5 digits is rejected and falls back to the default port.
const isValidPort = (v) => /^\d{1,5}$/.test(v)
const DASHBOARD_PORT = (() => {
  const fromEnv = process.env['WEB_PORT']
  if (fromEnv && isValidPort(fromEnv)) return fromEnv
  try {
    const m = readFileSync(join(REPO_ROOT, '.env'), 'utf-8').match(/^WEB_PORT=(.*)$/m)
    const v = m?.[1]?.trim().replace(/^["']|["']$/g, '')
    if (v && isValidPort(v)) return v
  } catch { /* no .env: fall through to the default */ }
  return '3420'
})()

// Built-in allowlist: URL prefixes the main agent may call directly via WebFetch.
// Anything not on this list (or the runtime allowlist) must go through the
// quarantine-reader sub-agent. Keep sorted and documented so additions are
// intentional, not accidental.
const ALLOWED_PREFIXES = [
  // GitHub REST API
  'https://api.github.com/',
  // Google OAuth token endpoint
  'https://oauth2.googleapis.com/',
  // Google APIs (Calendar, Gmail, Drive, etc.)
  'https://www.googleapis.com/',
  'https://gmail.googleapis.com/',
  'https://calendar.googleapis.com/',
  // Telegram Bot API
  'https://api.telegram.org/',
  // Slack Web API
  'https://slack.com/api/',
  // Discord REST API
  'https://discord.com/api/',
  // Ollama (local LLM server) -- localhost and loopback
  'http://localhost:11434/',
  'http://127.0.0.1:11434/',
  // Marveen dashboard API (local). The port follows WEB_PORT: a fixed 3420 here
  // blocked the agent's own dashboard once the install moved to another port.
  `http://localhost:${DASHBOARD_PORT}/`,
  `http://127.0.0.1:${DASHBOARD_PORT}/`,
]

// The quarantine tier.
//
// The block message tells the caller to fetch through the quarantine-reader
// sub-agent -- and until now this same hook blocked that sub-agent too, so the
// escape hatch the gate prescribed was one the gate closed (kanban #224).
//
// A sub-agent's PreToolUse payload carries two fields a main agent's does not:
// `agent_id` and `agent_type` (measured 2026-08-03, both key sets recorded in
// store/egress-blocked.log). `agent_type` is what separates the tiers.
//
// FAIL-CLOSED: only an exact `agent_type` match opens this tier. A missing,
// empty, unknown or misspelled value is treated as a main agent, i.e. blocked.
// A mistake here can only deny a fetch, never grant one.
//
// The domain list mirrors the one in the sub-agent's own definition
// (templates/sub-agents/quarantine-reader.md). That copy is a promise the
// sub-agent makes to itself in its prompt; this one is enforcement. Keep them
// in step -- and when they disagree, this file is the one that decides.
const QUARANTINE_AGENT_TYPE = 'quarantine-reader'

// `path` (optional) narrows a domain to the URLs the sub-agent's definition
// actually promises. Reddit is the reason it exists: the definition allows RSS
// feeds only, and hostname matching alone would hand over the entire site.
const QUARANTINE_DOMAINS = [
  { domain: 'status.anthropic.com' },
  { domain: 'status.claude.com' },
  { domain: 'feeds.feedburner.com' },
  { domain: 'rss.arxiv.org' },
  { domain: 'export.arxiv.org' },
  { domain: 'hnrss.org' },
  { domain: 'feeds.arstechnica.com' },
  { domain: 'techcrunch.com' },
  { domain: 'feeds.reuters.com' },
  { domain: 'feeds.bbci.co.uk' },
  { domain: 'www.reddit.com', path: (p) => p.endsWith('.rss') },
]

// The reader's posture is an OPERATOR SWITCH, not a code-level decision.
//
// First proposed as an unconditional inversion (allowlist -> denylist); the
// upstream owner asked for both behaviours to coexist behind one setting, with
// the allowlist as the default, and his reasoning is recorded here because it
// is the contract this code keeps: the two failure directions are not
// symmetric. An allowlist that errs refuses a legitimate read, and a human
// hears about it. A denylist that errs lets something in, and nobody hears
// anything. A default that silently flips on update pushes every install
// toward the quieter failure without anyone having decided that -- so the
// flip must be an explicit, per-install operator act:
//
//   store/egress-allowlist.json: { "quarantine_reader_posture": "denylist" }
//
// Anything other than the literal string "denylist" (missing key, missing
// file, typo, wrong type) means "allowlist" -- the stricter, louder default.
// An untouched install behaves byte-identically to before this change.
//
// Why the open posture is defensible for THIS tier and no other: the posture
// applies only to the quarantine-reader, a sub-agent whose definition grants
// it `tools: WebFetch` and nothing else. No shell, no filesystem, no store
// access -- it holds nothing to leak, and what it returns is data the caller
// must wrap before use. The main agent's own WebFetch path is unaffected by
// the switch in either position.
//
// What the deny rules below must stop in the open posture is therefore NOT
// exfiltration but SSRF: a poisoned page talking the caller into aiming the
// reader at our own network. Hence literal internal hosts, internal-only name
// suffixes, and private/link-local/loopback address literals.
const QUARANTINE_DENY_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'broadcasthost',
  '0.0.0.0',
  '::',
  '::1',
  '[::]',
  '[::1]',
  'metadata.google.internal',
  'instance-data',
])

const QUARANTINE_DENY_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.lan']

// Private / link-local / loopback IPv4 literals, plus the cloud metadata
// address (169.254.169.254 is inside the link-local range and thus covered).
function isPrivateIPv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  if (m.slice(1).some((x) => Number(x) > 255)) return true // malformed -> deny
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  return false
}

// IPv6 loopback / unique-local / link-local, with or without brackets.
function isPrivateIPv6(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (!h.includes(':')) return false
  if (h === '::1' || h === '::') return true
  if (h.startsWith('fc') || h.startsWith('fd')) return true // unique-local
  if (h.startsWith('fe80')) return true // link-local
  // IPv4-mapped (::ffff:10.0.0.1) -- reuse the v4 rules on the tail.
  const tail = h.split(':').pop() ?? ''
  if (tail.includes('.')) return isPrivateIPv4(tail)
  return false
}

// KNOWN LIMIT, stated rather than papered over: this checks the hostname as
// written. A public name that RESOLVES to a private address (DNS rebinding)
// still passes, because the hook sees the URL, not the socket. Closing that
// needs resolution at fetch time, which is not this layer's job.
export function isQuarantineDenied(url) {
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return true // unparseable -> deny
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return true
  const host = parsed.hostname.toLowerCase()
  if (!host) return true
  if (QUARANTINE_DENY_HOSTS.has(host)) return true
  if (QUARANTINE_DENY_SUFFIXES.some((s) => host.endsWith(s))) return true
  if (isPrivateIPv4(host)) return true
  if (isPrivateIPv6(host)) return true
  return false
}

function matchesQuarantineDomain(url, extraDomains = []) {
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return false
  }
  const hostMatches = (d) => parsed.hostname === d || parsed.hostname.endsWith('.' + d)
  for (const entry of QUARANTINE_DOMAINS) {
    if (!hostMatches(entry.domain)) continue
    if (entry.path && !entry.path(parsed.pathname)) return false
    return true
  }
  // Operator additions carry no path rule: an entry someone typed into the
  // store file is a deliberate act, and second-guessing its shape here would
  // only make the file's behaviour harder to predict.
  return extraDomains.some(hostMatches)
}

// ---- the Ponder tier ----------------------------------------------------------------------
const PONDER_AGENT = 'ponder'
const PONDER_AUDIT_LOG = join(REPO_ROOT, 'store', 'ponder-egress.jsonl')
// A whole URL, and its query, may not be long enough to smuggle a document out. Chosen from what
// public research URLs look like (a search URL is well under 300 characters), not measured on
// Ponder's own traffic, which does not exist yet; both are one-line constants for that reason.
const PONDER_MAX_URL = 2048
const PONDER_MAX_QUERY = 512
// The ONLY Playwright tools Ponder may call: they read a page, move around it, or aim at a URL that gets
// the rules below. Everything else is refused, including what puts data into a page (type,
// press_sequentially, fill_form, select_option, check, keydown, file_upload, drop, handle_dialog), runs
// code in it (evaluate, run_code_unsafe), writes browser state (cookie_set, localstorage_set,
// sessionstorage_set, set_storage_state) or rewrites traffic (route, network_state_set), and the tools
// that call into the page (webmcp_call). Adding a tool here is a one-line decision, made on purpose.
const PONDER_BROWSER_ALLOWED = new Set([
  'mcp__playwright__browser_navigate',
  'mcp__playwright__browser_navigate_back',
  'mcp__playwright__browser_navigate_forward',
  'mcp__playwright__browser_reload',
  'mcp__playwright__browser_tabs',          // action-checked below
  'mcp__playwright__browser_close',
  'mcp__playwright__browser_snapshot',
  'mcp__playwright__browser_take_screenshot',
  'mcp__playwright__browser_find',
  'mcp__playwright__browser_wait_for',
  'mcp__playwright__browser_console_messages',
  'mcp__playwright__browser_network_requests',
  'mcp__playwright__browser_network_request',
  'mcp__playwright__browser_click',
  'mcp__playwright__browser_hover',
  'mcp__playwright__browser_press_key',
])
// browser_press_key types ANY character it is given ("a", "Shift+a"), one call per character, which would
// empty the ban on type / press_sequentially. For Ponder only a key that PRINTS NOTHING is allowed, matched
// exactly (case-sensitive, no modifier combos): they move around and submit, they do not enter text.
const PONDER_KEYS_ALLOWED = new Set([
  'Enter', 'Escape', 'Tab', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp', 'PageDown', 'Home', 'End',
])
// PONDERTYPECEG1008 (owner decision, Telegram 3821, 2026-10-08): ONE narrow exception to the ban on
// putting text into a page. browser_type -- and nothing else from the deny list -- passes for Ponder ONLY
// when (a) the last URL this gate let Ponder navigate to is on a host in PONDER_TYPE_HOSTS, recorded by the
// runner below and younger than PONDER_TYPE_TTL_MS, and (b) the text is a short company name or registry
// number (PONDER_TYPE_TEXT). The free search box of the Hungarian company registry needs typing, and the
// search is a GET the page builds itself, so there is no URL to navigate to instead.
// KNOWN LIMIT, stated: the recorded host is what the GATE allowed last, not what the page shows now. A link
// clicked on the registry page, or a redirect, can move the tab elsewhere without the gate seeing it. The
// text rule bounds what can be typed there: letters, digits, space and . , & ' - / ( ), at most 100 chars.
export const PONDER_TYPE_HOSTS = new Set(['e-cegjegyzek.hu'])
export const PONDER_TYPE_TTL_MS = 30 * 60 * 1000
const PONDER_TYPE_TEXT = /^[\p{L}\p{N} .,&'\-\/()]{1,100}$/u
const PONDER_TYPE_STATE = join(REPO_ROOT, 'store', '.ponder-browser-host.json')
export function ponderTypeHostAllowed(host) {
  const h = String(host ?? '').toLowerCase()
  for (const d of PONDER_TYPE_HOSTS) if (h === d || h.endsWith('.' + d)) return true
  return false
}
function readPonderLastHost(now = Date.now()) {
  try {
    const s = JSON.parse(readFileSync(PONDER_TYPE_STATE, 'utf-8'))
    if (typeof s?.host !== 'string' || typeof s?.ts !== 'number' || now - s.ts > PONDER_TYPE_TTL_MS || s.ts > now) return ''
    return s.host
  } catch { return '' }
}
function writePonderLastHost(url) {
  try {
    const host = new URL(url).hostname
    mkdirSync(dirname(PONDER_TYPE_STATE), { recursive: true })
    writeFileSync(PONDER_TYPE_STATE, JSON.stringify({ host, ts: Date.now() }))
  } catch { /* an unwritable state only keeps typing closed */ }
}

// browser_tabs: list, select, close and new. A new tab with a url navigates, so that url is judged.
const PONDER_TABS_ACTIONS = new Set(['list', 'select', 'close', 'new'])

// Who is calling: 'ponder' or ''. Fail-closed: every doubt is ''.
export function callerIdentity(payload, root = REPO_ROOT) {
  if (!payload || typeof payload !== 'object') return ''
  if (payload.agent_type || payload.agent_id) return ''        // a helper, not the top-level session
  const tp = payload.transcript_path
  if (typeof tp !== 'string' || !tp.startsWith('/') || tp.includes('\0')) return ''
  // The harness hands over a canonical path. One that changes under normalisation (`..`, `//`, `/./`)
  // was not produced by it, and is not trusted.
  if (normalize(tp) !== tp) return ''
  const base = join(root, 'agents', PONDER_AGENT, '.claude-config') + sep
  return tp.startsWith(base) ? 'ponder' : ''
}

// Why a URL is not a public, readable address -- or null. Used for Ponder only.
export function ponderUrlDenied(url) {
  let u
  try { u = new URL(url) } catch { return 'unparseable' }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'scheme'
  if (u.username || u.password) return 'userinfo'
  const host = u.hostname.toLowerCase().replace(/\.$/, '')
  if (!host) return 'no-host'
  // The most specific reason first: an internal host is named as such even when it also carries a port.
  if (isQuarantineDenied(url)) return 'internal-host'
  if (host.includes(':') || /^\d+(\.\d+){0,3}$/.test(host) || /^0x/i.test(host)) return 'ip-literal'
  if (!host.includes('.')) return 'single-label-host'
  if (u.port && u.port !== '80' && u.port !== '443') return 'port'
  if (String(url).length > PONDER_MAX_URL) return 'url-too-long'
  if (u.search.length > PONDER_MAX_QUERY) return 'query-too-long'
  return null
}

// ---- the resolved address (Ponder only) ---------------------------------------------------------
// True when an address is not a public unicast one. Takes what a resolver returns (a v4 or v6 literal).
export function isNonPublicAddress(addr) {
  const kind = isIP(addr)
  if (kind === 4) {
    const [a, b, c] = addr.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)           // CGNAT
      || (a === 169 && b === 254)                     // link-local, metadata
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && c === 0)            // IETF protocol assignments
      || (a === 198 && (b === 18 || b === 19))        // benchmarking
  }
  if (kind === 6) {
    // Expand to 8 groups so ::ffff:a00:1 and ::ffff:10.0.0.1 are the same thing.
    let h = addr.toLowerCase().split('%')[0]
    const dotted = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(h)
    if (dotted) {
      const o = dotted[2].split('.').map(Number)
      h = dotted[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16)
    }
    const [head, tail = null] = h.split('::')
    const hg = head ? head.split(':') : []
    const tg = tail === null ? [] : (tail ? tail.split(':') : [])
    const g = tail === null ? hg : [...hg, ...Array(Math.max(0, 8 - hg.length - tg.length)).fill('0'), ...tg]
    if (g.length !== 8) return true                    // not parseable: refuse
    const w = g.map((x) => parseInt(x, 16))
    if (w.some((x) => Number.isNaN(x))) return true
    const v4of = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`
    if (w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0)) {
      // v4-mapped / v4-compatible: judge the embedded v4. A bare :: or ::1 lands here as 0.0.0.0 / 0.0.0.1.
      return isNonPublicAddress(v4of(w[6], w[7]))
    }
    // v4-translated (SIIT, ::ffff:0:a.b.c.d): the same, one group over.
    if (w.slice(0, 4).every((x) => x === 0) && w[4] === 0xffff && w[5] === 0) return isNonPublicAddress(v4of(w[6], w[7]))
    if (w[0] === 0x64 && w[1] === 0xff9b && w.slice(2, 6).every((x) => x === 0)) return isNonPublicAddress(v4of(w[6], w[7]))   // NAT64
    if (w[0] === 0x64 && w[1] === 0xff9b && w[2] === 1) return true                       // 64:ff9b:1::/48, local-use NAT64: not global
    if (w[0] === 0x2002) return isNonPublicAddress(v4of(w[1], w[2]))                       // 6to4: the v4 is in bits 16-47
    if (w[0] === 0x2001 && w[1] === 0) {                                                   // Teredo: server v4 plain, client v4 XOR 0xffff
      return isNonPublicAddress(v4of(w[2], w[3])) || isNonPublicAddress(v4of(w[6] ^ 0xffff, w[7] ^ 0xffff))
    }
    if ((w[0] & 0xfe00) === 0xfc00) return true       // unique-local
    if ((w[0] & 0xffc0) === 0xfe80) return true       // link-local
    if ((w[0] & 0xffc0) === 0xfec0) return true       // site-local (fec0::/10, deprecated, never global)
    if ((w[0] & 0xff00) === 0xff00) return true       // multicast
    return false
  }
  return true                                          // not an address at all
}

const PONDER_DNS_TIMEOUT_MS = 3000

// Resolve the URL's host and refuse it when ANY address is non-public, or when it cannot be resolved
// (fail closed: a name that does not resolve here would not be fetched either). `lookup` is a parameter
// for tests. Returns a reason string or null. The tool resolves again later; see the header.
export async function ponderResolvedDenied(url, lookup = (h) => dns.promises.lookup(h, { all: true })) {
  let host
  try { host = new URL(url).hostname.toLowerCase().replace(/\.$/, '') } catch { return 'unparseable' }
  let timer
  try {
    const addrs = await Promise.race([
      lookup(host),
      new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), PONDER_DNS_TIMEOUT_MS) }),
    ])
    const list = Array.isArray(addrs) ? addrs : [addrs]
    if (list.length === 0) return 'dns-unresolved'
    for (const a of list) if (isNonPublicAddress(String(a?.address ?? ''))) return 'resolves-to-non-public'
    return null
  } catch (e) {
    return e?.code === 'ETIMEOUT' ? 'dns-timeout' : 'dns-unresolved'
  } finally {
    clearTimeout(timer)
  }
}

// The URL a Ponder decision let through on the strength of its HOST, i.e. the one whose resolved address
// must also be checked -- or ''. WebFetch via the Ponder tier, browser_navigate, and browser_tabs with a url.
export function ponderJudgedUrl(toolName, toolInput, decision) {
  if (!decision || decision.blocked) return ''
  const url = typeof toolInput?.url === 'string' ? toolInput.url : ''
  if (toolName === 'WebFetch') return decision.tier === 'ponder-open' ? url : ''
  if (toolName === 'mcp__playwright__browser_navigate' || toolName === 'mcp__playwright__browser_tabs') return decision.tier === 'ponder-browser' ? url : ''
  return ''
}

// Load the runtime allowlist from store/egress-allowlist.json.
// FAIL-OPEN on the file: missing or malformed -> empty lists, NOT an error.
// The caller must still apply the built-in ALLOWED_PREFIXES.
export function loadRuntimeAllowlist() {
  try {
    const raw = readFileSync(RUNTIME_ALLOWLIST_PATH, 'utf-8')
    const parsed = JSON.parse(raw)
    return {
      domains: Array.isArray(parsed.domains) ? parsed.domains.filter((d) => typeof d === 'string') : [],
      prefixes: Array.isArray(parsed.prefixes) ? parsed.prefixes.filter((p) => typeof p === 'string') : [],
      // Operator-managed extension of the QUARANTINE tier. Reachable ONLY by
      // the quarantine-reader sub-agent -- putting a domain here does not open
      // it to the main agent, which is the whole point of the split.
      quarantineDomains: Array.isArray(parsed.quarantine_domains)
        ? parsed.quarantine_domains.filter((d) => typeof d === 'string')
        : [],
      // The reader-posture switch. ONLY the literal string "denylist" opens
      // the reader; any other value -- absent key, typo, wrong type -- is the
      // allowlist default. Fail-closed to the louder failure direction.
      quarantinePosture: parsed.quarantine_reader_posture === 'denylist' ? 'denylist' : 'allowlist',
      // The Ponder switch: ONLY the literal "open" opens it (see the header).
      ponderPosture: parsed.ponder_posture === 'open' ? 'open' : 'closed',
    }
  } catch {
    // Missing file or JSON parse error: treat as empty, never propagate.
    return { domains: [], prefixes: [], quarantineDomains: [], quarantinePosture: 'allowlist', ponderPosture: 'closed' }
  }
}

// Pure decision, with the tier that decided it.
//
// `runtimeList` is the decoded store/egress-allowlist.json (or any equivalent
// object) and `agentType` is the payload's `agent_type` -- empty for a main
// agent. Keeping file I/O out of this function makes it fully unit-testable
// without touching the filesystem.
//
// The tier is returned because the quarantine tier is the security-relevant
// exception and its grants are audited: a fetch nobody can see is a hole
// nobody can find.
//
// Domain matching uses URL-parsed hostname ONLY, not string-contains, to prevent
// bypasses like `https://evil.com/?x=docs.anthropic.com` matching the domain
// "docs.anthropic.com" via a simple includes() check.
export function egressDecision(
  toolName,
  toolInput,
  runtimeList = { domains: [], prefixes: [], quarantineDomains: [] },
  agentType = '',
  caller = '',
  ponderLastHost = '',
) {
  // Playwright: only the Ponder identity is ever judged here; everybody else is unchanged (allowed).
  if (typeof toolName === 'string' && toolName.startsWith('mcp__playwright__')) {
    if (caller !== 'ponder') return { blocked: false, tier: 'not-webfetch' }
    if (toolName === 'mcp__playwright__browser_type') {
      const text = toolInput?.text
      if (ponderTypeHostAllowed(ponderLastHost) && typeof text === 'string' && PONDER_TYPE_TEXT.test(text))
        return { blocked: false, tier: 'ponder-browser-type' }
      return { blocked: true, tier: 'ponder-denied', reason: 'browser-tool-not-allowed' }
    }
    if (!PONDER_BROWSER_ALLOWED.has(toolName)) return { blocked: true, tier: 'ponder-denied', reason: 'browser-tool-not-allowed' }
    if (toolName === 'mcp__playwright__browser_navigate') {
      const why = ponderUrlDenied(String(toolInput?.url ?? ''))
      if (why) return { blocked: true, tier: 'ponder-denied', reason: why }
      return { blocked: false, tier: 'ponder-browser' }
    }
    if (toolName === 'mcp__playwright__browser_press_key') {
      const key = toolInput?.key
      if (typeof key !== 'string' || !PONDER_KEYS_ALLOWED.has(key)) return { blocked: true, tier: 'ponder-denied', reason: 'browser-key-not-allowed' }
      return { blocked: false, tier: 'ponder-browser' }
    }
    if (toolName === 'mcp__playwright__browser_tabs') {
      const action = toolInput?.action
      if (typeof action !== 'string' || !PONDER_TABS_ACTIONS.has(action)) return { blocked: true, tier: 'ponder-denied', reason: 'browser-tabs-action' }
      // A url on any action is judged, not only on "new": the tool ignores it elsewhere today, and a
      // later version that does not is closed by default.
      if (toolInput?.url !== undefined && toolInput?.url !== null && toolInput?.url !== '') {
        const why = ponderUrlDenied(typeof toolInput.url === 'string' ? toolInput.url : '')
        if (why) return { blocked: true, tier: 'ponder-denied', reason: why }
      }
      return { blocked: false, tier: 'ponder-browser' }
    }
    return { blocked: false, tier: 'ponder-browser' }
  }
  if (toolName !== 'WebFetch') return { blocked: false, tier: 'not-webfetch' }
  const url = String(toolInput?.url ?? '')
  if (!url) return { blocked: false, tier: 'no-url' }

  // 00. The Ponder tier, rules first: they run BEFORE every allow path, so a built-in prefix (this
  //     install's own dashboard, http://localhost:PORT/) cannot re-open what the rules wall off. Only for
  //     the identified caller AND the operator switch; everyone else never reaches this block (a closed
  //     switch still refuses internal hosts to the Ponder session, below).
  const ponderOpen = caller === 'ponder' && (runtimeList.ponderPosture ?? 'closed') === 'open'
  if (ponderOpen) {
    const why = ponderUrlDenied(url)
    if (why) return { blocked: true, tier: 'ponder-denied', reason: why }
  } else if (caller === 'ponder') {
    // PONDERTIER1003 v4: with the switch CLOSED the Ponder session is still the Ponder session, and the
    // built-in grants below (this install's own dashboard, http://localhost:PORT/, is one) are for the
    // other agents' jobs. The research agent never has a reason to read an internal address, so an
    // internal host or an IP literal is refused for it whatever the switch says. Public names keep the
    // old behaviour exactly (a closed switch opens nothing, and closes nothing it did not close before).
    const why = ponderUrlDenied(url)
    if (why === 'internal-host' || why === 'ip-literal') return { blocked: true, tier: 'ponder-denied', reason: why }
  }

  const openReader = String(agentType ?? '') === QUARANTINE_AGENT_TYPE
    && (runtimeList.quarantinePosture ?? 'allowlist') === 'denylist'

  // 0. Reader deny rules, BEFORE every allow path -- in the denylist posture
  //    only, so the default posture stays byte-identical to the pre-switch
  //    gate. Order matters and was found by a test, not by reading: the
  //    built-in prefixes include this install's own dashboard
  //    (http://localhost:PORT/), so with the deny rules consulted only in
  //    step 4 an open reader would have reached localhost through step 1 --
  //    the one address the deny rules exist to refuse. An allowlist that
  //    predates the switch must not be able to re-open what the open posture
  //    walls off.
  if (openReader && isQuarantineDenied(url)) {
    return { blocked: true, tier: 'quarantine-denied' }
  }

  // 1. Built-in prefix check (startsWith is correct here: the prefix already
  //    includes the trailing slash so a prefix-extension attack is impossible,
  //    e.g. 'https://api.github.com.evil.com/' does not start with
  //    'https://api.github.com/').
  if (ALLOWED_PREFIXES.some((prefix) => url.startsWith(prefix))) return { blocked: false, tier: 'builtin' }

  // 2. Runtime prefix check.
  const rtPrefixes = runtimeList.prefixes ?? []
  if (rtPrefixes.some((p) => url.startsWith(p))) return { blocked: false, tier: 'runtime-prefix' }

  // 3. Runtime domain check: parse the URL to extract a verified hostname.
  //    URL parsing fails on non-URLs -> block (fail-safe).
  const rtDomains = runtimeList.domains ?? []
  if (rtDomains.length > 0) {
    let hostname
    try {
      hostname = new URL(url).hostname
    } catch {
      // Unparseable URL: block, don't throw.
      return { blocked: true, tier: 'unparseable' }
    }
    // Match exact hostname OR any subdomain (host.endsWith('.' + domain)).
    if (rtDomains.some((d) => hostname === d || hostname.endsWith('.' + d))) return { blocked: false, tier: 'runtime-domain' }
  }

  // 4. Quarantine tier -- the ONLY tier a main agent cannot reach. Exact
  //    agent_type match required (fail-closed: anything else falls through to
  //    the block below).
  //
  //    In the allowlist posture (the default) the named domains are the whole
  //    grant, exactly as before the switch existed. In the denylist posture
  //    two sub-cases, in this order:
  //    (a) the shipped feeds and operator additions -- allowed as before, so
  //        flipping the posture can never break a long-standing source;
  //    (b) anything else -- allowed UNLESS the deny rules catch it. The
  //        re-check is defence in depth: step 0 already refused denied URLs,
  //        and this keeps that true even if someone later reorders the steps.
  if (String(agentType ?? '') === QUARANTINE_AGENT_TYPE) {
    if (matchesQuarantineDomain(url, runtimeList.quarantineDomains ?? [])) {
      return { blocked: false, tier: 'quarantine' }
    }
    if (openReader) {
      if (!isQuarantineDenied(url)) return { blocked: false, tier: 'quarantine-open' }
      return { blocked: true, tier: 'quarantine-denied' }
    }
  }

  // 5. The Ponder tier: whatever the rules above did not refuse, a public URL, is readable.
  if (ponderOpen) return { blocked: false, tier: 'ponder-open' }

  return { blocked: true, tier: 'none' }
}

// Back-compatible boolean form.
export function isEgressBlocked(toolName, toolInput, runtimeList, agentType, caller) {
  return egressDecision(toolName, toolInput, runtimeList, agentType, caller).blocked
}

// The payload's top-level FIELD NAMES, sorted -- never a value.
//
// This exists to answer one open question with data instead of a guess: does
// the PreToolUse payload carry anything that identifies the CALLER? The gate
// decides on the URL alone, so a main agent and a quarantine-reader sub-agent
// are indistinguishable to it, and the sub-agent is the escape hatch the block
// message itself prescribes -- which is why the RSS path is currently dead
// (kanban #224). A caller-aware tier can only be built on a field that is
// verified to exist; building it on an assumed one would produce a guard that
// looks like it protects and does not.
//
// Keys only, by construction: a value could carry a url, a prompt, or a
// secret, and this log is read casually. Nested objects contribute nothing but
// their own key.
export function payloadKeySignature(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return ''
  return Object.keys(payload).sort().join(',')
}

// `agentType` IS logged by value, unlike everything else in the payload. It is
// an agent-type name from a fixed set -- not content, not a url, not a secret
// -- and without it a denied sub-agent call cannot be told apart from a denied
// main-agent one, which is exactly the distinction this log now exists to make.
// Verifying this gate by hand -- piping a payload into it after an allowlist
// change -- writes an ALLOWED_QUARANTINE line for a request that never left the
// machine. fetch-budget.py then counts it against the source's daily allowance,
// and its own comment says the opposite: "Only fetches that actually left the
// machine count against a source." Measured 2026-08-28: seven such phantom
// lines, one on every domain approved that morning, and the caller read them
// back as real traffic before starting a sweep.
//
// EGRESS_GATE_SELFTEST=1 prefixes the log kind with SELFTEST_ so those lines
// are visibly not traffic. It NEVER touches the decision -- allow and deny come
// out exactly the same with it set or unset -- because a gate with a switch
// that changes what it permits is not a gate.
//
// If the variable is ever left set in a live session, real fetches log as
// SELFTEST_ and go uncounted. That fails quiet, so fetch-budget.py should say
// out loud when it skips SELFTEST_ lines rather than silently reporting less.
const SELFTEST = process.env.EGRESS_GATE_SELFTEST === '1'

function logLine(kind, url, detail, keys = '', agentType = '') {
  try {
    mkdirSync(join(REPO_ROOT, 'store'), { recursive: true })
    const ts = new Date().toISOString()
    if (SELFTEST) kind = `SELFTEST_${kind}`
    const keyPart = keys ? ` payload_keys="${keys}"` : ''
    const agentPart = agentType ? ` agent_type="${agentType}"` : ''
    appendFileSync(EGRESS_BLOCK_LOG, `${ts} ${kind} url="${url}" ${detail}${agentPart}${keyPart}\n`, 'utf-8')
  } catch {
    // Never let log failure cascade into blocking the agent process itself.
  }
}

// Every Ponder call that reaches the gate, allowed or denied, one JSON object per line. The full URL
// IS logged (it is the thing under audit: a URL that carries data out is only findable if it is kept),
// so this file is as private as store/ itself. Never logged: the WebFetch `prompt`, page content.
export function ponderAuditLine(payload, decision, ts = new Date().toISOString()) {
  const url = String(payload?.tool_input?.url ?? '')
  let host = '', queryLen = 0
  try { const u = new URL(url); host = u.hostname; queryLen = u.search.length } catch { /* not a url */ }
  return JSON.stringify({
    ts,
    ...(SELFTEST ? { selftest: true } : {}),
    session: String(payload?.session_id ?? ''),
    tool: String(payload?.tool_name ?? ''),
    decision: decision.blocked ? 'deny' : 'allow',
    tier: decision.tier,
    ...(decision.reason ? { reason: decision.reason } : {}),
    host,
    url,
    url_len: url.length,
    query_len: queryLen,
  })
}

function auditPonder(payload, decision) {
  try {
    mkdirSync(join(REPO_ROOT, 'store'), { recursive: true })
    appendFileSync(PONDER_AUDIT_LOG, ponderAuditLine(payload, decision) + '\n', 'utf-8')
  } catch {
    // An audit failure must not turn into a block or an allow of its own: the decision stands.
  }
}

const PONDER_DENY_MESSAGE = (reason) =>
  'Egress TILTOTT (egress-gate hook, Ponder-szint). Ponder csak NYILVANOS web-cimet olvashat: http(s), ' +
  'felhasznalonev nelkul, 80/443-as porton, nev szerint (nem IP-cimre, nem belso hosztra), legfeljebb ' +
  `${PONDER_MAX_URL} karakteres URL-lel, ${PONDER_MAX_QUERY} karakteres lekerdezessel; a bongeszoben csak ` +
  `az engedelyezett olvaso eszkozok mennek (navigate, snapshot, screenshot, find, click, ...), es a nev ` +
  `feloldott cime is nyilvanos kell legyen. A kapu oka: ${reason}. ` +
  'A hivas rogzitve lett a store/ponder-egress.jsonl fajlban.'

const BLOCK_MESSAGE =
  'Egress TILTOTT (egress-gate hook). Ez az URL nem szerepel a fő ágens WebFetch ' +
  'engedélylistáján. Külső web-tartalom (RSS, dokumentáció, cikkek, ismeretlen API-k) ' +
  'KIZÁRÓLAG a quarantine-reader sub-ágensen keresztül kérhető le: ' +
  'Agent({ subagent_type: "quarantine-reader", prompt: `FETCH {"url":"...","nonce":"..."}` }). ' +
  'A letiltott hívás rögzítve lett a store/egress-blocked.log fájlban. ' +
  'Ha ez a hívás jogos, az operátor jóváhagyhatja: adja hozzá az URL-t vagy domain-t a ' +
  'store/egress-allowlist.json fájlhoz ({ "domains": ["example.com"] } vagy ' +
  '{ "prefixes": ["https://example.com/api/"] }), majd futtassa újra a WebFetch hívást.'

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
    allow() // malformed/empty input must never block the agent
  }
  const url = String(payload?.tool_input?.url ?? '')
  const agentType = String(payload?.agent_type ?? '')
  const runtimeList = loadRuntimeAllowlist()
  const caller = callerIdentity(payload)
  const decision = egressDecision(payload?.tool_name, payload?.tool_input, runtimeList, agentType, caller,
    caller === 'ponder' && payload?.tool_name === 'mcp__playwright__browser_type' ? readPonderLastHost() : '')
  // The rules above judged the NAME; for the Ponder tier the address the name resolves to is judged too.
  let finalDecision = decision
  if (caller === 'ponder') {
    const judged = ponderJudgedUrl(payload?.tool_name, payload?.tool_input, decision)
    if (judged) {
      const why = await ponderResolvedDenied(judged)
      if (why) finalDecision = { blocked: true, tier: 'ponder-denied', reason: why }
    }
  }
  if (caller === 'ponder' && (payload?.tool_name === 'WebFetch' || String(payload?.tool_name ?? '').startsWith('mcp__playwright__'))) {
    auditPonder(payload, finalDecision)
  }
  if (finalDecision !== decision) {
    logLine('BLOCKED', url, `reason="ponder: ${finalDecision.reason}"`, payloadKeySignature(payload), agentType)
    deny(PONDER_DENY_MESSAGE(finalDecision.reason))
  }
  if (decision.blocked && decision.tier === 'ponder-denied') {
    logLine('BLOCKED', url, `reason="ponder: ${decision.reason}"`, payloadKeySignature(payload), agentType)
    deny(PONDER_DENY_MESSAGE(decision.reason))
  }
  if (decision.blocked) {
    logLine('BLOCKED', url, 'reason="not on egress allowlist"', payloadKeySignature(payload), agentType)
    deny(BLOCK_MESSAGE)
  }
  // Audited, not silent: the quarantine tier is the one grant a main agent
  // cannot obtain, so every use of it leaves a line next to the denials. The
  // other tiers are the ordinary allowlist and stay quiet.
  if (decision.tier === 'quarantine') {
    logLine('ALLOWED_QUARANTINE', url, 'reason="quarantine-reader tier"', '', agentType)
  }
  // PONDERTYPECEG1008: remember where the gate last let Ponder go, for the browser_type exception.
  if (caller === 'ponder') {
    const tn = payload?.tool_name
    const navUrl = tn === 'mcp__playwright__browser_navigate' ? payload?.tool_input?.url
      : (tn === 'mcp__playwright__browser_tabs' && payload?.tool_input?.action === 'new') ? payload?.tool_input?.url : undefined
    if (typeof navUrl === 'string' && navUrl) writePonderLastHost(navUrl)
  }
  allow()
}
