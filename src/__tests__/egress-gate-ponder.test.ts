// PONDERTIER1003 (kanban c1dc4109, owner decision TG 3041 #67): the Ponder tier of the egress gate.
//
// One agent -- the research agent `agents/ponder` -- may READ the public web without an allowlist.
// Everybody else must come out byte-identical to before. A test file that only proved the first half
// would prove the gate is open for Ponder, not that it is closed for the rest, so the second half is
// the larger one: every "Ponder may" case has a twin where the same call from any other caller, or
// from Ponder with the switch off, is refused exactly as it was.
import { describe, it, expect, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs hook script, no types
import { egressDecision, callerIdentity, ponderUrlDenied, ponderAuditLine, loadRuntimeAllowlist, isNonPublicAddress, ponderResolvedDenied, ponderJudgedUrl } from '../../scripts/hooks/egress-gate.mjs'
import { injectEgressGate, ensureEgressGate, PONDER_BROWSER_MATCHER, injectBashEgressParser, injectSelfPaceGate } from '../web/agent-scaffold.js'
import { PROJECT_ROOT } from '../config.js'
import { describeAllowlistChange } from '../web/egress-allowlist-baseline.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..', '..')
const SCRIPT = join(ROOT, 'scripts', 'hooks', 'egress-gate.mjs')

type RT = { domains: string[]; prefixes: string[]; quarantineDomains: string[]; ponderPosture?: string }
const EMPTY: RT = { domains: [], prefixes: [], quarantineDomains: [] }
const OPEN: RT = { ...EMPTY, ponderPosture: 'open' }
const CLOSED: RT = { ...EMPTY, ponderPosture: 'closed' }
const PUBLIC = 'https://www.e-cegjegyzek.hu/?cegjegyzek'

const ponderTp = (root = ROOT) => join(root, 'agents', 'ponder', '.claude-config', 'projects', '-x', 's.jsonl')
const payload = (over: Record<string, unknown> = {}, root = ROOT) => ({
  tool_name: 'WebFetch',
  tool_input: { url: PUBLIC, prompt: 'p' },
  transcript_path: ponderTp(root),
  session_id: 'sess-1',
  ...over,
})

describe('identity: who is Ponder', () => {
  it('the top-level session whose transcript lives under agents/ponder/.claude-config', () => {
    expect(callerIdentity(payload())).toBe('ponder')
  })

  it('nobody else: every other agent, the main agent, the shared config root', () => {
    for (const tp of [
      join(ROOT, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl'),
      join(ROOT, 'agents', 'sam', '.claude-config', 'projects', '-x', 's.jsonl'),
      join(ROOT, '.channels-config', 'projects', '-x', 's.jsonl'),
      '/home/someone/.claude/projects/-x/s.jsonl',
    ]) expect({ tp, who: callerIdentity(payload({ transcript_path: tp })) }).toEqual({ tp, who: '' })
  })

  it('lookalikes are not Ponder: a longer name, a longer config dir, another subdirectory', () => {
    for (const tp of [
      join(ROOT, 'agents', 'ponder-evil', '.claude-config', 'projects', 's.jsonl'),
      join(ROOT, 'agents', 'ponder', '.claude-config-x', 'projects', 's.jsonl'),
      join(ROOT, 'agents', 'ponder', '.claude', 'projects', 's.jsonl'),
      join(ROOT, 'agents', 'ponder', 'research', 's.jsonl'),
      join(ROOT, 'agents', 'ponder', '.claude-config'),
      join(ROOT, 'xagents', 'ponder', '.claude-config', 's.jsonl'),
    ]) expect({ tp, who: callerIdentity(payload({ transcript_path: tp })) }).toEqual({ tp, who: '' })
  })

  it('a path the harness would not produce is not trusted (.., //, /./, relative, NUL)', () => {
    const good = ponderTp()
    for (const tp of [
      join(ROOT, 'agents', 'ponder', '.claude-config', '..', '..', 'igor', '.claude-config', 's.jsonl'),
      good.replace('/projects/', '//projects/'),
      good.replace('/projects/', '/./projects/'),
      `agents/ponder/.claude-config/projects/s.jsonl`,
      good + '\0',
    ]) expect({ tp, who: callerIdentity(payload({ transcript_path: tp })) }).toEqual({ tp, who: '' })
  })

  it('a helper Ponder spawned (agent_type / agent_id present) is not the top-level session', () => {
    expect(callerIdentity(payload({ agent_type: 'general-purpose' }))).toBe('')
    expect(callerIdentity(payload({ agent_type: 'quarantine-reader' }))).toBe('')
    expect(callerIdentity(payload({ agent_id: 'a1' }))).toBe('')
  })

  it('what the CALLER composes proves nothing: cwd, tool input, a name in the prompt', () => {
    const igor = join(ROOT, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl')
    expect(callerIdentity(payload({ transcript_path: igor, cwd: join(ROOT, 'agents', 'ponder') }))).toBe('')
    expect(callerIdentity(payload({ transcript_path: igor, tool_input: { url: PUBLIC, agent: 'ponder' } }))).toBe('')
  })

  it('missing, empty or non-string transcript_path, and a non-object payload', () => {
    for (const p of [null, undefined, 'x', 7, {}, { transcript_path: '' }, { transcript_path: 5 }])
      expect(callerIdentity(p as never)).toBe('')
  })

  it('the install root is a parameter, so a copy of the install is judged against ITS root', () => {
    expect(callerIdentity(payload({}, '/srv/inst'), '/srv/inst')).toBe('ponder')
    expect(callerIdentity(payload({}, '/srv/inst'), ROOT)).toBe('')
  })
})

describe('WebFetch: what the Ponder tier opens, and only for Ponder', () => {
  const d = (url: string, rt = OPEN, caller = 'ponder', agentType = '') =>
    egressDecision('WebFetch', { url }, rt, agentType, caller)

  it('Ponder with the switch open reads a public URL that is on no list', () => {
    expect(d(PUBLIC)).toEqual({ blocked: false, tier: 'ponder-open' })
    expect(d('https://hnrss.org/frontpage').blocked).toBe(false)
  })

  it('CONTROL: the same URL is blocked for any other caller, with the switch open', () => {
    expect(d(PUBLIC, OPEN, '').blocked).toBe(true)
    expect(d(PUBLIC, OPEN, '', 'general-purpose').blocked).toBe(true)
  })

  it('CONTROL: the same URL is blocked for Ponder when the switch is closed or absent', () => {
    expect(d(PUBLIC, CLOSED).blocked).toBe(true)
    expect(d(PUBLIC, EMPTY).blocked).toBe(true)
  })

  it('the quarantine-reader keeps its own tier: a helper of Ponder is NOT opened by the Ponder switch', () => {
    // the helper reaches the gate with an agent_type, hence caller '' (callerIdentity), hence today's rules
    expect(d(PUBLIC, OPEN, '', 'quarantine-reader').blocked).toBe(true)
  })

  it('everything that was allowed stays allowed (built-in prefixes)', () => {
    expect(d('https://api.github.com/repos/a/b').blocked).toBe(false)
    expect(d('https://api.github.com/repos/a/b', CLOSED).blocked).toBe(false)
  })

  it('the rules run BEFORE every allow path: the dashboard prefix cannot re-open an internal host', () => {
    // http://localhost:PORT/ is on the built-in list. For Ponder the rules refuse it first.
    expect(d('http://localhost:3420/api/memories')).toMatchObject({ blocked: true, reason: 'internal-host' })
    expect(d('http://127.0.0.1:3420/api/kanban').blocked).toBe(true)
    // ...while the same URL for another caller is the built-in grant it always was
    expect(d('http://localhost:3420/api/kanban', OPEN, '').blocked).toBe(false)
  })

  it('a runtime-allowlisted internal name is refused for Ponder too (rules before allow)', () => {
    const rt = { ...OPEN, domains: ['intranet.example'], prefixes: ['http://10.0.0.5/'] }
    expect(d('http://10.0.0.5/x', rt).blocked).toBe(true)
  })
})

describe('WebFetch: the URL rules (a public address, nothing that can carry data out in bulk)', () => {
  const why = (url: string): string | null => ponderUrlDenied(url)

  it('accepts ordinary research URLs', () => {
    for (const u of [
      'https://www.e-cegjegyzek.hu/?cegadatlap',
      'http://example.com/a/b.html',
      'https://mekh.hu:443/dokumentum.pdf',
      'https://example.org/search?q=napelem+telepítés+kft',
    ]) expect({ u, why: why(u) }).toEqual({ u, why: null })
  })

  it('refuses internal, private, loopback, link-local and metadata hosts', () => {
    for (const u of [
      'http://localhost/x', 'http://localhost.localdomain/x', 'http://foo.localhost/x', 'http://nas.local/x',
      'http://metadata.google.internal/x', 'http://svc.internal/x', 'http://router.home.arpa/x',
      'http://10.1.2.3/x', 'http://192.168.0.1/x', 'http://172.16.5.5/x', 'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1/x', 'http://[::1]/x', 'http://[fd00::1]/x', 'http://0.0.0.0/x',
    ]) expect({ u, denied: why(u) !== null }).toEqual({ u, denied: true })
  })

  it('refuses every IP literal, in the spellings a resolver reads differently', () => {
    for (const u of ['http://8.8.8.8/x', 'http://2130706433/x', 'http://0x7f.0.0.1/x', 'http://017700000001/x', 'http://127.1/x', 'http://[2001:db8::1]/x'])
      expect({ u, denied: why(u) !== null }).toEqual({ u, denied: true })
  })

  it('refuses a single-label name (a search domain can complete it to anywhere)', () => {
    expect(why('http://intranet/x')).toBe('single-label-host')
    expect(why('http://nas/x')).toBe('single-label-host')
  })

  it('refuses userinfo, other ports and other schemes', () => {
    expect(why('https://user:pw@example.com/')).toBe('userinfo')
    expect(why('https://example.com@evil.example/')).toBe('userinfo')   // the real host is evil.example: the lookalike is userinfo, refused
    expect(why('https://example.com:8080/')).toBe('port')
    expect(why('https://example.com:22/')).toBe('port')
    expect(why('ftp://example.com/x')).toBe('scheme')
    expect(why('file:///etc/passwd')).toBe('scheme')
    expect(why('javascript:alert(1)')).toBe('scheme')
  })

  it('refuses what is not a URL', () => {
    for (const u of ['', 'not a url', '//example.com/x', 'example.com']) expect({ u, why: why(u) }).toEqual({ u, why: 'unparseable' })
  })

  it('caps the whole URL at 2048 and the query at 512, exactly at the boundary', () => {
    const q = (n: number) => `https://example.com/?${'a'.repeat(n - 1)}`            // search = '?' + (n-1) = n chars
    expect(why(q(512))).toBeNull()
    expect(why(q(513))).toBe('query-too-long')
    const long = `https://example.com/${'p'.repeat(2048 - 'https://example.com/'.length)}`
    expect(long.length).toBe(2048)
    expect(why(long)).toBeNull()
    expect(why(long + 'p')).toBe('url-too-long')
  })

  it('a host that merely CONTAINS an internal word is a public host', () => {
    expect(why('https://localhost.example.com/x')).toBeNull()
    expect(why('https://intranet.example.com/x')).toBeNull()
  })
})

// The tool list of the installed @playwright/mcp 0.0.82 (83 names, capabilities config, core, devtools,
// network, pdf, storage, testing, vision), measured from its coreBundle.js. Kept here so a test fails
// when it is compared to a newer package, and so the "everything else is refused" half is proven on
// the REAL names, not on a short list picked to pass. It is a snapshot: a later version is NOT read here.
const ALL_PW_TOOLS = `annotate check click close console_clear console_messages cookie_clear cookie_delete cookie_get cookie_list
cookie_set drag drop emulate_media evaluate file_upload fill_form find generate_locator get_config handle_dialog hide_highlight
highlight hover keydown keyup localstorage_clear localstorage_delete localstorage_get localstorage_list localstorage_set
mouse_click_xy mouse_down mouse_drag_xy mouse_move_xy mouse_up mouse_wheel navigate navigate_back navigate_forward
network_clear network_request network_requests network_state_set pdf_save press_key press_sequentially reload resize resume
route route_list run_code_unsafe select_option sessionstorage_clear sessionstorage_delete sessionstorage_get
sessionstorage_list sessionstorage_set set_storage_state snapshot start_recording start_tracing start_video stop_recording
stop_tracing stop_video storage_state tabs take_screenshot type uncheck unroute verify_element_visible verify_list_visible
verify_text_visible verify_value video_chapter video_hide_actions video_show_actions wait_for webmcp_call webmcp_list`.split(/\s+/)
const PW_ALLOWED = ['navigate', 'navigate_back', 'navigate_forward', 'reload', 'tabs', 'close', 'snapshot', 'take_screenshot', 'find',
  'wait_for', 'console_messages', 'network_requests', 'network_request', 'click', 'hover', 'press_key']

describe('Playwright: only Ponder is judged, and only the reading tools are allowed', () => {
  const pw = (tool: string, input: Record<string, unknown> = {}, rt = OPEN, caller = 'ponder') =>
    egressDecision(`mcp__playwright__browser_${tool}`, input, rt, '', caller)

  it('the list below really is the 83 tools of the installed package', () => {
    expect(ALL_PW_TOOLS).toHaveLength(83)
    expect(new Set(ALL_PW_TOOLS).size).toBe(ALL_PW_TOOLS.length)
    for (const t of PW_ALLOWED) expect(ALL_PW_TOOLS).toContain(t)
  })

  it('CONTROL: every other caller is allowed everything, exactly as before', () => {
    for (const t of [...ALL_PW_TOOLS, 'run_code'])
      expect({ t, b: pw(t, { url: 'http://localhost:3420/', action: 'new' }, OPEN, '').blocked }).toEqual({ t, b: false })
  })

  it('Ponder: ALL 83 tools, only the allowlisted ones pass (the rest is refused by name, not by a short list)', () => {
    const ok = (t: string) => !pw(t, { url: PUBLIC, action: 'list', key: 'Enter' }).blocked
    expect(ALL_PW_TOOLS.filter(ok).sort()).toEqual([...PW_ALLOWED].sort())
    for (const t of ALL_PW_TOOLS.filter((x) => !PW_ALLOWED.includes(x)))
      expect({ t, r: pw(t, { url: PUBLIC, key: 'Enter' }) }).toMatchObject({ t, r: { blocked: true, tier: 'ponder-denied', reason: 'browser-tool-not-allowed' } })
  })

  it('Ponder: browser_press_key passes ONLY a key that prints nothing (v3: otherwise text goes in one character a call)', () => {
    for (const key of ['Enter', 'Escape', 'Tab', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp', 'PageDown', 'Home', 'End'])
      expect({ key, b: pw('press_key', { key }).blocked }).toEqual({ key, b: false })
    for (const key of ['a', 'A', '1', ' ', 'Space', 'Shift+a', 'Control+v', 'Enter+a', 'enter', 'ENTER', 'Enter ', ' Enter', 'Backspace', 'Delete', '@', 'Digit1', 'KeyA', 'Meta+Enter', '', 'Enter\n'])
      expect({ key, r: pw('press_key', { key }) }).toMatchObject({ key, r: { blocked: true, tier: 'ponder-denied', reason: 'browser-key-not-allowed' } })
    for (const input of [{}, { key: 5 }, { key: null }, { key: ['Enter'] }, { key: { toString: 'Enter' } }, { text: 'Enter' }])
      expect({ input, b: pw('press_key', input).blocked }).toEqual({ input, b: true })
    expect(pw('press_key', { key: 'a' }, CLOSED).blocked).toBe(true)                    // not the switch's business
    expect(pw('press_key', { key: 'a' }, OPEN, '').blocked).toBe(false)                 // CONTROL: anyone else unchanged
  })

  it('Ponder: the tools Sam named, and the old deny list, are refused', () => {
    for (const t of ['type', 'fill_form', 'file_upload', 'drop', 'evaluate', 'run_code', 'run_code_unsafe', 'press_sequentially',
      'select_option', 'check', 'uncheck', 'keydown', 'keyup', 'cookie_set', 'localstorage_set', 'sessionstorage_set',
      'set_storage_state', 'route', 'webmcp_call', 'handle_dialog', 'mouse_click_xy'])
      expect({ t, b: pw(t).blocked }).toEqual({ t, b: true })
  })

  it('Ponder: a tool a LATER package version adds is refused by default, so is a name outside browser_*', () => {
    expect(pw('some_tool_added_in_0_0_90')).toMatchObject({ blocked: true, reason: 'browser-tool-not-allowed' })
    expect(egressDecision('mcp__playwright__something', {}, OPEN, '', 'ponder')).toMatchObject({ blocked: true, reason: 'browser-tool-not-allowed' })
  })

  it('PONDERTYPECEG1008: browser_type passes ONLY on the company registry, with a short company-name text', () => {
    const ty = (text: unknown, host: string, caller = 'ponder') =>
      egressDecision('mcp__playwright__browser_type', { element: 'search', ref: 'e1', text }, OPEN, '', caller, host)
    for (const host of ['www.e-cegjegyzek.hu', 'e-cegjegyzek.hu', 'E-CEGJEGYZEK.HU'])
      for (const text of ['HT Solar PV Betulia Kft.', '01-09-123456', 'Árvíztűrő & Társa (HU)'])
        expect({ host, text, r: ty(text, host) }).toMatchObject({ host, text, r: { blocked: false, tier: 'ponder-browser-type' } })
    // the wrong host, a look-alike, no recorded host
    for (const host of ['', 'evil.example', 'e-cegjegyzek.hu.evil.example', 'notE-cegjegyzek.hu', 'xe-cegjegyzek.hu'])
      expect({ host, r: ty('Betulia', host) }).toMatchObject({ host, r: { blocked: true, reason: 'browser-tool-not-allowed' } })
    // text that is not a company name or number
    for (const text of ['', 'a'.repeat(101), 'x@evil.example', 'https://evil.example', 'a\nb', 'a;b', 'a"b', 5, null, ['a']])
      expect({ text, b: ty(text, 'www.e-cegjegyzek.hu').blocked }).toEqual({ text, b: true })
    // every other text-entering tool stays closed, even on the registry
    for (const t of ['fill_form', 'press_sequentially', 'select_option', 'evaluate'])
      expect({ t, b: egressDecision(`mcp__playwright__browser_${t}`, { text: 'Betulia' }, OPEN, '', 'ponder', 'www.e-cegjegyzek.hu').blocked }).toEqual({ t, b: true })
    expect(ty('a;b', '', '').blocked).toBe(false)                                         // CONTROL: anyone else unchanged
  })

  it('Ponder: navigation gets the URL rules', () => {
    expect(pw('navigate', { url: PUBLIC }).blocked).toBe(false)
    expect(pw('navigate', { url: 'http://localhost:3420/' })).toMatchObject({ blocked: true, reason: 'internal-host' })
    expect(pw('navigate', { url: 'http://169.254.169.254/' }).blocked).toBe(true)
    expect(pw('navigate', { url: 'https://u:p@example.com/' })).toMatchObject({ blocked: true, reason: 'userinfo' })
    expect(pw('navigate', { url: 'file:///etc/passwd' }).blocked).toBe(true)
    expect(pw('navigate', {}).blocked).toBe(true)
  })

  it('Ponder: browser_tabs action "new" navigates, so it gets the SAME URL rules (Sam finding 1)', () => {
    expect(pw('tabs', { action: 'new', url: PUBLIC }).blocked).toBe(false)
    expect(pw('tabs', { action: 'new' }).blocked).toBe(false)                       // about:blank, no navigation
    for (const [url, reason] of [['http://localhost:3420/', 'internal-host'], ['http://169.254.169.254/', 'internal-host'],
      ['https://u:p@example.com/', 'userinfo'], ['https://example.com:8443/', 'port'], ['http://10.0.0.1/', 'internal-host'],
      ['file:///etc/passwd', 'scheme'], ['https://example.com/?' + 'q'.repeat(600), 'query-too-long'], ['https://' + 'a'.repeat(2100) + '.com/', 'url-too-long']])
      expect({ url, r: pw('tabs', { action: 'new', url }) }).toMatchObject({ url, r: { blocked: true, reason } })
    expect(pw('tabs', { action: 'new', url: 5 })).toMatchObject({ blocked: true })  // a non-string url is not trusted
  })

  it('Ponder: browser_tabs list / select / close pass; an unknown or missing action is refused; a url on ANY action is judged', () => {
    for (const action of ['list', 'select', 'close']) expect({ action, b: pw('tabs', { action, index: 0 }).blocked }).toEqual({ action, b: false })
    for (const input of [{}, { action: 'goto', url: PUBLIC }, { action: 7 }, { action: null }, { action: 'NEW' }])
      expect({ input, r: pw('tabs', input) }).toMatchObject({ input, r: { blocked: true, reason: 'browser-tabs-action' } })
    expect(pw('tabs', { action: 'select', index: 0, url: 'http://localhost/' })).toMatchObject({ blocked: true, reason: 'internal-host' })
  })

  it('the restrictions do NOT depend on the switch: a closed Ponder is no freer than an open one', () => {
    expect(pw('type', {}, CLOSED).blocked).toBe(true)
    expect(pw('evaluate', {}, EMPTY).blocked).toBe(true)
    expect(pw('press_sequentially', {}, CLOSED).blocked).toBe(true)
    expect(pw('navigate', { url: 'http://localhost/' }, CLOSED).blocked).toBe(true)
    expect(pw('tabs', { action: 'new', url: 'http://localhost/' }, CLOSED).blocked).toBe(true)
  })
})

// PONDERTIER1003 v4, item 1 (owner decision, Telegram 3068): the install's OWN dashboard (localhost:3420,
// the Bearer-token API of every agent's memory, kanban and approvals) is named in the tests, in every
// spelling a URL can give it, on every tool that navigates, for the switch open and closed.
describe('the install\'s own dashboard is refused to Ponder (v4 item 1, named)', () => {
  const DASH = [
    'http://localhost:3420/', 'http://localhost:3420/api/agents', 'https://localhost:3420/', 'http://localhost./', 'http://LOCALHOST:3420/',
    'http://127.0.0.1:3420/', 'http://127.0.0.1:3420/api/memories?agent=hex', 'http://127.1:3420/', 'http://2130706433:3420/', 'http://0x7f000001:3420/',
    'http://0177.0.0.1:3420/', 'http://[::1]:3420/', 'http://[::ffff:127.0.0.1]:3420/', 'http://0.0.0.0:3420/', 'http://dashboard.localhost:3420/',
    'http://hex.local:3420/', 'http://u:p@localhost:3420/', 'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/', 'http://192.168.1.1/',
    'http://172.16.0.1/', 'http://100.64.0.1/', 'http://[fd00::1]/', 'http://[fe80::1]/',
  ]
  const tools = (url: string, rt = OPEN) => ({
    webfetch: egressDecision('WebFetch', { url, prompt: 'p' }, rt, '', 'ponder'),
    navigate: egressDecision('mcp__playwright__browser_navigate', { url }, rt, '', 'ponder'),
    tabsNew: egressDecision('mcp__playwright__browser_tabs', { action: 'new', url }, rt, '', 'ponder'),
  })
  it('every spelling is denied on WebFetch, browser_navigate and browser_tabs new, switch open and closed', () => {
    for (const url of DASH) for (const rt of [OPEN, CLOSED]) {
      const t = tools(url, rt)
      expect({ url, rt: rt.ponderPosture, navigate: t.navigate.blocked, tabsNew: t.tabsNew.blocked }).toEqual({ url, rt: rt.ponderPosture, navigate: true, tabsNew: true })
      expect({ url, rt: rt.ponderPosture, webfetch: t.webfetch.blocked }).toEqual({ url, rt: rt.ponderPosture, webfetch: true })
    }
  })
  it('a public-looking NAME that resolves to the dashboard is refused by the resolved-address step (every spelling of "my machine")', async () => {
    for (const a of ['127.0.0.1', '127.0.0.2', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '0.0.0.0', '10.0.0.5', '192.168.0.10', '172.20.0.3', '169.254.169.254', '100.100.100.200', 'fd12:3456::1', 'fe80::1ff:fe23:4567:890a'])
      expect({ a, r: await ponderResolvedDenied('http://my-hex.example.com/', async () => [{ address: a, family: a.includes(':') ? 6 : 4 }]) }).toEqual({ a, r: 'resolves-to-non-public' })
  })
})

describe('the resolved address (Sam finding 3)', () => {
  const addr = (...a: string[]) => async () => a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))
  it('classifies addresses: every non-public range is refused, ordinary public ones pass', () => {
    for (const a of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '100.64.0.1', '172.16.5.5', '172.31.255.255', '192.168.1.1', '0.0.0.0',
      '224.0.0.1', '255.255.255.255', '198.18.0.1', '192.0.0.8', '::1', '::', 'fe80::1', 'fd00::1', 'fc00::1', 'ff02::1',
      '::ffff:10.0.0.1', '::ffff:a00:1', '::ffff:7f00:1', '64:ff9b::a00:1', '::10.0.0.1', 'not-an-address', '',
      '2002:a00:1::1', '2002:7f00:1::', '2002:a9fe:a9fe::1', '2001:0:a00:1::1', '2001:0:4136:e378:8000:63bf:80ff:fffe'])
      expect({ a, np: isNonPublicAddress(a) }).toEqual({ a, np: true })
    for (const a of ['93.184.216.34', '8.8.8.8', '172.32.0.1', '172.15.0.1', '100.63.0.1', '100.128.0.1', '2606:2800:220:1:248:1893:25c8:1946',
      '::ffff:8.8.8.8', '64:ff9b::808:808', '2001:4860:4860::8888', '2002:5db8:d822::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2'])
      expect({ a, np: isNonPublicAddress(a) }).toEqual({ a, np: false })
  })
  it('v5: the v4-translated form, local-use NAT64 and site-local are refused; their public neighbours still pass', () => {
    for (const a of ['::ffff:0:a00:1', '::ffff:0:10.0.0.1', '::ffff:0:7f00:1', '::ffff:0:169.254.169.254', '0:0:0:0:ffff:0:c0a8:101',   // ::ffff:0:a.b.c.d (SIIT), judged by the embedded v4
      '64:ff9b:1::1', '64:ff9b:1:ffff:ffff:ffff:ffff:ffff', '64:ff9b:1::8.8.8.8',                                                 // 64:ff9b:1::/48
      'fec0::1', 'fec0:0:0:1::1', 'feff:ffff::1'])                                                                                // fec0::/10
      expect({ a, np: isNonPublicAddress(a) }).toEqual({ a, np: true })
    for (const a of ['::ffff:0:808:808', '::ffff:0:5db8:d822', '64:ff9b:2::1', '2606:4700::1111'])
      expect({ a, np: isNonPublicAddress(a) }).toEqual({ a, np: false })
  })
  it('a public-looking NAME that resolves to a private address is refused (the point of the finding)', async () => {
    expect(await ponderResolvedDenied('https://intranet-alias.example.com/', addr('10.1.2.3'))).toBe('resolves-to-non-public')
    expect(await ponderResolvedDenied('https://x.example.com/', addr('127.0.0.1'))).toBe('resolves-to-non-public')
    expect(await ponderResolvedDenied('https://x.example.com/', addr('::1'))).toBe('resolves-to-non-public')
    expect(await ponderResolvedDenied('https://x.example.com/', addr('::ffff:169.254.169.254'))).toBe('resolves-to-non-public')
  })
  it('ANY non-public address among several refuses the name', async () => {
    expect(await ponderResolvedDenied('https://x.example.com/', addr('93.184.216.34', '192.168.0.9'))).toBe('resolves-to-non-public')
    expect(await ponderResolvedDenied('https://x.example.com/', addr('93.184.216.34', '2606:2800:220:1::1'))).toBeNull()
  })
  it('fails closed: no answer, an empty answer, a resolver error and a timeout are all refusals', async () => {
    expect(await ponderResolvedDenied('https://x.example.com/', async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }) })).toBe('dns-unresolved')
    expect(await ponderResolvedDenied('https://x.example.com/', async () => [])).toBe('dns-unresolved')
    expect(await ponderResolvedDenied('https://x.example.com/', async () => { throw new Error('boom') })).toBe('dns-unresolved')
    expect(await ponderResolvedDenied('not a url', addr('93.184.216.34'))).toBe('unparseable')
  })
  it('a hung resolver is cut off at the timeout, not waited for', async () => {
    const t0 = Date.now()
    expect(await ponderResolvedDenied('https://x.example.com/', () => new Promise(() => {}))).toBe('dns-timeout')
    expect(Date.now() - t0).toBeLessThan(5000)
  })
  it('which URL gets resolved: only what the decision let through on its HOST, only for the tools that navigate', () => {
    const d = (tier: string, blocked = false) => ({ blocked, tier })
    expect(ponderJudgedUrl('WebFetch', { url: PUBLIC }, d('ponder-open'))).toBe(PUBLIC)
    expect(ponderJudgedUrl('WebFetch', { url: PUBLIC }, d('allowlist'))).toBe('')              // an allowlisted domain is not Ponder's grant
    expect(ponderJudgedUrl('WebFetch', { url: PUBLIC }, d('ponder-open', true))).toBe('')      // already refused
    expect(ponderJudgedUrl('mcp__playwright__browser_navigate', { url: PUBLIC }, d('ponder-browser'))).toBe(PUBLIC)
    expect(ponderJudgedUrl('mcp__playwright__browser_tabs', { action: 'new', url: PUBLIC }, d('ponder-browser'))).toBe(PUBLIC)
    expect(ponderJudgedUrl('mcp__playwright__browser_tabs', { action: 'list' }, d('ponder-browser'))).toBe('')
    expect(ponderJudgedUrl('mcp__playwright__browser_click', { url: PUBLIC }, d('ponder-browser'))).toBe('')
  })
})

// The script derives its root from its own location, so a copy under a temp dir has its own store/:
// nothing here can touch the real allowlist or the real logs.
describe('the hook process', () => {
  const made: string[] = []
  afterEach(() => { while (made.length) rmSync(made.pop() as string, { recursive: true, force: true }) })

  function install(allowlist?: unknown): string {
    const root = mkdtempSync(join(tmpdir(), 'ponder-gate-'))
    made.push(root)
    mkdirSync(join(root, 'scripts', 'hooks'), { recursive: true })
    mkdirSync(join(root, 'store'), { recursive: true })
    copyFileSync(SCRIPT, join(root, 'scripts', 'hooks', 'egress-gate.mjs'))
    if (allowlist !== undefined) writeFileSync(join(root, 'store', 'egress-allowlist.json'), typeof allowlist === 'string' ? allowlist : JSON.stringify(allowlist))
    return root
  }
  // The hook resolves names for Ponder. A test must not depend on the network, so a preload replaces the
  // resolver for the child process only: every name answers with a public address unless FAKE_DNS says
  // otherwise ("NX" = no such name). The hook code itself has no test switch.
  const fakeDns = (): string => {
    const f = join(mkdtempSync(join(tmpdir(), 'ponder-dns-')), 'fake-dns.cjs')
    made.push(dirname(f))
    writeFileSync(f, `const dns = require('node:dns'); const map = JSON.parse(process.env.FAKE_DNS || '{}')
dns.promises.lookup = async (h) => {
  const v = map[h] ?? '93.184.216.34'
  if (v === 'NX') throw Object.assign(new Error('ENOTFOUND ' + h), { code: 'ENOTFOUND' })
  return (Array.isArray(v) ? v : [v]).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))
}
`)
    return f
  }
  const run = (root: string, pl: unknown, fake: Record<string, string | string[]> = {}) => spawnSync(process.execPath, [join(root, 'scripts', 'hooks', 'egress-gate.mjs')], {
    input: typeof pl === 'string' ? pl : JSON.stringify(pl), encoding: 'utf-8',
    env: { ...process.env, EGRESS_GATE_SELFTEST: '', NODE_OPTIONS: `--require ${fakeDns()}`, FAKE_DNS: JSON.stringify(fake) },
  })
  const audit = (root: string) => {
    const f = join(root, 'store', 'ponder-egress.jsonl')
    return existsSync(f) ? readFileSync(f, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []
  }
  const denied = (r: { stdout: string }) => r.stdout.includes('"permissionDecision":"deny"')

  it('open + Ponder: allowed silently on stdout, one audit line with the full URL', () => {
    const root = install({ ponder_posture: 'open' })
    const r = run(root, payload({}, root))
    expect({ status: r.status, stdout: r.stdout }).toEqual({ status: 0, stdout: '' })
    expect(audit(root)).toHaveLength(1)
    expect(audit(root)[0]).toMatchObject({ decision: 'allow', tier: 'ponder-open', url: PUBLIC, host: 'www.e-cegjegyzek.hu', session: 'sess-1' })
  })

  it('open + Ponder + a refused URL: deny with the Ponder message, audit line AND the block log line', () => {
    const root = install({ ponder_posture: 'open' })
    const r = run(root, payload({ tool_input: { url: 'http://169.254.169.254/latest/' } }, root))
    expect(denied(r)).toBe(true)
    expect(r.stdout).toContain('Ponder-szint')
    expect(r.stdout).toContain('internal-host')
    expect(audit(root)[0]).toMatchObject({ decision: 'deny', reason: 'internal-host' })
    expect(readFileSync(join(root, 'store', 'egress-blocked.log'), 'utf-8')).toContain('reason="ponder: internal-host"')
  })

  it('CONTROL: another agent, the same URL, the same install: denied the old way, and NO Ponder audit', () => {
    const root = install({ ponder_posture: 'open' })
    const igor = join(root, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl')
    const r = run(root, payload({ transcript_path: igor }, root))
    expect(denied(r)).toBe(true)
    expect(r.stdout).toContain('quarantine-reader')           // the ORIGINAL block message, not the Ponder one
    expect(audit(root)).toEqual([])
  })

  it('only the literal "open" opens the switch', () => {
    for (const v of ['OPEN', 'Open', true, 1, ' open', 'denylist', null, {}, ['open']]) {
      const root = install({ ponder_posture: v })
      expect({ v, denied: denied(run(root, payload({}, root))) }).toEqual({ v, denied: true })
    }
    for (const content of [undefined, '{ not json', '[]', '"open"']) {
      const root = install(content as never)
      expect({ content, denied: denied(run(root, payload({}, root))) }).toEqual({ content, denied: true })
    }
    expect(denied(run(install({ ponder_posture: 'open' }), payload({}, '/nonexistent-root')))).toBe(true)   // identity of ANOTHER install
  })

  it('the switch is read live: flipping the file changes the next call, no restart', () => {
    const root = install({})
    expect(denied(run(root, payload({}, root)))).toBe(true)
    writeFileSync(join(root, 'store', 'egress-allowlist.json'), JSON.stringify({ ponder_posture: 'open' }))
    expect(denied(run(root, payload({}, root)))).toBe(false)
    writeFileSync(join(root, 'store', 'egress-allowlist.json'), JSON.stringify({ ponder_posture: 'closed' }))
    expect(denied(run(root, payload({}, root)))).toBe(true)
  })

  it('Playwright: Ponder is denied a write tool even with the switch closed; others pass; both audited only for Ponder', () => {
    const root = install({})
    const bp = (tool: string, tp?: string) => payload({ tool_name: `mcp__playwright__browser_${tool}`, tool_input: { url: PUBLIC, text: 'x' }, ...(tp ? { transcript_path: tp } : {}) }, root)
    expect(denied(run(root, bp('fill_form')))).toBe(true)
    expect(denied(run(root, bp('navigate')))).toBe(false)
    const igor = join(root, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl')
    expect(denied(run(root, bp('fill_form', igor)))).toBe(false)
    expect(audit(root).map((l: { tool: string }) => l.tool)).toEqual(['mcp__playwright__browser_fill_form', 'mcp__playwright__browser_navigate'])
  })

  it('Playwright process: the browser_tabs url is judged, and a tool outside the allowlist is denied (Sam findings 1 and 2)', () => {
    const root = install({})
    const bp = (tool: string, input: Record<string, unknown>) => payload({ tool_name: `mcp__playwright__browser_${tool}`, tool_input: input }, root)
    expect(denied(run(root, bp('tabs', { action: 'new', url: 'http://localhost:3420/' })))).toBe(true)
    expect(denied(run(root, bp('tabs', { action: 'new', url: PUBLIC })))).toBe(false)
    expect(denied(run(root, bp('tabs', { action: 'list' })))).toBe(false)
    const r = run(root, bp('press_sequentially', { text: 'x' }))
    expect(denied(r)).toBe(true)
    expect(r.stdout).toContain('browser-tool-not-allowed')
    expect(denied(run(root, bp('press_key', { key: 'Enter' })))).toBe(false)
    const k = run(root, bp('press_key', { key: 'a' }))
    expect(denied(k)).toBe(true)
    expect(k.stdout).toContain('browser-key-not-allowed')
    expect(audit(root).map((l: { decision: string }) => l.decision)).toEqual(['deny', 'allow', 'allow', 'deny', 'allow', 'deny'])
  })

  it('PONDERTYPECEG1008 process: typing opens after a navigate to the registry, and closes after a navigate elsewhere', () => {
    const root = install({})
    const bp = (tool: string, input: Record<string, unknown>) => payload({ tool_name: `mcp__playwright__browser_${tool}`, tool_input: input }, root)
    const type = bp('type', { element: 'search', ref: 'e1', text: 'HT Solar PV Betulia Kft.' })
    expect(denied(run(root, type))).toBe(true)                                              // no state yet
    expect(denied(run(root, bp('navigate', { url: 'https://www.e-cegjegyzek.hu/?cegkereses' })))).toBe(false)
    expect(denied(run(root, type))).toBe(false)
    expect(denied(run(root, bp('type', { element: 'search', ref: 'e1', text: 'x@evil.example' })))).toBe(true)
    expect(denied(run(root, bp('navigate', { url: 'https://example.org/' })))).toBe(false)
    expect(denied(run(root, type))).toBe(true)                                              // moved elsewhere
    expect(denied(run(root, bp('navigate', { url: 'https://www.e-cegjegyzek.hu/' })))).toBe(false)
    writeFileSync(join(root, 'store', '.ponder-browser-host.json'), JSON.stringify({ host: 'www.e-cegjegyzek.hu', ts: Date.now() - 31 * 60 * 1000 }))
    expect(denied(run(root, type))).toBe(true)                                              // stale state
    writeFileSync(join(root, 'store', '.ponder-browser-host.json'), 'not json')
    expect(denied(run(root, type))).toBe(true)                                              // broken state
    const igor = join(root, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl')
    expect(denied(run(root, payload({ tool_name: 'mcp__playwright__browser_navigate', tool_input: { url: 'https://www.e-cegjegyzek.hu/' }, transcript_path: igor }, root)))).toBe(false)
    expect(denied(run(root, type))).toBe(true)                                              // another agent's navigate records nothing
  })

  describe('the resolved address, end to end (the resolver is replaced for the child process only)', () => {
    it('WebFetch: a public-looking name that resolves to a private address is denied, audited, logged', () => {
      const root = install({ ponder_posture: 'open' })
      const r = run(root, payload({ tool_input: { url: 'https://alias.example.com/x', prompt: 'p' } }, root), { 'alias.example.com': '10.0.0.5' })
      expect(denied(r)).toBe(true)
      expect(r.stdout).toContain('resolves-to-non-public')
      expect(audit(root)[0]).toMatchObject({ decision: 'deny', reason: 'resolves-to-non-public', host: 'alias.example.com' })
      expect(readFileSync(join(root, 'store', 'egress-blocked.log'), 'utf-8')).toContain('reason="ponder: resolves-to-non-public"')
    })
    it('browser_navigate and browser_tabs new: the same, with the switch closed too (Playwright does not need it)', () => {
      const root = install({})
      const fake = { 'alias.example.com': ['93.184.216.34', '127.0.0.1'] }
      const bp = (tool: string, input: Record<string, unknown>) => payload({ tool_name: `mcp__playwright__browser_${tool}`, tool_input: input }, root)
      expect(denied(run(root, bp('navigate', { url: 'https://alias.example.com/' }), fake))).toBe(true)
      expect(denied(run(root, bp('tabs', { action: 'new', url: 'https://alias.example.com/' }), fake))).toBe(true)
      expect(denied(run(root, bp('navigate', { url: 'https://ok.example.com/' }), fake))).toBe(false)
    })
    it('fails closed: a name that does not resolve is denied', () => {
      const root = install({ ponder_posture: 'open' })
      const r = run(root, payload({ tool_input: { url: 'https://nonexistent.example.com/', prompt: 'p' } }, root), { 'nonexistent.example.com': 'NX' })
      expect(denied(r)).toBe(true)
      expect(r.stdout).toContain('dns-unresolved')
    })
    it('CONTROL: another agent is never resolved or audited, and Ponder with a closed switch is denied the old way, without a lookup', () => {
      const root = install({ ponder_posture: 'open' })
      const igor = join(root, 'agents', 'igor', '.claude-config', 'projects', '-x', 's.jsonl')
      const bp = (tp: string) => payload({ tool_name: 'mcp__playwright__browser_navigate', tool_input: { url: 'https://alias.example.com/' }, transcript_path: tp }, root)
      expect(denied(run(root, bp(igor), { 'alias.example.com': '10.0.0.5' }))).toBe(false)
      expect(audit(root)).toEqual([])
      const closed = install({})
      const r = run(closed, payload({ tool_input: { url: 'https://alias.example.com/', prompt: 'p' } }, closed), { 'alias.example.com': '10.0.0.5' })
      expect(r.stdout).toContain('quarantine-reader')
    })
  })

  it('garbage on stdin never blocks, and a tool that is not WebFetch / Playwright writes no audit', () => {
    const root = install({ ponder_posture: 'open' })
    expect(run(root, 'not json').stdout).toBe('')
    expect(run(root, payload({ tool_name: 'Bash', tool_input: { command: 'ls' } }, root)).stdout).toBe('')
    expect(audit(root)).toEqual([])
  })

  it('an unwritable audit location does not change the decision', () => {
    const root = install({ ponder_posture: 'open' })
    mkdirSync(join(root, 'store', 'ponder-egress.jsonl'))          // a directory where the audit FILE should be
    expect(denied(run(root, payload({}, root)))).toBe(false)
    expect(denied(run(root, payload({ tool_input: { url: 'http://localhost/' } }, root)))).toBe(true)
  })
})

describe('the allowlist loader reads the switch', () => {
  it('is closed with no store file (the test checkout has none)', () => {
    expect(loadRuntimeAllowlist().ponderPosture).toBe('closed')
  })
})

describe('wiring: the Playwright matcher, for sub-agents only', () => {
  const entries = (s: Record<string, unknown>) =>
    (((s.hooks as Record<string, unknown>)?.PreToolUse ?? []) as Array<Record<string, unknown>>)
      .filter((e) => JSON.stringify(e).includes('egress-gate.mjs'))

  it('injectEgressGate wires the WebFetch entry AND the Playwright entry, once each, however often it runs', () => {
    const s: Record<string, unknown> = {}
    injectEgressGate(s)
    injectEgressGate(s)
    expect(entries(s).map((e) => e.matcher).sort()).toEqual([PONDER_BROWSER_MATCHER, 'WebFetch'].sort())
    expect(PONDER_BROWSER_MATCHER).toBe('mcp__playwright__.*')
  })

  it('the matcher really matches the Playwright tool names and nothing else', () => {
    const re = new RegExp(`^(${PONDER_BROWSER_MATCHER})$`)
    expect(re.test('mcp__playwright__browser_navigate')).toBe(true)
    expect(re.test('mcp__playwright__browser_type')).toBe(true)
    expect(re.test('mcp__plugin_telegram_telegram__reply')).toBe(false)
    expect(re.test('WebFetch')).toBe(false)
  })

  it('the other gate injectors do not strip it', () => {
    const s: Record<string, unknown> = {}
    injectEgressGate(s)
    injectBashEgressParser(s)
    injectSelfPaceGate(s)
    expect(entries(s)).toHaveLength(2)
  })

  describe('the startup migration backfills an agent that has only the old WebFetch entry', () => {
    const PROBE = 'ponderwire-probe'
    const dir = join(PROJECT_ROOT, 'agents', PROBE)
    afterEach(() => rmSync(dir, { recursive: true, force: true }))

    it('adds the second entry once, then reports "already wired"', () => {
      if (existsSync(join(dir, 'HANDOFF.md'))) throw new Error(`refusing: agents/${PROBE} looks like a live agent`)
      rmSync(dir, { recursive: true, force: true })
      mkdirSync(join(dir, '.claude'), { recursive: true })
      const old: Record<string, unknown> = {}
      injectEgressGate(old)
      const hooks = old.hooks as { PreToolUse: Array<{ matcher?: string }> }
      hooks.PreToolUse = hooks.PreToolUse.filter((e) => e.matcher === 'WebFetch')          // the pre-change shape
      writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify(old))
      expect(ensureEgressGate(PROBE)).toBe(true)
      const after = JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf-8'))
      expect(entries(after).map((e) => e.matcher).sort()).toEqual([PONDER_BROWSER_MATCHER, 'WebFetch'].sort())
      expect(ensureEgressGate(PROBE)).toBe(false)
    })
  })
})

describe('the switch is reported when it is flipped', () => {
  it('the allowlist baseline watcher names the key and both values', () => {
    expect(describeAllowlistChange('{}', '{"ponder_posture":"open"}')).toBe('ponder_posture: (none) -> open')
    expect(describeAllowlistChange('{"ponder_posture":"open"}', '{"ponder_posture":"closed"}')).toBe('ponder_posture: open -> closed')
  })
})
