// PONDERTIER1003 v4: the destination filter for the research agent's browser.
//
// The hook (egress-gate.mjs) judges the URL a Playwright tool call is ASKED to open; nothing the page does
// afterwards. The proxy under test sits in the path of every request the browser makes. Three layers here:
//   1. the decision (judgeTarget) and the proxy as a server, with a replaced resolver and connector, so no
//      test depends on the network or touches a real address;
//   2. the launcher (ponder-playwright-mcp.mjs), run as a process against a fake server binary;
//   3. END TO END, with the real @playwright/mcp and a real Chromium, when both are installed: the nine
//      routes a page can use to reach an internal service, each with a POSITIVE CONTROL (the same route to a
//      public-looking name DOES reach the target), so a "no" is a measurement and not silence.
import { describe, it, expect, afterEach, afterAll } from 'vitest'
import { createHash } from 'node:crypto'
import dgram from 'node:dgram'
import http from 'node:http'
import net from 'node:net'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir, homedir, userInfo } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs script, no types
import { judgeTarget, createPonderProxy } from '../../scripts/ponder-browser-proxy.mjs'
// @ts-expect-error -- plain .mjs script, no types
import { refusedFlag, REFUSED_FLAGS, ALLOWED_FLAGS, childEnv, envAllowed, serverBin, browserConfig, BROWSER_ARGS, pinExecutablePath, browserRoot, resolveBrowserBinary, sha256File, PINNED_BROWSER_SHA256 } from '../../scripts/ponder-playwright-mcp.mjs'
// @ts-expect-error -- plain .mjs script, no types
import { browserSetupProblems } from '../../scripts/ponder-browser-check.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..', '..')
const LAUNCHER = join(ROOT, 'scripts', 'ponder-playwright-mcp.mjs')
const PUBLIC = '93.184.216.34'

type Addr = { address: string; family: number }
const answer = (...a: string[]): (() => Promise<Addr[]>) => async () => a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))

describe('judgeTarget: what the proxy refuses, and why', () => {
  it('lets a public name through and returns the address it resolved (the one to connect to)', async () => {
    expect(await judgeTarget('www.example.com', 443, answer(PUBLIC))).toEqual({ addr: PUBLIC })
    expect(await judgeTarget('WWW.Example.COM.', 80, answer(PUBLIC))).toEqual({ addr: PUBLIC })     // case and the trailing dot
    expect(await judgeTarget('v6.example.com', 443, answer('2606:2800:220:1:248:1893:25c8:1946'))).toMatchObject({ addr: '2606:2800:220:1:248:1893:25c8:1946' })
  })
  it('refuses every port but 80 and 443', async () => {
    for (const p of [0, 22, 25, 3420, 8080, 8443, 65535]) expect({ p, r: await judgeTarget('www.example.com', p, answer(PUBLIC)) }).toEqual({ p, r: { deny: 'port' } })
  })
  it('refuses IP literals in every spelling, and single-label names, without asking DNS', async () => {
    const never = async () => { throw new Error('the resolver must not be asked') }
    for (const h of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '2130706433', '0x7f.1', '0177.0.0.1', '127.1', '::1', '::ffff:10.0.0.1', 'fe80::1', '93.184.216.34'])
      expect({ h, r: await judgeTarget(h, 80, never) }).toEqual({ h, r: { deny: 'ip-literal' } })
    for (const h of ['localhost', 'LOCALHOST', 'localhost.', 'intranet', 'metadata'])
      expect({ h, r: await judgeTarget(h, 80, never) }).toEqual({ h, r: { deny: 'single-label-host' } })
    expect(await judgeTarget('', 80, never)).toEqual({ deny: 'no-host' })
  })
  it('refuses a public-looking NAME that resolves to ANY non-public address (the point of resolving here)', async () => {
    for (const a of ['127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
      '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1', '::ffff:a00:1', '64:ff9b::a00:1', '2002:a00:1::1', '2001:0:a00:1::1',
      '::ffff:0:a00:1', '64:ff9b:1::1', 'fec0::1'])                                                    // v5: SIIT, local-use NAT64, site-local
      expect({ a, r: await judgeTarget('alias.example.com', 443, answer(a)) }).toEqual({ a, r: { deny: 'resolves-to-non-public' } })
    expect(await judgeTarget('mixed.example.com', 443, answer(PUBLIC, '10.0.0.5'))).toEqual({ deny: 'resolves-to-non-public' })
    expect(await judgeTarget('mixed.example.com', 443, answer('192.168.0.9', PUBLIC))).toEqual({ deny: 'resolves-to-non-public' })
    expect(await judgeTarget('dashboard.localhost', 80, answer('127.0.0.1'))).toEqual({ deny: 'resolves-to-non-public' })
  })
  it('fails closed: no answer, an empty answer, an empty address, a resolver error', async () => {
    const nx = async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }) }
    expect(await judgeTarget('x.example.com', 80, nx)).toEqual({ deny: 'dns-unresolved' })
    expect(await judgeTarget('x.example.com', 80, async () => [])).toEqual({ deny: 'dns-unresolved' })
    expect(await judgeTarget('x.example.com', 80, async () => [{ address: '' }])).toEqual({ deny: 'dns-unresolved' })
    expect(await judgeTarget('x.example.com', 80, async () => { throw new Error('boom') })).toEqual({ deny: 'dns-unresolved' })
  })
  it('cuts a hung resolver off at the timeout', async () => {
    const t0 = Date.now()
    expect(await judgeTarget('x.example.com', 80, () => new Promise(() => {}))).toEqual({ deny: 'dns-timeout' })
    expect(Date.now() - t0).toBeLessThan(5000)
  })
})

// ---------------------------------------------------------------------------------------------------------
describe('the proxy as a server', () => {
  const open: Array<{ close: () => Promise<void> }> = []
  afterEach(async () => { while (open.length) await (open.pop() as { close: () => Promise<void> }).close() })

  async function upstreamHttp(): Promise<{ port: number; seen: string[]; close: () => Promise<void> }> {
    const seen: string[] = []
    const srv = http.createServer((q, s) => { seen.push(`${q.method} ${q.url} host=${q.headers.host} pc=${q.headers['proxy-connection'] ?? '-'}`); s.setHeader('x-up', '1'); s.end('UP-OK ' + q.url) })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const o = { port: (srv.address() as net.AddressInfo).port, seen, close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()) }) }
    open.push(o); return o
  }
  const viaProxy = (proxyPort: number, absoluteUrl: string, method = 'GET', body?: string) => new Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>((res, rej) => {
    const u = new URL(absoluteUrl)
    const q = http.request({ host: '127.0.0.1', port: proxyPort, method, path: absoluteUrl, headers: { host: u.host, 'proxy-connection': 'keep-alive' } }, (r) => { let d = ''; r.on('data', (c) => d += c); r.on('end', () => res({ status: r.statusCode ?? 0, body: d, headers: r.headers })) })
    q.on('error', rej); if (body) q.write(body); q.end()
  })

  it('forwards a public name to the address it RESOLVED, with the Host header of the name, without proxy headers', async () => {
    const up = await upstreamHttp()
    const calls: Array<[string, number]> = []
    const log: unknown[] = []
    const px = await createPonderProxy({ ports: new Set([up.port]), lookup: answer(PUBLIC), connect: (a: string, p: number) => { calls.push([a, p]); return net.connect({ host: '127.0.0.1', port: up.port }) }, log: (e: unknown) => log.push(e) })
    open.push(px)
    const r = await viaProxy(px.port, `http://site.example.com:${up.port}/page?q=1`)
    expect({ status: r.status, body: r.body, xup: r.headers['x-up'] }).toEqual({ status: 200, body: 'UP-OK /page?q=1', xup: '1' })
    expect(calls).toEqual([[PUBLIC, up.port]])                                  // connected to the resolved ADDRESS, not the name
    expect(up.seen).toEqual([`GET /page?q=1 host=site.example.com:${up.port} pc=-`])
    expect(px.stats).toEqual({ allowed: 1, denied: 0 })
    expect(log).toEqual([])
  })
  it('DNS rebinding between the check and the connection cannot happen: the answer that was checked is the one used', async () => {
    const up = await upstreamHttp()
    let n = 0
    const lookup = async () => (++n === 1 ? [{ address: PUBLIC, family: 4 }] : [{ address: '10.0.0.5', family: 4 }])   // a second lookup would say "private"
    const calls: string[] = []
    const px = await createPonderProxy({ ports: new Set([up.port]), lookup, connect: (a: string) => { calls.push(a); return net.connect({ host: '127.0.0.1', port: up.port }) } })
    open.push(px)
    expect((await viaProxy(px.port, `http://rebind.example.com:${up.port}/`)).status).toBe(200)
    expect({ lookups: n, connectedTo: calls }).toEqual({ lookups: 1, connectedTo: [PUBLIC] })
  })
  it('refuses a name that resolves to an internal address: 403, a logged reason, nothing connected', async () => {
    const calls: string[] = []; const log: Array<Record<string, unknown>> = []
    const px = await createPonderProxy({ ports: new Set([80, 3420]), lookup: answer('127.0.0.1'), connect: (a: string) => { calls.push(a); return net.connect({ host: '127.0.0.1', port: 9 }) }, log: (e: Record<string, unknown>) => log.push(e) })
    open.push(px)
    const r = await viaProxy(px.port, 'http://dashboard.example.com:3420/api/agents')
    expect({ status: r.status, body: r.body }).toEqual({ status: 403, body: 'ponder-proxy: refused (resolves-to-non-public)\n' })
    expect(calls).toEqual([])
    expect(log).toHaveLength(1)
    expect(log[0]).toMatchObject({ kind: 'HTTP', host: 'dashboard.example.com', port: 3420, reason: 'resolves-to-non-public' })
    expect(px.stats).toEqual({ allowed: 0, denied: 1 })
  })
  it('the install\'s own dashboard is refused by name, by literal and by port', async () => {
    const px = await createPonderProxy({ lookup: answer(PUBLIC), connect: () => net.connect({ host: '127.0.0.1', port: 9 }), log: () => {} })
    open.push(px)
    for (const [url, reason] of [['http://localhost:3420/', 'port'], ['http://localhost/', 'single-label-host'], ['http://127.0.0.1:3420/', 'port'], ['http://127.0.0.1/', 'ip-literal'],
      ['http://[::1]/', 'ip-literal'], ['http://dashboard.example.com:3420/', 'port'], ['http://localhost.:80/', 'single-label-host']]) {
      const r = await viaProxy(px.port, url)
      expect({ url, status: r.status, body: r.body }).toEqual({ url, status: 403, body: `ponder-proxy: refused (${reason})\n` })
    }
  })
  it('a log that throws never changes the decision', async () => {
    const px = await createPonderProxy({ lookup: answer('10.0.0.1'), connect: () => net.connect({ host: '127.0.0.1', port: 9 }), log: () => { throw new Error('disk full') } })
    open.push(px)
    expect((await viaProxy(px.port, 'http://x.example.com/')).status).toBe(403)
  })
  it('refuses a scheme other than http on the plain path, and a request that is not an absolute URL', async () => {
    const px = await createPonderProxy({ lookup: answer(PUBLIC), connect: () => net.connect({ host: '127.0.0.1', port: 9 }), log: () => {} })
    open.push(px)
    const raw = (line: string) => new Promise<string>((res) => { const s = net.connect(px.port, '127.0.0.1', () => s.write(`${line}\r\nhost: x\r\n\r\n`)); let d = ''; s.on('data', (c) => d += c); s.on('close', () => res(d)); setTimeout(() => s.destroy(), 1500) })
    expect(await raw('GET /relative HTTP/1.1')).toContain('400')
    expect(await raw('GET ftp://x.example.com/ HTTP/1.1')).toContain('403')
  })

  describe('CONNECT (every https request, and websockets)', () => {
    const connectVia = (proxyPort: number, target: string, extra = '') => new Promise<{ head: string; tunnel: string }>((res) => {
      const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n\r\n`))
      let all = ''
      s.on('data', (c) => { all += c })
      if (extra) setTimeout(() => s.write(extra), 150)
      setTimeout(() => s.destroy(), 900)
      s.on('close', () => { const i = all.indexOf('\r\n\r\n'); res({ head: i < 0 ? all : all.slice(0, i), tunnel: i < 0 ? '' : all.slice(i + 4) }) })
    })
    it('tunnels to the resolved address when the name is public', async () => {
      const echo = net.createServer((c) => c.on('data', (d) => c.write('ECHO:' + d)))
      await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r))
      open.push({ close: () => new Promise<void>((r) => { echo.close(() => r()) }) })
      const ep = (echo.address() as net.AddressInfo).port
      const calls: Array<[string, number]> = []
      const px = await createPonderProxy({ ports: new Set([443]), lookup: answer(PUBLIC), connect: (a: string, p: number) => { calls.push([a, p]); return net.connect({ host: '127.0.0.1', port: ep }) } })
      open.push(px)
      const r = await connectVia(px.port, 'secure.example.com:443', 'hello')
      expect(r.head).toMatch(/^HTTP\/1\.1 200 Connection Established/)
      expect(r.tunnel).toBe('ECHO:hello')
      expect(calls).toEqual([[PUBLIC, 443]])
      expect(px.stats.allowed).toBe(1)
    })
    it('refuses an internal name, an IP literal (v4 and bracketed v6), a bad port and a malformed target, all without connecting', async () => {
      const calls: string[] = []; const log: Array<Record<string, unknown>> = []
      const px = await createPonderProxy({ lookup: async (h: string) => [{ address: h.startsWith('intranet') ? '10.1.1.1' : PUBLIC, family: 4 }], connect: (a: string) => { calls.push(a); return net.connect({ host: '127.0.0.1', port: 9 }) }, log: (e: Record<string, unknown>) => log.push(e) })
      open.push(px)
      for (const [target, reason] of [['intranet.example.com:443', 'resolves-to-non-public'], ['10.0.0.1:443', 'ip-literal'], ['[::1]:443', 'ip-literal'], ['localhost:443', 'single-label-host'],
        ['www.example.com:22', 'port'], ['www.example.com:3420', 'port']]) {
        const r = await connectVia(px.port, target)
        expect({ target, line: r.head.split('\r\n')[0] }).toEqual({ target, line: 'HTTP/1.1 403 Forbidden' })
        expect(r.tunnel).toContain(`(${reason})`)
      }
      expect((await connectVia(px.port, 'no-port-here')).head).toContain('400')
      expect(calls).toEqual([])
      expect(log.map((e) => e.reason)).toEqual(['resolves-to-non-public', 'ip-literal', 'ip-literal', 'single-label-host', 'port', 'port'])
    })
  })

  it('only a client on the loopback interface is served', async () => {
    const px = await createPonderProxy({ lookup: answer(PUBLIC), connect: () => net.connect({ host: '127.0.0.1', port: 9 }), log: () => {} })
    open.push(px)
    const r = await new Promise<string>((res) => {
      const s = net.connect({ port: px.port, host: '127.0.0.1', localAddress: '127.0.0.2' }, () => s.write('GET http://x.example.com/ HTTP/1.1\r\nhost: x.example.com\r\n\r\n'))
      let d = ''; s.on('data', (c) => d += c); s.on('close', () => res(d)); s.on('error', () => res('ERR')); setTimeout(() => { s.destroy(); res(d || 'TIMEOUT') }, 1500)
    })
    expect(r === '' || r === 'ERR' || r === 'TIMEOUT').toBe(true)               // dropped, never answered with a page or a 403
    expect(px.stats).toEqual({ allowed: 0, denied: 0 })
  })
})

// ---------------------------------------------------------------------------------------------------------
describe('the launcher', () => {
  const dirs: string[] = []
  afterEach(() => { while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true }) })

  // v5.2 (PONDERBINPIN1004): --executable-path is pinned to the Playwright-installed browser binaries. The unit
  // cases use a fixture root with the same layout and an injected root (the seam: opts.root), because the real
  // cache is the one place a test must not write to. The hash pin is real: the fixture "binaries" are the pinned
  // bytes (opts.pinned holds THEIR sha256), the "wrapper" is a shell script with the right name, and the "dropped
  // ELF" starts with the ELF magic bytes at the right name but is not the pinned file (v5.3: that passed the old
  // name+ELF pin, and is what `curl -o` / `wget -O` into the cache produces).
  const ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0])
  const ELF_SHA = createHash('sha256').update(ELF).digest('hex')
  const DROPPED_ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0x41])
  function fixture() {
    const root = mkdtempSync(join(tmpdir(), 'ponder-cache-')); dirs.push(root)
    const mk = (rel: string, body: Buffer | string = ELF) => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body, { mode: 0o755 }); return p }
    const headless = mk('chromium_headless_shell-1228/chrome-headless-shell-linux64/chrome-headless-shell')
    const chromium = mk('chromium-1228/chrome-linux64/chrome')
    return { root, headless, chromium, mk, opts: { root, pinned: new Set([ELF_SHA]) } }
  }

  it('v5.2: only the Playwright-installed browser binaries are accepted as --executable-path', () => {
    const f = fixture()
    for (const ok of [f.headless, f.chromium]) expect({ ok, r: refusedFlag(['--executable-path', ok], f.opts) }).toEqual({ ok, r: null })
    expect(refusedFlag([`--executable-path=${f.chromium}`], f.opts)).toBeNull()
    // the owner's measured bypass: a wrapper script that ignores --proxy-server, at the right name, under the root
    const wrapperScript = f.mk('chromium-1229/chrome-linux64/chrome', '#!/bin/sh\nexec /usr/bin/true "$@"\n')
    // every shape that is NOT one of the two binaries
    const outside = join(mkdtempSync(join(tmpdir(), 'ponder-out-')), 'chrome'); dirs.push(dirname(outside)); writeFileSync(outside, ELF, { mode: 0o755 })
    const linkOut = join(f.root, 'chromium-1230'); mkdirSync(linkOut, { recursive: true }); symlinkSync(dirname(outside), join(linkOut, 'chrome-linux64'))
    for (const bad of [
      wrapperScript,                                                               // a script, not the pinned binary
      f.mk('chromium-1231/chrome-linux64/chrome', DROPPED_ELF),                    // v5.3: ELF magic, right name, right place, wrong hash
      f.mk('chromium_headless_shell-1231/chrome-headless-shell-linux64/chrome-headless-shell', DROPPED_ELF),
      outside,                                                                     // an ELF, outside the root
      join(linkOut, 'chrome-linux64', 'chrome'),                                   // inside by name, outside by realpath
      f.mk('chromium-1228/chrome-linux64/wrapper.sh'),                             // under the root, wrong file name
      f.mk('chromium-1228/chrome-linux64/chrome.real'),
      f.mk('chromium-x/chrome-linux64/chrome'),                                    // version is digits only
      f.mk('other-1228/chrome-linux64/chrome'),
      f.mk('chrome'),                                                              // right name, no versioned directory
      f.mk('chromium-1228/nested/chrome-linux64/chrome'),
      f.root + '/chromium-1228/chrome-linux64/../chrome-linux64/chrome',            // a ".." component (path.join would fold it away, so it is spelled out)
      join(f.root, 'chromium-4242', 'chrome-linux64', 'chrome'),                   // does not exist
      '/bin/sh', '/usr/bin/chromium', '/usr/bin/env',
    ]) expect({ bad, refused: refusedFlag(['--executable-path', bad], f.opts) !== null }).toEqual({ bad, refused: true })
    // a symlink OUTSIDE that points INTO the root resolves to a pinned binary: accepted, and launch() passes the resolved path on
    const viaLink = join(dirname(outside), 'link-to-headless'); symlinkSync(f.headless, viaLink)
    expect(refusedFlag(['--executable-path', viaLink], f.opts)).toBeNull()
    expect(pinExecutablePath(['--headless', '--executable-path', viaLink], f.opts)).toEqual(['--headless', '--executable-path', realpathSync(f.headless)])
    expect(pinExecutablePath([`--executable-path=${viaLink}`], f.opts)).toEqual([`--executable-path=${realpathSync(f.headless)}`])
  })
  it('v5.3: the real pinned hashes are what is in the launcher, the real cache binaries match them, and a one-byte change does not', () => {
    expect([...PINNED_BROWSER_SHA256].every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true)
    expect(PINNED_BROWSER_SHA256.size).toBe(2)
    if (!CHROMIUM) return
    expect(resolveBrowserBinary(CHROMIUM as string)).toBe(realpathSync(CHROMIUM as string))
    const f = fixture()
    const flipped = f.mk('chromium-1232/chrome-linux64/chrome', Buffer.concat([ELF, Buffer.from([1])]))
    expect(resolveBrowserBinary(flipped, f.opts)).toBeNull()
    expect(resolveBrowserBinary(f.chromium, f.opts)).toBe(realpathSync(f.chromium))
    expect(sha256File(f.chromium)).toBe(ELF_SHA)
    expect(sha256File(join(f.root, 'nope'))).toBeNull()
    expect(resolveBrowserBinary(f.chromium, { ...f.opts, digest: () => null })).toBeNull()             // unreadable = refused
  })
  it('v5.2: the pin root comes from the passwd entry, not from $HOME or PLAYWRIGHT_BROWSERS_PATH', () => {
    const before = { HOME: process.env.HOME, PBP: process.env.PLAYWRIGHT_BROWSERS_PATH }
    const f = fixture()
    try {
      process.env.HOME = f.root
      process.env.PLAYWRIGHT_BROWSERS_PATH = f.root
      expect(browserRoot()).toBe(join(userInfo().homedir, '.cache', 'ms-playwright'))
      expect(refusedFlag(['--executable-path', f.chromium])).toBe('--executable-path')     // no injected root: the real one applies
    } finally {
      if (before.HOME === undefined) delete process.env.HOME; else process.env.HOME = before.HOME
      if (before.PBP === undefined) delete process.env.PLAYWRIGHT_BROWSERS_PATH; else process.env.PLAYWRIGHT_BROWSERS_PATH = before.PBP
    }
  })
  it('v5.2: the launcher PROCESS refuses a wrapper script as the browser (exit 2), and starts with a real browser through a link (the server gets the resolved path)', () => {
    const d = mkdtempSync(join(tmpdir(), 'ponder-pin-')); dirs.push(d)
    const wrapperScript = join(d, 'chrome'); writeFileSync(wrapperScript, '#!/bin/sh\nexit 0\n', { mode: 0o755 })
    const r = spawnSync(process.execPath, [wrapper(fakeServer(0)), '--headless', '--executable-path', wrapperScript], { encoding: 'utf-8', timeout: 20000, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' } })
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('--executable-path is refused')
    if (!CHROMIUM) return                                                           // no browser installed here: the refusal above stands
    const link = join(d, 'browser-link'); symlinkSync(CHROMIUM as string, link)
    const ok = run(fakeServer(0), ['--headless', '--executable-path', link], {})
    expect(ok.status).toBe(0)
    const args: string[] = lastJson(ok.stdout).args
    expect(args[args.indexOf('--executable-path') + 1]).toBe(realpathSync(CHROMIUM as string))
  })

  it('refuses every flag that would route the browser around the proxy, in both spellings', () => {
    expect(REFUSED_FLAGS).toEqual(['--proxy-server', '--proxy-bypass', '--cdp-endpoint', '--extension', '--config', '--allow-unrestricted-file-access'])
    for (const f of REFUSED_FLAGS) {
      expect({ f, r: refusedFlag(['--headless', f, 'x']) }).toEqual({ f, r: f })
      expect({ f, r: refusedFlag(['--headless', `${f}=x`]) }).toEqual({ f, r: f })
    }
    const f = fixture()
    expect(refusedFlag(['--headless', '--browser', 'chromium', '--executable-path', f.chromium, '--isolated'], f.opts)).toBeNull()
  })

  // v5.1: the flags are an ALLOWLIST. A refusal list is one that a version bump makes incomplete.
  const PONDER_ARGS_FOR = (exe: string) => ['--headless', '--browser', 'chromium', '--executable-path', exe, '--output-dir', '/home/u/agents_munka/ponder/playwright']
  it('v5.1: the allowlist is exactly the flags the research agent\'s setup needs', () => {
    expect(Object.keys(ALLOWED_FLAGS)).toEqual(['--headless', '--isolated', '--browser', '--executable-path', '--output-dir', '--viewport-size'])
  })
  it('v5.1: the research agent\'s real arguments pass, in both spellings', () => {
    const f = fixture()
    const PONDER_ARGS = PONDER_ARGS_FOR(f.headless)
    expect(refusedFlag(PONDER_ARGS, f.opts)).toBeNull()
    expect(refusedFlag([...PONDER_ARGS, '--isolated', '--viewport-size', '1280x720'], f.opts)).toBeNull()
    expect(refusedFlag(['--headless', '--browser=chromium', `--executable-path=${f.chromium}`, '--output-dir=/x/out', '--viewport-size=1280x720'], f.opts)).toBeNull()
    expect(refusedFlag([])).toBeNull()
  })
  it('v5.1: every flag outside the allowlist is refused, with a value and in the --flag=value spelling', () => {
    // the seven the owner named, and the rest of the server's options
    for (const f of ['--endpoint', '--init-page', '--init-script', '--user-data-dir', '--storage-state', '--secrets', '--grant-permissions',
      '--caps', '--port', '--host', '--allowed-hosts', '--allowed-origins', '--blocked-origins', '--device', '--mobile', '--user-agent', '--codegen',
      '--no-sandbox', '--sandbox', '--ignore-https-errors', '--save-session', '--shared-browser-context', '--cdp-header', '--cdp-timeout',
      '--profile-dir-name', '--snapshot-mode', '--image-responses', '--file-paths', '--block-service-workers', '--no-webmcp', '--idle-timeout',
      '--timeout-action', '--timeout-navigation', '--timeout-settle', '--test-id-attribute', '--snapshot-boxes', '--console-level', '--output-max-size',
      '--some-flag-a-later-version-adds', '--constructor', '--__proto__', '--toString'])
      for (const args of [['--headless', f, 'x'], ['--headless', `${f}=x`], ['--headless', f]])
        expect({ f, args, r: refusedFlag(args) }).toEqual({ f, args, r: f })
  })
  it('v5.1: a value is judged, not just the flag', () => {
    for (const bad of [
      ['--browser', 'chrome'], ['--browser', 'msedge'], ['--browser', 'firefox'], ['--browser', 'webkit'], ['--browser=chromium-x'], ['--browser'],
      ['--executable-path', 'chrome'], ['--executable-path', './chrome'], ['--executable-path', '/x/../etc/x'], ['--executable-path', ''], ['--executable-path'],
      ['--output-dir', 'out'], ['--output-dir', '/x/../y'], ['--output-dir', '--config'], ['--output-dir', '-x'],
      ['--viewport-size', '1280,720'], ['--viewport-size', '1280x720; x'], ['--viewport-size', 'x'], ['--viewport-size', '1x1'],
      ['--headless=false'], ['--isolated=1'],
    ]) expect({ bad, refused: refusedFlag(bad) !== null }).toEqual({ bad, refused: true })
    // the name that comes back is the flag (or the stray word), so the message can say what to remove
    expect(refusedFlag(['--browser', 'chrome'])).toBe('--browser')
    expect(refusedFlag(['--output-dir', '--config'])).toBe('--output-dir')
  })
  it('v5.1: stray words and short flags are refused (they would be a value of nothing, or a flag we have not read)', () => {
    for (const a of ['chromium', '-b', '-h', '-', 'http://x/', '/x/chrome']) expect({ a, r: refusedFlag(['--headless', a]) }).toEqual({ a, r: a })
    expect(refusedFlag(['--headless', '--browser', 'chromium', 'extra'])).toBe('extra')
  })
  it('v5.1 against the INSTALLED server: every option its --help lists is refused unless it is on the allowlist (a drift detector)', () => {
    if (!MCP) return                                                              // no server installed here: the unit cases above stand
    const help = spawnSync(MCP, ['--help'], { encoding: 'utf-8', timeout: 20000 }).stdout
    const listed = [...new Set([...help.matchAll(/^\s+(?:-\w, )?(--[a-z][a-z0-9-]*)/gm)].map((m) => m[1]))].filter((f) => f !== '--help')
    expect(listed.length).toBeGreaterThan(30)                                      // the parse found the options (a zero here would be a blind instrument)
    for (const f of Object.keys(ALLOWED_FLAGS)) expect(listed).toContain(f)         // and every allowed flag really exists in this version
    for (const f of listed.filter((x) => !(x in ALLOWED_FLAGS)))
      expect({ f, r: refusedFlag(['--headless', f, 'x']) }).toEqual({ f, r: f })
  })

  // The launcher takes its server binary from the environment of NOTHING (v5): a test reaches the process
  // through a one-line wrapper that calls launch() with a fake bin, which is the seam the command line lacks.
  function wrapper(bin: string): string {
    const d = mkdtempSync(join(tmpdir(), 'ponder-wrap-')); dirs.push(d)
    const w = join(d, 'wrap.mjs')
    writeFileSync(w, `import { launch } from ${JSON.stringify(LAUNCHER)}\nawait launch(process.argv.slice(2), { bin: ${JSON.stringify(bin)} })\n`)
    return w
  }
  function fakeServer(exitCode = 0): string {
    const d = mkdtempSync(join(tmpdir(), 'ponder-launch-')); dirs.push(d)
    const bin = join(d, 'fake-mcp.mjs')
    // prints its argv, its environment (names and the values of the few that matter), the content of the
    // --config file it was given, asks its own proxy for localhost, then exits
    writeFileSync(bin, `#!/usr/bin/env node
import net from 'node:net'
import { readFileSync } from 'node:fs'
const args = process.argv.slice(2)
const i = args.indexOf('--proxy-server')
const port = i >= 0 ? Number(new URL(args[i + 1]).port) : 0
const c = args.indexOf('--config')
let config = null
try { config = JSON.parse(readFileSync(args[c + 1], 'utf-8')) } catch { /* no config */ }
const s = net.connect(port, '127.0.0.1', () => s.write('GET http://localhost/ HTTP/1.1\\r\\nhost: localhost\\r\\n\\r\\n'))
let d = ''
s.on('data', (x) => { d += x })
s.on('close', () => { console.log(JSON.stringify({ args, port, config, envNames: Object.keys(process.env).sort(), answer: d.split('\\r\\n')[0] })); process.exit(${exitCode}) })
s.on('error', () => { console.log(JSON.stringify({ args, port, error: true })); process.exit(9) })
`, { mode: 0o755 })
    return bin
  }
  const run = (bin: string, args: string[], env: Record<string, string>) =>
    spawnSync(process.execPath, [wrapper(bin), ...args], { encoding: 'utf-8', timeout: 20000, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env } })
  const lastJson = (stdout: string) => JSON.parse(stdout.trim().split('\n').pop() as string)

  it('runs the server with --proxy-server on a live proxy that judges, and passes the exit code', () => {
    const r = run(fakeServer(3), ['--headless', '--browser', 'chromium'], {})
    expect(r.status).toBe(3)
    const out = lastJson(r.stdout)
    expect(out.args.slice(0, 3)).toEqual(['--headless', '--browser', 'chromium'])
    expect(out.args.slice(-2)).toEqual(['--proxy-server', `http://127.0.0.1:${out.port}`])
    expect(out.port).toBeGreaterThan(0)
    expect(out.answer).toBe('HTTP/1.1 403 Forbidden')                          // the proxy was live and judged `localhost`
  })
  it('v5 item 2: the server gets an ALLOWLIST of the environment, not the whole of it', () => {
    const hostile: Record<string, string> = {
      PLAYWRIGHT_MCP_CDP_ENDPOINT: 'http://127.0.0.1:9222', PLAYWRIGHT_MCP_PROXY_BYPASS: '*', PLAYWRIGHT_MCP_PROXY_SERVER: 'http://evil:3128',
      PLAYWRIGHT_MCP_CONFIG: '/x/c.json', PLAYWRIGHT_MCP_EXTENSION: '1', PLAYWRIGHT_MCP_ALLOW_UNRESTRICTED_FILE_ACCESS: '1',
      PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK: '1', PONDER_PLAYWRIGHT_MCP_BIN: '/x/evil', NODE_OPTIONS: '--max-old-space-size=256',
      HTTP_PROXY: 'http://evil:3128', HTTPS_PROXY: 'http://evil:3128', ALL_PROXY: 'socks5://evil:1080', NO_PROXY: '*', LD_PRELOAD: '',
      CLAUDE_CODE_OAUTH_TOKEN: 'secret', ANTHROPIC_API_KEY: 'secret',
    }
    const r = run(fakeServer(), ['--headless'], { ...hostile, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC', PLAYWRIGHT_BROWSERS_PATH: '/x/browsers' })
    expect(r.status).toBe(0)
    const names: string[] = lastJson(r.stdout).envNames
    expect(names.filter((n) => n in hostile)).toEqual([])                       // none of them reached the server
    for (const n of ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'PLAYWRIGHT_BROWSERS_PATH']) expect(names).toContain(n)   // what the browser needs did
    expect(names.filter((n) => !envAllowed(n))).toEqual([])                     // and nothing outside the list (node adds nothing of its own)
  })
  it('childEnv: exactly the allowed names, LC_* by prefix (not the bare prefix), strings only', () => {
    expect(childEnv({ PATH: '/b', LC_CTYPE: 'x', LC_: 'y', LCX: 'z', NODE_OPTIONS: 'o', PLAYWRIGHT_MCP_CONFIG: 'c', HTTPS_PROXY: 'p', HOME: '/h' })).toEqual({ PATH: '/b', LC_CTYPE: 'x', HOME: '/h' })
    expect(childEnv({})).toEqual({})
    for (const n of ['NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'PONDER_PLAYWRIGHT_MCP_BIN', 'PLAYWRIGHT_MCP_CDP_ENDPOINT', 'PLAYWRIGHT_MCP_PROXY_BYPASS', 'HTTP_PROXY', 'https_proxy', 'ALL_PROXY', 'NO_PROXY', 'CHROMIUM_FLAGS', 'DISPLAY'])
      expect({ n, ok: envAllowed(n) }).toEqual({ n, ok: false })
  })
  it('v5 item 1: the browser gets --webrtc-ip-handling-policy=disable_non_proxied_udp, through a config file of the launcher\'s own', () => {
    // NOT --force-webrtc-ip-handling-policy: measured against a real Chromium, that spelling changes nothing.
    expect(BROWSER_ARGS).toEqual(['--webrtc-ip-handling-policy=disable_non_proxied_udp'])
    expect(browserConfig()).toEqual({ browser: { launchOptions: { args: ['--webrtc-ip-handling-policy=disable_non_proxied_udp'] } } })
    const out = lastJson(run(fakeServer(), ['--headless', '--browser', 'chromium'], {}).stdout)
    expect(out.config).toEqual(browserConfig())                                  // the server was handed a readable config with the switch in it
    const i = out.args.indexOf('--config')
    expect(i).toBeGreaterThan(2)                                                 // after the agent's own arguments
    expect(out.args.filter((a: string) => a === '--config')).toHaveLength(1)
  })
  it('the config file does not outlive the launcher', () => {
    const before = readdirSync(tmpdir()).filter((x) => x.startsWith('ponder-mcp-')).length
    run(fakeServer(), ['--headless'], {})
    expect(readdirSync(tmpdir()).filter((x) => x.startsWith('ponder-mcp-')).length).toBeLessThanOrEqual(before)
  })
  it('v5 item 3: the server binary is the one next to node; the environment cannot name another', () => {
    expect(serverBin('/n/bin/node', (p: string) => p === '/n/bin/playwright-mcp')).toBe('/n/bin/playwright-mcp')
    expect(serverBin('/n/bin/node', () => false)).toBeNull()
    process.env.PONDER_PLAYWRIGHT_MCP_BIN = '/x/evil'
    try {
      expect(serverBin('/n/bin/node', (p: string) => p === '/n/bin/playwright-mcp')).toBe('/n/bin/playwright-mcp')   // the variable changes nothing
      expect(serverBin('/n/bin/node', (p: string) => p === '/x/evil')).toBeNull()                                    // and is not consulted
    } finally { delete process.env.PONDER_PLAYWRIGHT_MCP_BIN }
    // no code path reads it any more (comments excepted)
    const code = readFileSync(LAUNCHER, 'utf-8').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    expect(code).not.toContain('PONDER_PLAYWRIGHT_MCP_BIN')
  })
  it('exits 2, without starting anything, on a refused flag', () => {
    const bin = fakeServer()
    for (const f of [['--proxy-server=http://x:1'], ['--cdp-endpoint', 'http://localhost:9222'], ['--proxy-bypass', '<-loopback>'], ['--config=/x/c.json'],
      ['--endpoint', 'ws://127.0.0.1:1/x'], ['--init-page', '/x/p.ts'], ['--init-script=/x/s.js'], ['--user-data-dir', '/x/u'], ['--storage-state', '/x/s.json'], ['--secrets', '/x/s'],
      ['--grant-permissions', 'geolocation'], ['--browser', 'msedge'], ['--no-sandbox']]) {
      const r = run(bin, ['--headless', ...f], {})
      expect({ f, status: r.status, stdout: r.stdout }).toEqual({ f, status: 2, stdout: '' })
      expect(r.stderr).toContain('is refused')
    }
  })
  it('exits 127 when the server binary cannot be started', () => {
    const r = run('/nonexistent/playwright-mcp', ['--headless'], {})
    expect(r.status).toBe(127)
    expect(r.stderr).toContain('cannot start')
  })
})

// ---------------------------------------------------------------------------------------------------------
describe('the Ponder browser setup check (reads the agent\'s .mcp.json)', () => {
  const R = '/inst'
  // v5.2: the check pins --executable-path like the launcher does; the fixture is a root with one ELF browser in it
  const pinFix = (() => { const root = mkdtempSync(join(tmpdir(), 'ponder-cache-chk-')); const exe = join(root, 'chromium-1228', 'chrome-linux64', 'chrome'); const body = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]); mkdirSync(dirname(exe), { recursive: true }); writeFileSync(exe, body, { mode: 0o755 }); return { root, exe, opts: { root, pinned: new Set([createHash('sha256').update(body).digest('hex')]) } } })()
  afterAll(() => rmSync(pinFix.root, { recursive: true, force: true }))
  const problems = (m: unknown, root: string) => browserSetupProblems(m, root, pinFix.opts)
  const good = { mcpServers: { playwright: { command: 'node', args: [`${R}/scripts/ponder-playwright-mcp.mjs`, '--headless', '--browser', 'chromium', '--executable-path', pinFix.exe] } } }
  const withArgs = (extra: string[]) => ({ mcpServers: { playwright: { ...good.mcpServers.playwright, args: [...good.mcpServers.playwright.args, ...extra] } } })
  it('passes the setup the tier assumes', () => {
    expect(problems(good, R)).toEqual([])
    expect(problems({ mcpServers: { ...good.mcpServers, files: { command: 'node', args: ['/x/fs-mcp.js'] } } }, R)).toEqual([])
  })
  it('v5.2: fails a .mcp.json whose --executable-path is not one of the installed browsers (the owner\'s measured wrapper-script bypass)', () => {
    const script = join(pinFix.root, 'chromium-1229', 'chrome-linux64', 'chrome')
    mkdirSync(dirname(script), { recursive: true }); writeFileSync(script, '#!/bin/sh\nexec /usr/bin/true "$@"\n', { mode: 0o755 })
    const withExe = (exe: string) => ({ mcpServers: { playwright: { command: 'node', args: [`${R}/scripts/ponder-playwright-mcp.mjs`, '--headless', '--browser', 'chromium', '--executable-path', exe] } } })
    expect(problems(withExe(pinFix.exe), R)).toEqual([])
    for (const bad of [script, '/tmp/wrapper.sh', '/usr/bin/chromium', '/bin/sh', join(pinFix.root, 'chromium-4242', 'chrome-linux64', 'chrome')])
      expect({ bad, p: problems(withExe(bad), R).join(' ').includes('--executable-path') }).toEqual({ bad, p: true })
  })
  it('fails the plain server, a wrong key, a wrong launcher path and a refused flag', () => {
    const plain = { mcpServers: { playwright: { command: '/x/bin/playwright-mcp', args: ['--headless'] } } }
    expect(problems(plain, R).join(' ')).toContain('does not run the launcher')
    expect(problems({ mcpServers: { pw: good.mcpServers.playwright } }, R).join(' ')).toContain('exactly "playwright"')
    expect(problems({ mcpServers: { playwright: { command: 'node', args: ['/elsewhere/ponder-playwright-mcp.mjs'] } } }, R).join(' ')).toContain('does not run the launcher')
    expect(problems(withArgs(['--proxy-bypass', '<-loopback>']), R).join(' ')).toContain('--proxy-bypass')
    expect(problems(withArgs(['--cdp-endpoint=http://localhost:9222']), R).join(' ')).toContain('--cdp-endpoint')
    expect(problems({ mcpServers: { playwright: { ...good.mcpServers.playwright, env: { PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK: '1' } } } }, R).join(' ')).toContain('PLAYWRIGHT_DISABLE_FORCED')
  })
  it('v5.1: fails any flag outside the allowlist, a bad value, and an --output-dir outside the research agent\'s own area', () => {
    for (const extra of [['--endpoint', 'ws://127.0.0.1:1/x'], ['--init-page', '/x/p.ts'], ['--init-script=/x/s.js'], ['--user-data-dir', '/x/u'], ['--storage-state', '/x/s.json'],
      ['--secrets', '/x/s'], ['--grant-permissions', 'geolocation'], ['--no-sandbox'], ['--browser', 'msedge'], ['stray']])
      expect({ extra, p: problems(withArgs(extra), R).length > 0 }).toEqual({ extra, p: true })
    expect(problems(withArgs(['--endpoint', 'x']), R).join(' ')).toContain('--endpoint')
    const own = join(homedir(), 'agents_munka', 'ponder')
    expect(problems(withArgs(['--output-dir', `${own}/playwright`]), R)).toEqual([])
    expect(problems(withArgs([`--output-dir=${own}/playwright`, '--isolated', '--viewport-size', '1280x720']), R)).toEqual([])
    expect(problems(withArgs(['--output-dir', own]), R)).toEqual([])                              // the area itself
    for (const bad of [`${join(homedir(), 'agents_munka')}/other`, `${own}-evil/x`, `${homedir()}/marveen/agents/ponder`, '/tmp/x', `${own}/../ponder-x`])
      expect({ bad, p: problems(withArgs(['--output-dir', bad]), R).join(' ').includes('own area') }).toEqual({ bad, p: true })
  })
  it('v5: fails an env block that sets anything the launcher would drop (the PLAYWRIGHT_MCP_* family, proxies, the binary, NODE_OPTIONS)', () => {
    const withEnv = (env: Record<string, string>) => ({ mcpServers: { playwright: { ...good.mcpServers.playwright, env } } })
    for (const n of ['PLAYWRIGHT_MCP_CDP_ENDPOINT', 'PLAYWRIGHT_MCP_PROXY_BYPASS', 'PLAYWRIGHT_MCP_PROXY_SERVER', 'PLAYWRIGHT_MCP_CONFIG', 'PLAYWRIGHT_MCP_EXTENSION',
      'PLAYWRIGHT_MCP_ALLOW_UNRESTRICTED_FILE_ACCESS', 'PONDER_PLAYWRIGHT_MCP_BIN', 'NODE_OPTIONS', 'HTTPS_PROXY', 'ALL_PROXY', 'no_proxy'])
      expect({ n, p: problems(withEnv({ [n]: 'x' }), R).join(' ').includes(n) }).toEqual({ n, p: true })
    expect(problems(withEnv({ LANG: 'C.UTF-8', TZ: 'Europe/Budapest', PLAYWRIGHT_BROWSERS_PATH: '/x/b' }), R)).toEqual([])   // what the launcher passes is fine
    expect(problems(withEnv({}), R)).toEqual([])
  })
  it('fails a SECOND server that could drive a browser, and a file without servers', () => {
    expect(problems({ mcpServers: { ...good.mcpServers, chrome: { command: 'npx', args: ['chrome-devtools-mcp'] } } }, R).join(' ')).toContain('another server ("chrome")')
    expect(problems({ mcpServers: { ...good.mcpServers, puppet: { command: 'npx', args: ['puppeteer-mcp'] } } }, R).join(' ')).toContain('another server ("puppet")')
    for (const bad of [null, {}, { mcpServers: null }, { mcpServers: [] }, 'x']) expect(problems(bad, R).length).toBeGreaterThan(0)
  })
  it('the script: exit 3 with no Ponder, 1 on a bad file, 0 on a good one', () => {
    const d = mkdtempSync(join(tmpdir(), 'ponder-check-'))
    try {
      const run = () => spawnSync(process.execPath, [join(ROOT, 'scripts', 'ponder-browser-check.mjs'), d], { encoding: 'utf-8' })
      expect(run().status).toBe(3)
      mkdirSync(join(d, 'agents', 'ponder'), { recursive: true })
      writeFileSync(join(d, 'agents', 'ponder', '.mcp.json'), '{ not json')
      expect(run().status).toBe(1)
      writeFileSync(join(d, 'agents', 'ponder', '.mcp.json'), JSON.stringify({ mcpServers: { playwright: { command: 'playwright-mcp', args: [] } } }))
      expect(run().status).toBe(1)
      writeFileSync(join(d, 'agents', 'ponder', '.mcp.json'), JSON.stringify({ mcpServers: { playwright: { command: 'node', args: [join(d, 'scripts', 'ponder-playwright-mcp.mjs'), '--headless'] } } }))
      const ok = run()
      expect({ status: ok.status, pass: ok.stdout.startsWith('PASS') }).toEqual({ status: 0, pass: true })
    } finally { rmSync(d, { recursive: true, force: true }) }
  })
})

// ---------------------------------------------------------------------------------------------------------
// End to end: the real @playwright/mcp and a real Chromium. The nine routes of the measurement (a server
// redirect, a meta refresh, window.location, a click, window.open, fetch(), an iframe, browser_tabs "new",
// and a direct navigate), each to an INTERNAL name (the proxy must stop it) and to a PUBLIC-looking name
// that maps to the same server (the positive control: the proxy lets it through). Names are fake; the
// resolver and the connector are replaced in this process. Skipped, loudly, where there is no browser.
function findChromium(): string | null {
  const env = process.env.CHROMIUM_BIN
  if (env && existsSync(env)) return env
  const base = join(homedir(), '.cache', 'ms-playwright')
  try {
    for (const d of readdirSync(base).filter((x) => /^chromium-\d+$/.test(x)).sort().reverse()) {
      const p = join(base, d, 'chrome-linux64', 'chrome')
      if (existsSync(p)) return p
    }
  } catch { /* no cache */ }
  return null
}
function findMcp(): string | null {
  if (process.env.PLAYWRIGHT_MCP_BIN && existsSync(process.env.PLAYWRIGHT_MCP_BIN)) return process.env.PLAYWRIGHT_MCP_BIN
  const beside = join(dirname(process.execPath), 'playwright-mcp')               // an npm -g install sits next to node
  if (existsSync(beside)) return beside
  for (const d of (process.env.PATH ?? '').split(':')) if (d && existsSync(join(d, 'playwright-mcp'))) return join(d, 'playwright-mcp')
  return null
}
const CHROMIUM = findChromium()
const MCP = findMcp()

describe.skipIf(!CHROMIUM || !MCP)('end to end with the real browser (measured on the host that has one)', () => {
  it('every route to an internal name is refused, every route to a public-looking name works, and nothing reaches the internal server', async () => {
    const hits: string[] = []
    const B = http.createServer((q, s) => { hits.push(q.url ?? ''); s.setHeader('content-type', 'text/html'); s.setHeader('access-control-allow-origin', '*'); s.end('<h1>INTERNAL-B</h1>') })
    await new Promise<void>((r) => B.listen(0, '127.0.0.1', r)); const bPort = (B.address() as net.AddressInfo).port
    let aPort = 0
    const target = (n: string) => `http://${n}:${bPort}`
    const A = http.createServer((q, s) => {
      s.setHeader('content-type', 'text/html')
      const url = q.url ?? ''
      const T = url.includes('pub') ? target('pub-b.example') : target('internal.example')
      if (url.startsWith('/redirect')) { s.statusCode = 302; s.setHeader('location', `${T}/via-redirect`); return s.end() }
      if (url.startsWith('/meta')) return s.end(`<html><head><meta http-equiv="refresh" content="0;url=${T}/via-meta"></head><body>m</body></html>`)
      if (url.startsWith('/script')) return s.end(`<html><body><script>setTimeout(()=>{window.location='${T}/via-script'},50)</script></body></html>`)
      if (url.startsWith('/click')) return s.end(`<html><body><a href="${T}/via-click">go</a></body></html>`)
      if (url.startsWith('/open')) return s.end(`<html><body><button onclick="window.open('${T}/via-open')">open</button></body></html>`)
      if (url.startsWith('/fetch')) return s.end(`<html><body><script>fetch('${T}/via-fetch')</script></body></html>`)
      if (url.startsWith('/iframe')) return s.end(`<html><body><iframe src="${T}/via-iframe"></iframe></body></html>`)
      s.end('<html><body>A</body></html>')
    })
    await new Promise<void>((r) => A.listen(0, '127.0.0.1', r)); aPort = (A.address() as net.AddressInfo).port
    const FAKE: Record<string, string> = { 'a.example': '93.184.216.34', 'pub-b.example': '93.184.216.35', 'internal.example': '10.0.0.5' }
    const refused: string[] = []
    const px = await createPonderProxy({
      ports: new Set([80, 443, aPort, bPort]),
      lookup: async (h: string) => { if (FAKE[h]) return [{ address: FAKE[h], family: 4 }]; throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }) },
      connect: (a: string) => net.connect({ host: '127.0.0.1', port: a === '93.184.216.34' ? aPort : bPort }),
      log: (e: { host: string; reason: string }) => refused.push(`${e.host} ${e.reason}`),
    })
    const p = spawn(MCP as string, ['--headless', '--isolated', '--executable-path', CHROMIUM as string, '--no-sandbox', '--proxy-server', `http://127.0.0.1:${px.port}`], { stdio: ['pipe', 'pipe', 'ignore'] })
    let buf = ''; const waiters = new Map<number, (m: unknown) => void>(); let id = 0
    p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); try { const m = JSON.parse(l); if (m.id && waiters.has(m.id)) { (waiters.get(m.id) as (m: unknown) => void)(m); waiters.delete(m.id) } } catch { /* not json */ } } })
    const send = (method: string, params: unknown) => new Promise<{ result?: { content?: Array<{ text?: string }> } }>((res) => { const i = ++id; waiters.set(i, res as (m: unknown) => void); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n') })
    const call = async (name: string, args: unknown) => ((await send('tools/call', { name, arguments: args })).result?.content ?? []).map((c) => c.text ?? '').join('\n')
    const settle = () => new Promise((r) => setTimeout(r, 1500))
    try {
      await send('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } })
      p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n')
      const result: Record<string, { internal: boolean; control: boolean }> = {}
      const run = async (label: string, drive: (kind: 'internal' | 'pub') => Promise<void>) => {
        const r = { internal: false, control: false }
        for (const kind of ['internal', 'pub'] as const) { hits.length = 0; await drive(kind); await settle(); if (kind === 'internal') r.internal = hits.length > 0; else r.control = hits.length > 0 }
        result[label] = r
      }
      const clickFirst = async () => { const snap = await call('browser_snapshot', {}); const ref = (snap.match(/\[ref=([a-z0-9]+)\]/) ?? [])[1]; if (ref) await call('browser_click', { target: ref }) }
      await run('direct navigate', async (k) => { await call('browser_navigate', { url: target(k === 'pub' ? 'pub-b.example' : 'internal.example') + '/d' }) })
      for (const route of ['redirect', 'meta', 'script', 'fetch', 'iframe', 'click', 'open'])
        await run(route, async (k) => { await call('browser_navigate', { url: `http://a.example:${aPort}/${route}${k === 'pub' ? '-pub' : ''}` }); if (route === 'click' || route === 'open') await clickFirst() })
      await run('tabs new', async (k) => { await call('browser_tabs', { action: 'new', url: target(k === 'pub' ? 'pub-b.example' : 'internal.example') + '/t' }) })
      for (const [label, r] of Object.entries(result)) expect({ label, ...r }).toEqual({ label, internal: false, control: true })
      expect(Object.keys(result)).toHaveLength(9)
      // the proxy logged the internal name's refusals, and never refused the names that were meant to work
      expect(refused.some((x) => x === 'internal.example resolves-to-non-public')).toBe(true)
      expect(refused.filter((x) => x.startsWith('a.example ') || x.startsWith('pub-b.example '))).toEqual([])
    } finally {
      p.kill(); await px.close(); A.close(); B.close()
    }
  }, 120000)
})

// ---------------------------------------------------------------------------------------------------------
// v5, end to end against the real browser (skipped, loudly, where there is none).
// WEBRTC: the proxy is an HTTP proxy and carries no UDP, so a page that makes Chromium send STUN to an
// internal address goes around it. POSITIVE CONTROL first: without the launcher's config the datagrams DO
// arrive (so a zero below is a measurement). Then the same page with browserConfig() from the launcher.
// A MUTANT is part of the record: the spelling --force-webrtc-ip-handling-policy=... reaches the command line
// and still lets the datagrams through (measured 2026-10-04, Chromium 1228).
type Rpc = { send: (method: string, params: unknown) => Promise<{ result?: { content?: Array<{ text?: string }> } }>; call: (name: string, args: unknown) => Promise<string>; stop: () => void }
function mcpSession(cmd: string, args: string[], env: Record<string, string> = process.env as Record<string, string>): Rpc {
  const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'ignore'], env })
  let buf = ''; const waiters = new Map<number, (m: unknown) => void>(); let id = 0
  p.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); try { const m = JSON.parse(l); if (m.id && waiters.has(m.id)) { (waiters.get(m.id) as (m: unknown) => void)(m); waiters.delete(m.id) } } catch { /* not json */ } } })
  const send: Rpc['send'] = (method, params) => new Promise((res) => { const i = ++id; waiters.set(i, res as (m: unknown) => void); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n') })
  const call: Rpc['call'] = async (name, a) => ((await send('tools/call', { name, arguments: a })).result?.content ?? []).map((c) => c.text ?? '').join('\n')
  return { send, call, stop: () => p.kill() }
}
async function initialised(s: Rpc): Promise<Rpc> {
  await s.send('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } })
  return s
}

describe.skipIf(!CHROMIUM || !MCP)('v5 end to end: WebRTC cannot reach an internal address past the proxy, and the launcher\'s environment is enough for the browser', () => {
  async function stunDatagrams(extraBrowserArgs: string[] | null, useLauncherConfig: boolean): Promise<number> {
    const udp = dgram.createSocket('udp4'); let got = 0
    await new Promise<void>((r) => udp.bind(0, '127.0.0.1', () => r())); udp.on('message', () => { got++ })
    const uport = udp.address().port
    const page = `<html><body><script>const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:${uport}' }] }); pc.createDataChannel('x'); pc.createOffer().then((o) => pc.setLocalDescription(o))</script>ok</body></html>`
    const A = http.createServer((_q, s) => { s.setHeader('content-type', 'text/html'); s.end(page) })
    await new Promise<void>((r) => A.listen(0, '127.0.0.1', () => r())); const aPort = (A.address() as net.AddressInfo).port
    const px = await createPonderProxy({
      ports: new Set([80, 443, aPort]),
      lookup: async (h: string) => { if (h === 'a.example') return [{ address: '93.184.216.34', family: 4 }]; throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }) },
      connect: () => net.connect({ host: '127.0.0.1', port: aPort }),
    })
    const d = mkdtempSync(join(tmpdir(), 'ponder-webrtc-'))
    const cfg = join(d, 'c.json')
    writeFileSync(cfg, JSON.stringify(useLauncherConfig ? browserConfig() : { browser: { launchOptions: { args: extraBrowserArgs ?? [] } } }))
    const s = mcpSession(MCP as string, ['--headless', '--isolated', '--executable-path', CHROMIUM as string, '--no-sandbox', '--proxy-server', `http://127.0.0.1:${px.port}`, ...(useLauncherConfig || extraBrowserArgs ? ['--config', cfg] : [])])
    try {
      await initialised(s)
      await s.call('browser_navigate', { url: `http://a.example:${aPort}/` })
      await new Promise((r) => setTimeout(r, 3000))
      return got
    } finally { s.stop(); await px.close(); A.close(); udp.close(); rmSync(d, { recursive: true, force: true }) }
  }
  it('POSITIVE CONTROL: with no WebRTC switch the page makes Chromium send STUN straight to a loopback UDP port', async () => {
    expect(await stunDatagrams(null, false)).toBeGreaterThan(0)
  }, 60000)
  it('MUTANT: --force-webrtc-ip-handling-policy reaches the browser and changes nothing (why the launcher does not use it)', async () => {
    expect(await stunDatagrams(['--force-webrtc-ip-handling-policy=disable_non_proxied_udp'], false)).toBeGreaterThan(0)
  }, 60000)
  it('the launcher\'s browserConfig(): the same page sends NOTHING', async () => {
    expect(await stunDatagrams(null, true)).toBe(0)
  }, 60000)

  // The research agent's own browser is the headless shell (agents/ponder/.mcp.json), the full Chromium is the other one.
  // Both are measured when installed, WITHOUT the LD_LIBRARY_PATH that Ponder's .mcp.json env block carries: the
  // launcher drops it, and on this host (ldd: nothing "not found") neither browser needs it.
  const HEADLESS = (() => {
    try {
      for (const d of readdirSync(join(homedir(), '.cache', 'ms-playwright')).filter((x) => /^chromium_headless_shell-\d+$/.test(x)).sort().reverse()) {
        const p = join(homedir(), '.cache', 'ms-playwright', d, 'chrome-headless-shell-linux64', 'chrome-headless-shell')
        if (existsSync(p)) return p
      }
    } catch { /* no cache */ }
    return null
  })()
  const BROWSERS = [CHROMIUM, HEADLESS].filter((x): x is string => !!x)
  it.each(BROWSERS)('the launcher itself: the real server starts under the allowlisted environment, the browser (%s) launches and every request goes through the proxy', async (browser) => {
    const d = mkdtempSync(join(tmpdir(), 'ponder-real-'))
    const w = join(d, 'wrap.mjs')
    writeFileSync(w, `import { launch } from ${JSON.stringify(LAUNCHER)}\nawait launch(process.argv.slice(2), { bin: ${JSON.stringify(MCP)} })\n`)
    const s = mcpSession(process.execPath, [w, '--headless', '--isolated', '--executable-path', browser], {
      PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', PLAYWRIGHT_MCP_CDP_ENDPOINT: 'http://127.0.0.1:1', NODE_OPTIONS: '--max-old-space-size=256',
    })
    try {
      await initialised(s)
      // A name that does not resolve, over https: the browser asks the PROXY for a tunnel and the proxy refuses it.
      // That message comes from a running Chromium behind the launcher's proxy: nothing else produces it.
      const out = await s.call('browser_navigate', { url: 'https://intranet.example.com/' })
      expect(out).toContain('ERR_TUNNEL_CONNECTION_FAILED')                       // the browser started (allowlisted env was enough) and every request went through the proxy
      expect(out).not.toMatch(/CDP|ECONNREFUSED 127\.0\.0\.1:1/)                  // the hostile PLAYWRIGHT_MCP_CDP_ENDPOINT was not honoured
    } finally { s.stop(); rmSync(d, { recursive: true, force: true }) }
  }, 90000)
})
