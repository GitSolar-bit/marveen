// PONDERTIER1003 v4: the destination filter for the research agent's BROWSER.
//
// WHY THIS EXISTS (measured, scripts/__tests__ and docs/security-hardening.md): the egress-gate hook sees
// the URL a Playwright tool call is ASKED to open, and nothing the page does afterwards. Against @playwright/mcp
// 0.0.82 with a real Chromium, a public page reaches an internal service by a server redirect, a meta refresh,
// window.location, a click, window.open, fetch(), an iframe and browser_tabs "new": all nine routes. The
// MCP's own --blocked-origins / --allowed-origins close eight of them and say so themselves: "does not
// affect redirects". They also match exact origins, not address ranges, and not a name that resolves
// somewhere private. A forward proxy sees EVERY request the browser makes, redirects and sub-resources
// included, and resolves the name itself.
//
// WHAT IT DOES: every request the browser makes goes through this proxy (the launcher passes
// --proxy-server; Playwright forces loopback through a proxy too unless told otherwise). Per request the
// proxy refuses:
//   - a port other than 80 / 443;
//   - an IP literal in any spelling, and a single-label name (localhost, a search-domain name);
//   - a name that does not resolve, or whose lookup takes longer than 3 s (fail closed);
//   - a name for which ANY resolved address is not a public unicast one (loopback, private, link-local,
//     CGNAT, ULA, multicast, 6to4 / Teredo / NAT64 with the embedded v4 unpacked: the same
//     isNonPublicAddress() the hook uses, one definition);
// and it CONNECTS TO THE ADDRESS IT RESOLVED, not to the name again, so the answer it checked is the answer
// it used (DNS rebinding between a check and a connection is closed here, unlike in the hook).
//
// WHAT IT DOES NOT DO, stated rather than papered over:
//   - it does not narrow the PUBLIC web: a page may still send data to any public host, in the URL, a POST
//     body or a header, and for HTTPS the proxy sees host:port only (no URL, no query). The URL-length caps
//     of the hook apply to the URL the agent asks for, not to what a page requests afterwards.
//   - it is only in the path if the browser is LAUNCHED through scripts/ponder-playwright-mcp.mjs; a browser
//     started another way is not filtered (scripts/ponder-browser-check.mjs checks the agent's .mcp.json).
//   - a request the browser does not route through an HTTP proxy (none was found for http/https/ws/wss).
//
// Audit: every REFUSAL is appended to store/ponder-proxy.jsonl (time, kind, host, port, reason). Allowed
// requests are only counted (stats), because a page makes hundreds of them and the host list of an allowed
// request would not tell a reader more than the browser history does.
import http from 'node:http'
import net from 'node:net'
import dns from 'node:dns'
import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isNonPublicAddress } from './hooks/egress-gate.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_PROXY_LOG = join(HERE, '..', 'store', 'ponder-proxy.jsonl')
const ALLOWED_PORTS = new Set([80, 443])
const DNS_TIMEOUT_MS = 3000
const CONNECT_TIMEOUT_MS = 15000
const IDLE_TIMEOUT_MS = 120000
const LOOPBACK_CLIENTS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])

const defaultLookup = (host) => dns.promises.lookup(host, { all: true })
const defaultConnect = (addr, port) => net.connect({ host: addr, port })

// Why a destination is refused, or the address to connect to. Pure but for `lookup`.
export async function judgeTarget(rawHost, port, lookup = defaultLookup, ports = ALLOWED_PORTS) {
  const host = String(rawHost ?? '').toLowerCase().replace(/\.$/, '')
  if (!host) return { deny: 'no-host' }
  if (!ports.has(Number(port))) return { deny: 'port' }
  if (host.includes(':') || host.startsWith('[') || /^\d+(\.\d+){0,3}$/.test(host) || /^0x/i.test(host)) return { deny: 'ip-literal' }
  if (!host.includes('.')) return { deny: 'single-label-host' }
  let timer
  try {
    const addrs = await Promise.race([
      lookup(host),
      new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), DNS_TIMEOUT_MS) }),
    ])
    const list = (Array.isArray(addrs) ? addrs : [addrs]).map((a) => String(a?.address ?? ''))
    if (list.length === 0 || list.some((a) => !a)) return { deny: 'dns-unresolved' }
    if (list.some((a) => isNonPublicAddress(a))) return { deny: 'resolves-to-non-public' }
    return { addr: list[0] }
  } catch (e) {
    return { deny: e?.code === 'ETIMEOUT' ? 'dns-timeout' : 'dns-unresolved' }
  } finally {
    clearTimeout(timer)
  }
}

function hostPortOfConnect(target) {
  const m = /^\[([^\]]+)\]:(\d+)$/.exec(target) ?? /^([^:]+):(\d+)$/.exec(target)
  return m ? { host: m[1], port: Number(m[2]) } : null
}

const HOP_BY_HOP = new Set(['connection', 'proxy-connection', 'proxy-authorization', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade'])

// Returns { server, port, stats, close }. `lookup`, `connect` and `ports` are parameters for tests; the launcher
// uses the defaults. `log` receives every refusal; the default appends to store/ponder-proxy.jsonl.
export async function createPonderProxy({ lookup = defaultLookup, connect = defaultConnect, log = defaultLog, listenHost = '127.0.0.1', port = 0, ports = ALLOWED_PORTS } = {}) {
  const stats = { allowed: 0, denied: 0 }
  const refuse = (kind, host, p, reason) => {
    stats.denied++
    try { log({ ts: new Date().toISOString(), kind, host, port: p, reason }) } catch { /* the decision never depends on the log */ }
  }
  const fromLoopback = (socket) => LOOPBACK_CLIENTS.has(socket?.remoteAddress ?? '')

  const server = http.createServer(async (req, res) => {
    if (!fromLoopback(req.socket)) { req.socket.destroy(); return }
    let u
    try { u = new URL(req.url) } catch { res.writeHead(400, { 'content-type': 'text/plain' }); res.end('ponder-proxy: absolute URL required\n'); return }
    if (u.protocol !== 'http:') { refuse('HTTP', u.hostname, u.port, 'scheme'); res.writeHead(403, { 'content-type': 'text/plain' }); res.end('ponder-proxy: refused (scheme)\n'); return }
    const p = u.port ? Number(u.port) : 80
    const j = await judgeTarget(u.hostname, p, lookup, ports)
    if (j.deny) { refuse('HTTP', u.hostname, p, j.deny); res.writeHead(403, { 'content-type': 'text/plain' }); res.end(`ponder-proxy: refused (${j.deny})\n`); return }
    stats.allowed++
    const headers = {}
    for (const [k, v] of Object.entries(req.headers)) if (!HOP_BY_HOP.has(k.toLowerCase())) headers[k] = v
    headers.host = u.host
    const up = http.request({ method: req.method, path: u.pathname + u.search, headers, createConnection: () => connect(j.addr, p) }, (r) => {
      const out = {}
      for (const [k, v] of Object.entries(r.headers)) if (!HOP_BY_HOP.has(k.toLowerCase())) out[k] = v
      res.writeHead(r.statusCode ?? 502, r.statusMessage, out)
      r.pipe(res)
    })
    up.setTimeout(CONNECT_TIMEOUT_MS + IDLE_TIMEOUT_MS, () => up.destroy())
    up.on('error', () => { if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('ponder-proxy: upstream error\n') } else res.destroy() })
    req.pipe(up)
  })

  server.on('connect', async (req, client, head) => {
    client.on('error', () => client.destroy())
    if (!fromLoopback(client)) { client.destroy(); return }
    const t = hostPortOfConnect(String(req.url ?? ''))
    if (!t) { client.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n'); return }
    const j = await judgeTarget(t.host, t.port, lookup, ports)
    if (j.deny) { refuse('CONNECT', t.host, t.port, j.deny); client.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nponder-proxy: refused (${j.deny})\n`); return }
    stats.allowed++
    const up = connect(j.addr, t.port)
    up.setTimeout(CONNECT_TIMEOUT_MS, () => { up.destroy(); client.destroy() })
    up.on('error', () => { if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n'); up.destroy() })
    up.once('connect', () => {
      up.setTimeout(IDLE_TIMEOUT_MS, () => { up.destroy(); client.destroy() })
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head?.length) up.write(head)
      up.pipe(client); client.pipe(up)
    })
    client.on('close', () => up.destroy())
    up.on('close', () => client.destroy())
  })

  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, listenHost, resolve) })
  return {
    server,
    port: server.address().port,
    stats,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()) }),
  }
}

function defaultLog(evt) {
  mkdirSync(dirname(DEFAULT_PROXY_LOG), { recursive: true })
  appendFileSync(DEFAULT_PROXY_LOG, JSON.stringify(evt) + '\n', 'utf-8')
}
