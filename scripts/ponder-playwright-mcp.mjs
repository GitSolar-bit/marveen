#!/usr/bin/env node
// PONDERTIER1003 v4 (hardened in v5): the launcher for the research agent's Playwright MCP server.
//
// It starts the destination filter (ponder-browser-proxy.mjs) inside this process, then runs the real
// @playwright/mcp server with --proxy-server pointing at it, stdio passed straight through, so that EVERY
// request the browser makes, a redirect or a page-started navigation included, is judged by the proxy.
// The proxy lives and dies with the MCP server: when the child exits (or this launcher gets a signal), the
// proxy closes. The agent's .mcp.json uses THIS script as the server command:
//
//   "playwright": { "command": "node", "args": ["<install>/scripts/ponder-playwright-mcp.mjs", "--headless", "--browser", "chromium", "--executable-path", "<chromium>"] }
//
// The server key must be exactly "playwright" (the egress-gate matcher is mcp__playwright__.*; another
// name leaves the hook off). The arguments the flag allowlist accepts (below) go to @playwright/mcp unchanged; the rest is refused.
//
// FLAGS REFUSED, because each one routes the browser around the proxy or widens what it may open:
// --proxy-server / --proxy-bypass (a second proxy, or a bypass list), --cdp-endpoint / --extension (a
// browser that is already running, with its own network), --config (a file that can set a proxy), and
// --allow-unrestricted-file-access (file:// pages). SINCE v5.1 that is no longer a list of refusals but an
// ALLOWLIST (ALLOWED_FLAGS below): anything not on it is refused, whatever it is called.
//
// v5, THREE MORE WAYS AROUND THE FILTER, closed here:
//  1. WEBRTC. The proxy is an HTTP proxy; it carries no UDP. A page can make Chromium send UDP (STUN, and
//     ICE connectivity checks) straight to an internal address, past the proxy. The launcher hands the
//     browser --webrtc-ip-handling-policy=disable_non_proxied_udp through a config file of its own. MEASURED
//     (v5): the spelling --force-webrtc-ip-handling-policy=... reaches the Chromium command line and changes
//     NOTHING (4 datagrams still arrive); --webrtc-ip-handling-policy=... stops them (0). Use the second.
//  2. THE ENVIRONMENT. @playwright/mcp reads PLAYWRIGHT_MCP_* variables that mirror the flags refused above
//     (CDP endpoint, proxy bypass, config file, ...), and Node reads NODE_OPTIONS. The child gets an ALLOWLIST
//     of variables (ENV_ALLOW), nothing else: no PLAYWRIGHT_MCP_*, no proxy variables, no NODE_OPTIONS, and no
//     credential of the session that started it.
//  3. THE SERVER BINARY. It was named by the environment (PONDER_PLAYWRIGHT_MCP_BIN). It is now the one that
//     sits next to the node running this launcher, and the variable is ignored. launch() takes a bin for
//     tests; the command line and the environment cannot.
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { closeSync, existsSync, mkdtempSync, openSync, readSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir, userInfo } from 'node:os'
import { dirname, join, sep } from 'node:path'
import { createPonderProxy } from './ponder-browser-proxy.mjs'

// v5.1: THE FLAGS ARE AN ALLOWLIST, not a refusal list. @playwright/mcp 0.0.82 has ~50 options, and a list of
// the dangerous ones is a list that a version bump silently makes incomplete (--endpoint, --init-page,
// --init-script, --user-data-dir, --storage-state, --secrets, --grant-permissions were all outside the v4/v5
// list). Only what the research agent's setup needs is passed on, with a check on each value; everything
// else is refused, and a flag that is new in a later version is refused until somebody reads it.
//   --headless, --isolated                       no value
//   --browser chromium                           only chromium (the other values name system browsers)
//   --executable-path <absolute path>            the browser binary: only the Playwright-installed chromium / chrome-headless-shell (resolveBrowserBinary)
//   --output-dir <absolute path>                 where unnamed output files go (the agent's own area; ponder-browser-check pins it)
//   --viewport-size <W>x<H>                      digits only
// A value never starts with "-", is never empty, and the --flag=value spelling is judged like the two-word one.
const absolutePath = (v) => v.startsWith('/') && !v.split('/').includes('..') && !v.includes('\0')

// v5.2 (PONDERBINPIN1004): --executable-path used to take ANY absolute path, so a wrapper script that ignores
// --proxy-server was a valid "browser" (measured by the owner's independent bypass search, 2026-10-04). It is now
// pinned: the path, after realpath, must be one of the two binaries Playwright installs under the research
// agent's OWN user's ~/.cache/ms-playwright, by exact file name:
//   chromium-<N>/chrome-linux[64]/chrome
//   chromium_headless_shell-<N>/chrome-headless-shell-linux[64]/chrome-headless-shell
// v5.3 (PONDERBINHASH1004): name and ELF shape were not enough: the owner's second search showed that an agent
// that can `curl -o` / `wget -O` an ELF under that cache passes both. The file must now ALSO hash to one of the
// two known binaries below. Updating Playwright changes the hashes on purpose: the launcher then refuses the new
// browser until somebody replaces the two lines (and the matching doc line) deliberately. Refresh with:
//   sha256sum ~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome \
//             ~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell
// The root comes from the passwd entry (os.userInfo), not from $HOME or PLAYWRIGHT_BROWSERS_PATH: both of those
// are environment, and the environment is what this launcher does not trust. Check and launch use the same
// function. launch() then hands the server the RESOLVED path.
// WHAT THIS DOES NOT CLOSE: hash-then-spawn is not atomic. Whoever can REPLACE the file between the check and the
// exec (a ~2 s window) is not stopped here; that is closed by the write confinement in the destructive gate.
export const BROWSER_BINARY_PATTERNS = [
  /^chromium-\d+\/chrome-linux\d*\/chrome$/,
  /^chromium_headless_shell-\d+\/chrome-headless-shell-linux\d*\/chrome-headless-shell$/,
]
export const PINNED_BROWSER_SHA256 = new Set([
  '2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801', // chromium-1228/chrome-linux64/chrome (measured 2026-10-04)
  '670ba079b75107746ba41abad131180a31a7c7219aa1bd4061fb471f4535d541', // chromium_headless_shell-1228/chrome-headless-shell-linux64/chrome-headless-shell (measured 2026-10-04)
])
export const browserRoot = () => join(userInfo().homedir, '.cache', 'ms-playwright')

// sha256 of a file, streamed in 1 MiB blocks (the two binaries are 180-280 MB; about 2 s each). null when unreadable.
export const sha256File = (p) => {
  let fd
  try {
    fd = openSync(p, 'r')
    const h = createHash('sha256')
    const b = Buffer.alloc(1 << 20)
    for (let n; (n = readSync(fd, b, 0, b.length, null)) > 0;) h.update(b.subarray(0, n))
    return h.digest('hex')
  } catch { return null } finally { if (fd !== undefined) try { closeSync(fd) } catch { /* nothing to close */ } }
}

// The resolved browser path when `v` is an allowed browser binary, else null. `root`, `real`, `digest` and `pinned`
// are for tests. The name check runs first, so only a file with a pinned name is ever read and hashed.
export function resolveBrowserBinary(v, { root = browserRoot(), real = realpathSync, digest = sha256File, pinned = PINNED_BROWSER_SHA256 } = {}) {
  if (typeof v !== 'string' || !absolutePath(v)) return null
  let r, rootReal
  try { r = real(v); rootReal = real(root) } catch { return null }
  if (!r.startsWith(rootReal + sep)) return null
  const rel = r.slice(rootReal.length + 1)
  if (!BROWSER_BINARY_PATTERNS.some((re) => re.test(rel))) return null
  const d = digest(r)
  return d !== null && pinned.has(d) ? r : null
}

export const ALLOWED_FLAGS = {
  '--headless': null,
  '--isolated': null,
  '--browser': (v) => v === 'chromium',
  '--executable-path': (v, opts) => resolveBrowserBinary(v, opts) !== null,
  '--output-dir': absolutePath,
  '--viewport-size': (v) => /^\d{2,5}x\d{2,5}$/.test(v),
}

// The ones that were refused by NAME before v5.1: they route the browser around the proxy or widen what it may
// open. They stay named so that the message says why; the allowlist refuses them anyway.
export const REFUSED_FLAGS = ['--proxy-server', '--proxy-bypass', '--cdp-endpoint', '--extension', '--config', '--allow-unrestricted-file-access']

// The first argument the allowlist does not accept (the flag, or the stray word, as written), or null.
export function refusedFlag(args, opts = {}) {
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i])
    if (!a.startsWith('--')) return a                                  // a stray word, a short flag (-b): not a flag we know
    const eq = a.indexOf('=')
    const name = eq < 0 ? a : a.slice(0, eq)
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_FLAGS, name)) return name
    const valid = ALLOWED_FLAGS[name]
    if (valid === null) { if (eq >= 0) return name; continue }         // a switch takes no value
    const v = eq >= 0 ? a.slice(eq + 1) : (i + 1 < args.length ? String(args[++i]) : undefined)
    if (v === undefined || v === '' || v.startsWith('-') || !valid(v, opts)) return name
  }
  return null
}

// What the browser server may inherit. Exact names, plus the LC_* locale family. Everything else is dropped.
// (Headless only: no DISPLAY. A variable the server really needs is added here, with the reason.)
export const ENV_ALLOW = [
  'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LANGUAGE', 'TZ',
  'TMPDIR', 'TEMP', 'TMP',
  'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_RUNTIME_DIR',
  'PLAYWRIGHT_BROWSERS_PATH',                 // where the browsers were installed; selects a path, runs nothing
  'FONTCONFIG_PATH', 'FONTCONFIG_FILE',
]
export const ENV_ALLOW_PREFIXES = ['LC_']

// True when the launcher passes this variable on.
export function envAllowed(name) {
  return ENV_ALLOW.includes(name) || ENV_ALLOW_PREFIXES.some((p) => name.startsWith(p) && name.length > p.length)
}

// The environment of the server process: the allowed variables of `env`, and nothing else.
export function childEnv(env) {
  const out = {}
  for (const [k, v] of Object.entries(env)) if (envAllowed(k) && typeof v === 'string') out[k] = v
  return out
}

// Chromium switches the launcher adds (see 1. above).
export const BROWSER_ARGS = ['--webrtc-ip-handling-policy=disable_non_proxied_udp']

// The @playwright/mcp config file content for BROWSER_ARGS.
export function browserConfig() {
  return { browser: { launchOptions: { args: [...BROWSER_ARGS] } } }
}

// The server binary: the playwright-mcp that sits next to the node running this launcher (an npm -g install
// puts it there), or null. Not the environment, not the PATH.
export function serverBin(execPath = process.execPath, exists = existsSync) {
  const p = join(dirname(execPath), 'playwright-mcp')
  return exists(p) ? p : null
}

// Runs the filter and the server; ends the process when the server ends. `bin` is for tests only.
// The same arguments with the browser path replaced by its resolved form (both spellings). Call after refusedFlag.
export function pinExecutablePath(args, opts = {}) {
  const out = []
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i])
    if (a === '--executable-path' && i + 1 < args.length) { out.push(a, resolveBrowserBinary(String(args[++i]), opts) ?? args[i]); continue }
    if (a.startsWith('--executable-path=')) { out.push('--executable-path=' + (resolveBrowserBinary(a.slice('--executable-path='.length), opts) ?? a.slice('--executable-path='.length))); continue }
    out.push(a)
  }
  return out
}

export async function launch(args, { bin = serverBin(), pin = {} } = {}) {
  const bad = refusedFlag(args, pin)
  if (bad) {
    const why = REFUSED_FLAGS.includes(bad) ? 'it would route the browser around the destination filter' : `it is not on the launcher's flag allowlist (${Object.keys(ALLOWED_FLAGS).join(', ')}), or its value is not accepted`
    process.stderr.write(`ponder-playwright-mcp: ${bad} is refused: ${why}.\n`)
    process.exit(2)
  }
  if (!bin) {
    process.stderr.write(`ponder-playwright-mcp: cannot start: no playwright-mcp next to ${process.execPath}\n`)
    process.exit(127)
  }
  const proxy = await createPonderProxy()
  const dir = mkdtempSync(join(tmpdir(), 'ponder-mcp-'))
  const cfg = join(dir, 'config.json')
  writeFileSync(cfg, JSON.stringify(browserConfig()), { mode: 0o600 })
  const cleanup = () => { try { rmSync(dir, { recursive: true, force: true }) } catch { /* already gone */ } }
  process.on('exit', cleanup)
  const child = spawn(bin, [...pinExecutablePath(args, pin), '--config', cfg, '--proxy-server', `http://127.0.0.1:${proxy.port}`], { stdio: 'inherit', env: childEnv(process.env) })
  const stop = (code) => { proxy.close().finally(() => process.exit(code)) }
  child.on('exit', (code, signal) => stop(code ?? (signal ? 1 : 0)))
  child.on('error', (e) => { process.stderr.write(`ponder-playwright-mcp: cannot start ${bin}: ${e.message}\n`); stop(127) })
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => { try { child.kill(sig) } catch { /* already gone */ } })
}

function isInvokedDirectly() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === (process.argv[1] ? realpathSync(process.argv[1]) : '')
  } catch { return false }
}

if (isInvokedDirectly()) await launch(process.argv.slice(2))
