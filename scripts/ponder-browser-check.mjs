#!/usr/bin/env node
// PONDERTIER1003 v4: is the research agent's browser actually behind the destination filter?
//
// The proxy only protects a browser that is LAUNCHED through scripts/ponder-playwright-mcp.mjs, and the hook
// cannot see how an MCP server was started. This reads the agent's .mcp.json (read only) and says whether
// the setup that the rest of the tier assumes is the one in place:
//   - the server key is exactly "playwright" (the egress-gate matcher is mcp__playwright__.*; another name
//     leaves the Playwright rules off);
//   - the server command runs the launcher (node <install>/scripts/ponder-playwright-mcp.mjs ...);
//   - the --executable-path is one of the Playwright-installed browser binaries (v5.3: resolveBrowserBinary, by
//     realpath, exact file name AND the sha256 of the two known binaries); a wrapper script that drops --proxy-server
//     would otherwise pass, and so would an ELF dropped there by curl -o;
//   - every flag is on the launcher's ALLOWLIST (v5.1; anything else would make it exit 2 at start, which is
//     also a failure the agent would notice, but a file that says so is better caught here), and --output-dir,
//     when present, is under ~/agents_munka/ponder/;
//   - the server's env block (v5) sets nothing the launcher would drop: no PLAYWRIGHT_MCP_* (they mirror the
//     refused flags), no proxy variable, no PONDER_PLAYWRIGHT_MCP_BIN, no NODE_OPTIONS. The launcher passes an
//     allowlist of variables on, so such a line changes nothing at run time; a file that carries one is a file
//     somebody meant to do something with, and that is worth failing on. (This reads .mcp.json only: the
//     environment of the session that starts the server is not visible here, which is why the launcher
//     filters it rather than trusting the file.)
//   - no OTHER server in the file can drive a browser (a second playwright-like or puppeteer-like entry).
// Usage: node scripts/ponder-browser-check.mjs [<install root>]     exit 0 = PASS, 1 = FAIL, 3 = no Ponder yet
import { readFileSync, existsSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { refusedFlag, envAllowed } from './ponder-playwright-mcp.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))

// Pure: the findings for a parsed .mcp.json and the install root. [] = nothing wrong.
export function browserSetupProblems(mcpJson, root, pin = {}) {
  const problems = []
  const servers = mcpJson && typeof mcpJson === 'object' && mcpJson.mcpServers && typeof mcpJson.mcpServers === 'object' ? mcpJson.mcpServers : null
  if (!servers) return ['no mcpServers object in the file']
  const launcher = join(root, 'scripts', 'ponder-playwright-mcp.mjs')
  const pw = servers.playwright
  if (!pw) problems.push('no server named exactly "playwright" (the hook matcher is mcp__playwright__.*)')
  else {
    const args = Array.isArray(pw.args) ? pw.args.map(String) : []
    const runsLauncher = (pw.command === 'node' || String(pw.command ?? '').endsWith('/node')) && args[0] === launcher
    if (!runsLauncher) problems.push(`the playwright server does not run the launcher (want: node ${launcher} ...; have: ${pw.command} ${args[0] ?? ''})`)
    const bad = refusedFlag(args.slice(1), pin)
    if (bad) problems.push(`the playwright server passes ${bad}, which the launcher refuses (it is not on the flag allowlist, or its value is not accepted)`)
    // --output-dir is allowed because its purpose is the agent's OWN area; the launcher cannot know whose area, this can.
    const own = join(homedir(), 'agents_munka', 'ponder') + sep
    for (let i = 1; i < args.length; i++) {
      const a = args[i]
      const v = a === '--output-dir' ? args[i + 1] : a.startsWith('--output-dir=') ? a.slice('--output-dir='.length) : null
      if (v != null && !(join(v) + sep).startsWith(own)) problems.push(`--output-dir ${v} is not under the research agent's own area (${own})`)
    }
    if (pw.env && typeof pw.env === 'object') {
      for (const name of Object.keys(pw.env)) if (!envAllowed(name)) problems.push(`the playwright server sets ${name} in its env block (the launcher drops it, but it should not be there)`)
    }
  }
  for (const [name, s] of Object.entries(servers)) {
    if (name === 'playwright') continue
    const text = JSON.stringify(s).toLowerCase()
    if (/playwright|puppeteer|chrome|chromium|browser/.test(text) || /playwright|puppeteer|browser/.test(name.toLowerCase())) problems.push(`another server ("${name}") looks able to drive a browser; it would not be behind the filter`)
  }
  return problems
}

function isInvokedDirectly() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === (process.argv[1] ? realpathSync(process.argv[1]) : '') } catch { return false }
}

if (isInvokedDirectly()) {
  const root = resolve(process.argv[2] ?? join(HERE, '..'))
  const file = join(root, 'agents', 'ponder', '.mcp.json')
  if (!existsSync(file)) { console.log(`NO PONDER YET: ${file} does not exist, nothing to check`); process.exit(3) }
  let parsed
  try { parsed = JSON.parse(readFileSync(file, 'utf-8')) } catch (e) { console.log(`FAIL ${file} is not readable JSON: ${e.message}`); process.exit(1) }
  const problems = browserSetupProblems(parsed, root)
  if (problems.length) { for (const p of problems) console.log('FAIL ' + p); process.exit(1) }
  console.log(`PASS ${file}: the browser runs behind the destination filter`)
}
