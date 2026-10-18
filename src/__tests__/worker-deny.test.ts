import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ensureWorkerCwd, makeWorkerCtx } from '../web/agent-worker.js'
import {
  mergeBashEgressDeny, mergeDenyRules, workerDenyRules, BASH_EGRESS_DENY, FLEET_BASELINE_DENY,
} from '../web/agent-scaffold.js'

// WORKERVAK925: the two worker sessions (hex-worker, hex-worker-fast) run
// `claude --dangerously-skip-permissions` on a prompt taken from a message, in a
// cwd and a CLAUDE_CONFIG_DIR outside the project. Measured 2026-10-02: ZERO deny
// rules on both, because no profile, no repo settings file and no per-agent
// route reaches them. ensureWorkerCwd() owns the worker's settings.json, so the
// rules belong there.

describe('workerDenyRules', () => {
  it('is the egress list plus the floor, with ${HOME} resolved', () => {
    const rules = workerDenyRules('/h/me')
    for (const r of BASH_EGRESS_DENY) expect(rules).toContain(r)
    expect(rules).toContain('Bash(sudo:*)')
    expect(rules).toContain('Bash(rm -rf /h/me:*)')
    expect(rules).toContain('Read(//h/me/.ssh/**)')
    expect(rules.some((r) => r.includes('${HOME}'))).toBe(false)
    // no rule is listed twice (the two lists are disjoint, pinned in fleet-baseline-deny)
    expect(new Set(rules).size).toBe(rules.length)
    expect(rules.length).toBe(BASH_EGRESS_DENY.length + FLEET_BASELINE_DENY.length)
  })
})

describe('mergeDenyRules', () => {
  it('appends only what is missing, keeps the existing order, reports a change once', () => {
    const s: Record<string, unknown> = { permissions: { allow: ['Read'], deny: ['Mine', 'Bash(sudo:*)'] } }
    expect(mergeDenyRules(s, ['Bash(sudo:*)', 'New'])).toBe(true)
    expect((s.permissions as { deny: string[] }).deny).toEqual(['Mine', 'Bash(sudo:*)', 'New'])
    expect((s.permissions as { allow: string[] }).allow).toEqual(['Read'])
    expect(mergeDenyRules(s, ['Bash(sudo:*)', 'New'])).toBe(false)
  })

  it('creates the permissions block when the file has none', () => {
    const s: Record<string, unknown> = {}
    expect(mergeDenyRules(s, ['A'])).toBe(true)
    expect((s.permissions as { deny: string[] }).deny).toEqual(['A'])
  })

  it('mergeBashEgressDeny still merges exactly the egress list', () => {
    const s: Record<string, unknown> = {}
    expect(mergeBashEgressDeny(s)).toBe(true)
    expect((s.permissions as { deny: string[] }).deny).toEqual([...BASH_EGRESS_DENY])
  })
})

describe('ensureWorkerCwd writes the deny rules into the worker settings.json', () => {
  let tmp = ''
  const realHome = process.env.HOME
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'worker-deny-'))
    process.env.HOME = tmp // ensureWorkerCwd reads homedir()/.claude and .claude.json
  })
  afterEach(() => {
    if (realHome === undefined) delete process.env.HOME; else process.env.HOME = realHome
    rmSync(tmp, { recursive: true, force: true })
  })

  const settingsOf = (ctx: ReturnType<typeof makeWorkerCtx>) =>
    JSON.parse(readFileSync(join(ctx.configDir, 'settings.json'), 'utf-8'))

  it('a fresh worker gets the full list, and the plugin/first-run keys are still there', () => {
    const ctx = makeWorkerCtx('t-worker', join(tmp, '.t-worker'))
    ensureWorkerCwd(ctx)
    const s = settingsOf(ctx)
    expect(s.permissions.deny).toEqual(workerDenyRules(tmp))
    expect(s.skipDangerousModePermissionPrompt).toBe(true)
    expect(s.enabledPlugins).toBeTruthy()
  })

  it('survives a second start, and keeps a rule an operator added by hand', () => {
    const ctx = makeWorkerCtx('t-worker', join(tmp, '.t-worker'))
    ensureWorkerCwd(ctx)
    const path = join(ctx.configDir, 'settings.json')
    const s = settingsOf(ctx)
    s.permissions.deny.unshift('Bash(echo operator-rule:*)')
    writeFileSync(path, JSON.stringify(s))
    ensureWorkerCwd(ctx)
    const after = settingsOf(ctx)
    expect(after.permissions.deny[0]).toBe('Bash(echo operator-rule:*)')
    for (const r of workerDenyRules(tmp)) expect(after.permissions.deny).toContain(r)
    expect(after.permissions.deny.filter((r: string) => r === 'Bash(sudo:*)')).toHaveLength(1)
  })

  it('wires the bash-egress-parser hook once, and keeps a hook that was already there', () => {
    const ctx = makeWorkerCtx('t-worker', join(tmp, '.t-worker'))
    ensureWorkerCwd(ctx)
    const path = join(ctx.configDir, 'settings.json')
    const s = settingsOf(ctx)
    s.hooks.PreToolUse.push({ matcher: 'Read', hooks: [{ type: 'command', command: 'echo operator-hook' }] })
    writeFileSync(path, JSON.stringify(s))
    ensureWorkerCwd(ctx)
    const pre = settingsOf(ctx).hooks.PreToolUse as Array<{ matcher: string; hooks: Array<{ command: string }> }>
    const parser = pre.filter((e) => JSON.stringify(e).includes('bash-egress-parser.mjs'))
    expect(parser).toHaveLength(1)
    expect(parser[0].matcher).toBe('Bash')
    expect(pre.some((e) => e.hooks.some((h) => h.command === 'echo operator-hook'))).toBe(true)
  })

  it('restores the rules when the file was reset to the pre-fix shape', () => {
    // exactly what the live workers carry today: no permissions block at all
    const ctx = makeWorkerCtx('t-worker-fast', join(tmp, '.t-worker-fast'))
    mkdirSync(ctx.configDir, { recursive: true })
    writeFileSync(join(ctx.configDir, 'settings.json'), JSON.stringify({ enabledPlugins: {}, skipDangerousModePermissionPrompt: true }))
    ensureWorkerCwd(ctx)
    expect(settingsOf(ctx).permissions.deny).toEqual(workerDenyRules(tmp))
  })
})
