/**
 * The operator's decision (2026-10-03): the destructive-gate runs on all four
 * sub-agents -- igor (developer-senior), sam and zola (default), willy (marketer).
 *
 * The switch is the profile flag `destructiveGate`, because that is the one place
 * the scaffold re-reads on every spawn: the deny-list and the hook wiring are
 * rendered FROM the profile, so a hand-edit of an agent's settings.json would be
 * regenerated away (UJAGENSDENY925). These tests render the REAL shipped profiles
 * into a throwaway agent and assert the FINAL settings file, twice, so a re-render
 * cannot silently drop the gate.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import {
  agentGetsDestructiveGate,
  agentSettingsPath,
  writeAgentSettingsFromProfile,
  DESTRUCTIVE_GATE_MATCHER,
} from '../web/agent-scaffold.js'
import { loadProfileTemplate } from '../web/profiles.js'
import { MAIN_AGENT_ID } from '../config.js'
import { AGENTS_BASE_DIR } from '../web/agent-config.js'

// agent -> securityProfile, as measured from agents/<n>/agent-config.json.
const FLEET: Record<string, string> = {
  igor: 'developer-senior',
  sam: 'default',
  willy: 'marketer',
  zola: 'default',
}
const PROBE = 'destructive-gate-fleet-probe'
const root = () => join(AGENTS_BASE_DIR, PROBE)

function cleanup(): void {
  const r = root()
  if (!existsSync(r)) return
  if (existsSync(join(r, 'CLAUDE.md')) || existsSync(join(r, 'HANDOFF.md'))) {
    throw new Error(`refusing: ${r} looks like a live agent, not a test checkout`)
  }
  rmSync(r, { recursive: true, force: true })
}
beforeEach(cleanup)
afterEach(cleanup)

function gateEntries(profileId: string): Array<{ matcher?: string }> {
  mkdirSync(join(root(), '.claude'), { recursive: true })
  const profile = loadProfileTemplate(profileId)
  writeAgentSettingsFromProfile(PROBE, profile)
  writeAgentSettingsFromProfile(PROBE, profile) // a second spawn must converge
  const settings = JSON.parse(readFileSync(agentSettingsPath(PROBE), 'utf-8')) as {
    hooks?: { PreToolUse?: Array<{ matcher?: string }> }
  }
  return (settings.hooks?.PreToolUse ?? []).filter((e) => JSON.stringify(e).includes('destructive-gate.py'))
}

describe('the four sub-agents run the destructive gate through their real profile', () => {
  for (const [agent, profileId] of Object.entries(FLEET)) {
    it(`${agent} (${profileId}) is gated`, () => {
      expect(agentGetsDestructiveGate(agent, loadProfileTemplate(profileId))).toBe(true)
    })
  }

  for (const profileId of new Set(Object.values(FLEET))) {
    it(`profile ${profileId}: the final settings carry exactly one canonical gate entry after two renders`, () => {
      const entries = gateEntries(profileId)
      expect(entries).toHaveLength(1)
      expect(entries[0].matcher).toBe(DESTRUCTIVE_GATE_MATCHER)
    })
  }

  it('the main agent is NOT gated, whatever the profile says', () => {
    for (const profileId of new Set(Object.values(FLEET))) {
      expect(agentGetsDestructiveGate(MAIN_AGENT_ID, loadProfileTemplate(profileId))).toBe(false)
    }
  })
})

// The deny floor (DENYARGS925, #1679), measured on the REAL rendered file of each
// agent's profile: recursive removal of the home directory and of the root is
// denied for everyone, and the marketer profile (willy) keeps the whole `rm` ban.
// This asserts the RULES in the file. That Claude Code matches them is a separate
// measurement: a probe of `sudo -n true` was denied in a live session
// (--dangerously-skip-permissions does not bypass deny); an `rm -rf <absolute>`
// probe is stopped earlier by Claude Code's own removal check, so it cannot tell
// the two apart and is NOT claimed here.
function denyRules(profileId: string): string[] {
  mkdirSync(join(root(), '.claude'), { recursive: true })
  writeAgentSettingsFromProfile(PROBE, loadProfileTemplate(profileId))
  const settings = JSON.parse(readFileSync(agentSettingsPath(PROBE), 'utf-8')) as {
    permissions?: { deny?: string[] }
  }
  return settings.permissions?.deny ?? []
}

describe('the deny floor reaches every profile the four agents run', () => {
  for (const profileId of new Set(Object.values(FLEET))) {
    it(`profile ${profileId}: rm -rf of HOME and of / is denied`, () => {
      const deny = denyRules(profileId)
      expect(deny).toContain(`Bash(rm -rf ${homedir()}:*)`)
      expect(deny).toContain('Bash(rm -rf /:*)')
      expect(deny).toContain('Bash(sudo:*)')
    })
  }

  it('willy (marketer) keeps the whole rm ban on top of the floor', () => {
    expect(denyRules('marketer')).toContain('Bash(rm:*)')
  })
})
