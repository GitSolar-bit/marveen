import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

// DENYARGS925 (measured 2026-09-25): permissions.deny is rebuilt WHOLESALE from
// the security profile on every spawn, so a rule that lives in ONE profile is
// not a floor. Before this baseline, a default-profile agent (sam) sat at 16
// rules while a developer-senior one sat at 24, and the hand-edited lists on
// willy and zola would have lost 5 and 9 rules at their next restart.
//
// This file pins branch (A): the code-level floor in writeAgentSettingsFromProfile,
// which covers every SUB-agent. The main agent is a separate mechanism (the
// scaffold deliberately never writes its settings, #1305) and lands in the next
// commit.
import { writeAgentSettingsFromProfile, agentSettingsPath, FLEET_BASELINE_DENY } from '../web/agent-scaffold.js'
import { agentDir } from '../web/agent-config.js'
import { listProfileTemplates, loadProfileTemplate, resolveProfilePlaceholders } from '../web/profiles.js'

const NAME = 'fleet-baseline-test-agent'
const DIR = agentDir(NAME)

function readDeny(): string[] {
  return JSON.parse(readFileSync(agentSettingsPath(NAME), 'utf-8')).permissions.deny as string[]
}
function expectedFor(agent: string): string[] {
  const ctx = { HOME: homedir(), AGENT_DIR: agentDir(agent) }
  return FLEET_BASELINE_DENY.map(r => resolveProfilePlaceholders(r, ctx))
}

beforeEach(() => {
  // A pre-existing dir means we are not in a clean checkout: refuse rather than
  // delete something we did not create.
  if (existsSync(DIR)) throw new Error(`refusing: ${DIR} already exists`)
  mkdirSync(DIR, { recursive: true })
  writeFileSync(join(DIR, 'agent-config.json'), JSON.stringify({}, null, 2))
})
afterEach(() => {
  rmSync(DIR, { recursive: true, force: true })
})

describe('(A) the baseline reaches EVERY profile, including ones added later', () => {
  // Iterating the directory rather than a hardcoded list is the point: a
  // profile added tomorrow is covered by this test the day it lands.
  const profiles = listProfileTemplates()

  it('finds the shipped profiles (scope check: a silent empty list would pass every case below)', () => {
    expect(profiles.length).toBeGreaterThanOrEqual(7)
  })

  for (const profile of profiles) {
    it(`profile "${profile.id}" carries the full baseline`, () => {
      writeAgentSettingsFromProfile(NAME, loadProfileTemplate(profile.id))
      const deny = readDeny()
      for (const rule of expectedFor(NAME)) expect(deny).toContain(rule)
    })
  }

  it('survives a respawn (second write) on the leanest profile', () => {
    writeAgentSettingsFromProfile(NAME, loadProfileTemplate('default'))
    writeAgentSettingsFromProfile(NAME, loadProfileTemplate('default'))
    const deny = readDeny()
    for (const rule of expectedFor(NAME)) expect(deny).toContain(rule)
  })

  it('does not duplicate a rule the profile already declares', () => {
    // marketer declares Bash(sudo:*) and Bash(rm:*) itself.
    writeAgentSettingsFromProfile(NAME, loadProfileTemplate('marketer'))
    const deny = readDeny()
    for (const rule of ['Bash(sudo:*)', 'Bash(rm:*)']) {
      expect(deny.filter(r => r === rule)).toHaveLength(1)
    }
  })

  it('keeps the egress rules and the profile\'s own rules alongside the baseline', () => {
    writeAgentSettingsFromProfile(NAME, loadProfileTemplate('developer-senior'))
    const deny = readDeny()
    expect(deny).toContain('Bash(wget *)')
    expect(deny).toContain('Bash(*/wget *)')
    expect(deny).toContain('ScheduleWakeup')
  })
})
