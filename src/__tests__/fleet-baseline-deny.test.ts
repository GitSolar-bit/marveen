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
// Two branches are pinned here, because they are two different mechanisms:
//   (A) sub-agents  -> the code-level floor in writeAgentSettingsFromProfile
//   (B) main agent  -> the repo's tracked project settings (.claude/settings.json),
//       which the scaffold deliberately never writes (#1305).
import { writeAgentSettingsFromProfile, agentSettingsPath, FLEET_BASELINE_DENY } from '../web/agent-scaffold.js'
import { agentDir } from '../web/agent-config.js'
import { listProfileTemplates, loadProfileTemplate, resolveProfilePlaceholders } from '../web/profiles.js'
import { PROJECT_ROOT } from '../config.js'

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

  it('pairs every command-NAME rule with its absolute-path form', () => {
    // DENYARGS925: a command-name deny holds against an inserted prefix word
    // (`command sudo ...`) but NOT against an absolute path -- `/usr/bin/sudo -n
    // true` ran on a list that carried Bash(sudo:*). The network rules always had
    // a `*/` partner; sudo and rm did not. This pins that they keep one, so the
    // pairing cannot be dropped in a later tidy-up.
    for (const name of ['sudo', 'rm']) {
      expect(FLEET_BASELINE_DENY).toContain(`Bash(${name}:*)`)
      expect(FLEET_BASELINE_DENY).toContain(`Bash(*/${name} *)`)
    }
  })

  it('pairs the force-push rules with the absolute-path form too', () => {
    // The git rules are shaped differently from sudo/rm -- the name rule carries
    // a SUBCOMMAND (`git push --force`), so its partner cannot be
    // `Bash(*/git push --force *)`: that is still a leading-word match and the
    // absolute path moves the words. The partner is the broad `Bash(*/git *)`,
    // which is why it is pinned separately from the sudo/rm loop above.
    expect(FLEET_BASELINE_DENY).toContain('Bash(git push --force:*)')
    expect(FLEET_BASELINE_DENY).toContain('Bash(git push -f:*)')
    expect(FLEET_BASELINE_DENY).toContain('Bash(*/git *)')
  })

  it('the comment names the force-push limit, so the list cannot be read as cover', () => {
    // This is the finding that prompted the pairing (Sam, 2026-09-25): the block
    // comment LISTS the weak rules by name and, before this change, left the two
    // git lines out -- so a reader approving the list read them as protection.
    // The measured limit therefore has to survive a later tidy-up, which is what
    // this pins. `git -C <path> push --force` RAN with the pair installed
    // (measured by HEX, with a control in both directions).
    const src = readFileSync(join(PROJECT_ROOT, 'src/web/agent-scaffold.ts'), 'utf-8')
    const start = src.indexOf('The fleet-wide deny FLOOR')
    const end = src.indexOf('export const FLEET_BASELINE_DENY')
    expect(start).toBeGreaterThan(0)
    expect(end).toBeGreaterThan(start)
    const comment = src.slice(start, end)
    expect(comment).toContain('git -C <path> push --force')
    expect(comment).toContain('NARROWED')
    expect(comment).toContain('NOT fixable by a better pattern')
  })

  it('keeps the egress rules and the profile\'s own rules alongside the baseline', () => {
    writeAgentSettingsFromProfile(NAME, loadProfileTemplate('developer-senior'))
    const deny = readDeny()
    expect(deny).toContain('Bash(wget *)')
    expect(deny).toContain('Bash(*/wget *)')
    expect(deny).toContain('ScheduleWakeup')
  })
})

describe('(B) the main agent gets the baseline from the repo project settings', () => {
  // The scaffold refuses to write the main agent's settings (#1305), so the
  // main agent's floor cannot come from (A). It ships in the repo instead.
  const settingsPath = join(PROJECT_ROOT, '.claude', 'settings.json')
  const settings = JSON.parse(readFileSync(settingsPath, 'utf-8'))

  it('carries every baseline rule in its home-relative (~) form', () => {
    const deny: string[] = settings.permissions?.deny ?? []
    for (const rule of FLEET_BASELINE_DENY) {
      // ${HOME} is not expanded when Claude Code reads this file, so the shipped
      // form uses '~', which is MEASURED to match (TMPLPERM908).
      expect(deny).toContain(rule.replace('${HOME}', '~'))
    }
  })

  it('ships the absolute-path partners too, not only the command names', () => {
    const deny: string[] = settings.permissions?.deny ?? []
    for (const name of ['sudo', 'rm']) {
      expect(deny).toContain(`Bash(${name}:*)`)
      expect(deny).toContain(`Bash(*/${name} *)`)
    }
    // The force-push partner has a different shape (see the (A) case above), so
    // it is pinned by name rather than through the loop.
    expect(deny).toContain('Bash(*/git *)')
  })

  it('never hardcodes a developer machine home into the shipped file', () => {
    const deny: string[] = settings.permissions?.deny ?? []
    for (const rule of deny) {
      expect(rule).not.toMatch(/\/(?:home|Users)\//)
    }
  })

  it('adds permissions ALONGSIDE the existing keys, it does not replace them', () => {
    expect(settings.enabledPlugins).toBeTruthy()
    expect(settings.hooks).toBeTruthy()
    expect(Object.keys(settings.hooks).length).toBeGreaterThan(0)
  })
})
