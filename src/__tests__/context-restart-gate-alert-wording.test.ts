/**
 * RIASZTALLIT924 (card cdcedd77). The persistent-block alert past 120 minutes used to say "the same reason for
 * N minutes, so this will probably not clear by itself". N is the time the context stayed above the threshold
 * (nextBlockClock), not the time the reason stayed the same; HEX measured 16 gaps over 120 s in one day inside
 * a 5.9-hour streak (the reason cannot have been continuous), and a premise nobody measured made an alert call
 * for action. The sentence now claims what the clock measures, and says how many sweeps of the streak could not
 * be measured (a fresh session reads null for about a minute, and the clock runs through those).
 */
import { describe, it, expect, vi } from 'vitest'

// the run-state file lives under PROJECT_ROOT/store: point it at a throwaway directory, never the real store
const { root } = vi.hoisted(() => ({ root: { dir: '' } }))
vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  const { mkdtempSync, mkdirSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  root.dir = mkdtempSync(join(tmpdir(), 'gate-alert-wording-'))
  mkdirSync(join(root.dir, 'store'), { recursive: true })
  return { ...actual, PROJECT_ROOT: root.dir }
})
import { blockAlertEscalation, nextUnmeasuredTicks, nextBlockClock } from '../context-restart-gate.js'
import { readGateRunState, writeGateRunState, stateAfterClear } from '../web/context-restart-gate-store.js'

const REASON = 'transcript-active (12s since last write, need 120s)'

describe('blockAlertEscalation', () => {
  it('is empty below the threshold of minutes, and for an unknown streak length', () => {
    expect(blockAlertEscalation(119, REASON, 0, 120)).toBe('')
    expect(blockAlertEscalation(0, REASON, 5, 120)).toBe('')
    expect(blockAlertEscalation('?', REASON, 5, 120)).toBe('')
  })

  it('past the threshold it claims the THRESHOLD streak, names the reason as the current one, and makes no persistence claim', () => {
    const t = blockAlertEscalation(240, REASON, 0, 120)
    expect(t).toContain('a kontextus 240 perce folyamatosan a kuszob folott all')
    expect(t).toContain(`A mostani ok (${REASON}) nem biztos, hogy ennyi ideje ugyanaz`)
    expect(t).toContain('az ok valtozasat nem koveti')
    // the false claims of the old wording
    expect(t).not.toContain('ugyanez az ok')
    expect(t).not.toContain('NEM fog megszunni')
    expect(t).not.toContain('magatol')
  })

  it('names the unmeasured sweeps when there were some, and says nothing about them when there were none', () => {
    expect(blockAlertEscalation(240, REASON, 3, 120)).toContain('A(z) 240 percbol 3 ellenorzesnel nem volt kontextus-meres')
    expect(blockAlertEscalation(240, REASON, 0, 120)).not.toContain('nem volt kontextus-meres')
  })

  it('the threshold itself escalates (>=)', () => {
    expect(blockAlertEscalation(120, REASON, 0, 120)).toContain('FIGYELEM')
  })
})

describe('nextUnmeasuredTicks -- the sweeps the clock ran through without a reading', () => {
  const THRESHOLD = 100_000
  it('counts a sweep with no reading while a streak is running', () => {
    const clock = nextBlockClock(1000, null, THRESHOLD, 5000)
    expect(clock).toBe(1000)   // the clock hands its old value back, that is the point
    expect(nextUnmeasuredTicks(2, null, clock)).toBe(3)
  })
  it('leaves the count alone on a measured sweep above the threshold', () => {
    expect(nextUnmeasuredTicks(2, THRESHOLD + 1, nextBlockClock(1000, THRESHOLD + 1, THRESHOLD, 5000))).toBe(2)
  })
  it('zeroes it when the streak ends (a reading below the threshold clears the clock)', () => {
    expect(nextUnmeasuredTicks(9, THRESHOLD - 1, nextBlockClock(1000, THRESHOLD - 1, THRESHOLD, 5000))).toBe(0)
  })
  it('does not count when no streak is running (a fresh session before its first reading)', () => {
    expect(nextUnmeasuredTicks(0, null, nextBlockClock(null, null, THRESHOLD, 5000))).toBe(0)
  })
})

describe('the run-state store keeps the count', () => {
  it('a state without the field (written before this change) reads as 0; a written count reads back; garbage reads as 0', () => {
    const name = `alert-wording-${process.pid}`
    expect(readGateRunState(name).unmeasuredTicks).toBe(0)
    writeGateRunState(name, { firstBlockedAt: 1000, lastAlertAt: null, lastClearAt: null, pendingWakeAt: null, unmeasuredTicks: 4 })
    expect(readGateRunState(name).unmeasuredTicks).toBe(4)
    writeGateRunState(name, { firstBlockedAt: 1000, lastAlertAt: null, lastClearAt: null, pendingWakeAt: null, unmeasuredTicks: -3 })
    expect(readGateRunState(name).unmeasuredTicks).toBe(0)
  })
})

describe('stateAfterClear', () => {
  it('ends the streak, zeroes the unmeasured count, stamps the clear and owes the wake nudge; the alert time survives', () => {
    const prev = { firstBlockedAt: 1000, lastAlertAt: 2000, lastClearAt: null, pendingWakeAt: null, unmeasuredTicks: 9 }
    expect(stateAfterClear(prev, 777_000)).toEqual({
      firstBlockedAt: null, lastAlertAt: 2000, lastClearAt: 777_000, pendingWakeAt: 777_000, unmeasuredTicks: 0,
    })
  })
})
