/**
 * Card fdd71470 (Sam 5629, the class of 805e4938): the log lines in schedule-runner.ts that report a FAILED CHANNEL SEND take the
 * scrubbed message (a string), never the caught Error object. A logger serialises an Error with its message AND its stack, and the
 * provider's error text is not under our control: the configured token, the chat id or a long digit run can end up in it. No
 * provider error is MEASURED to carry the bot URL, so this is hygiene, not a known leak.
 *
 * The senders are private and only reachable through the scheduler tick, so this pins the SOURCE of the four catch blocks that wrap
 * sendSchedulerAlertMessage (catch-up summary, pending-retry with its transient + permanent lines, task-timeout, usage-limit notice: five log
 * lines) and keeps the scrub function's
 * own behaviour as a behavioural case. The midturn-commands sites are behavioural, in midturn-commands.test.ts.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { scrubErrForLog } from '../notify.js'

const SRC = readFileSync(join(__dirname, '..', 'web', 'schedule-runner.ts'), 'utf8')

/** The catch blocks that directly follow an `await sendSchedulerAlertMessage(` (each in its own try). */
function catchBlocksAfterAlertSend(): string[] {
  const out: string[] = []
  let from = 0
  for (;;) {
    const at = SRC.indexOf('await sendSchedulerAlertMessage(token, ownerChat, text)', from)
    if (at < 0) break
    const c = SRC.indexOf('} catch (err) {', at)
    const end = SRC.indexOf('\n  })()', c)
    out.push(SRC.slice(c, end))
    from = at + 10
  }
  return out
}

describe('schedule-runner: a failed alert send never logs the Error object', () => {
  const blocks = catchBlocksAfterAlertSend()

  it('finds all four alert senders (a rename must not silently empty this pin)', () => {
    expect(blocks.length).toBe(4)
  })

  it('every logger call in those catch blocks that has an err field scrubs it', () => {
    let seen = 0
    for (const b of blocks) {
      for (const m of b.matchAll(/logger\.warn\(\{([^}]*)\}/g)) {
        if (!/\berr\b/.test(m[1])) continue
        seen++
        expect(m[1], m[0]).toMatch(/err: scrubErrForLog\(err, ownerChat\)/)
      }
    }
    expect(seen).toBe(5) // catch-up summary, retry transient, retry permanent, task-timeout, usage-limit notice
  })
})

describe('scrubErrForLog', () => {
  const TOKEN_SHAPE = ['123456789', 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'].join(':')
  it('an Error: its message, masked; no stack', () => {
    const out = scrubErrForLog(new Error(`Telegram API 400: at /bot${TOKEN_SHAPE}/sendMessage chat 5040302010 user 9876543210`), '5040302010')
    expect(out).toContain('Telegram API 400')
    expect(out).not.toContain(TOKEN_SHAPE)
    expect(out).not.toContain('5040302010')
    expect(out).not.toContain('9876543210')
    expect(out).not.toContain('\n    at ')
  })
  it('a non-Error throw is stringified, not lost', () => {
    expect(scrubErrForLog('boom 1234567', 'x')).toBe('boom <id>')
    expect(scrubErrForLog(undefined, 'x')).toBe('undefined')
  })
})
