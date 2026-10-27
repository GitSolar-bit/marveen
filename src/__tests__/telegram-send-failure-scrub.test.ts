/**
 * Card 9964813a (Sam 2775, the class of fdd71470): the log lines that report a FAILED CHANNEL SEND in telegram.ts (welcome message, Marveen
 * avatar change, agent avatar change, Marveen alert), routes/approvals.ts (the owner notification) and command-task.ts (the alert) take the
 * scrubbed message, a string, never the caught Error. A logger serialises an Error with its message AND its stack, unmasked, and the provider's
 * error text is not under our control: the configured token, the chat id or a long digit run can end up in it. No provider error is MEASURED to
 * carry the bot URL, so this is hygiene, not a known leak.
 *
 * The four telegram.ts senders run for real against a stubbed fetch (behaviour); the approvals.ts site is behavioural in
 * approvals-owner-notify-branches.test.ts; command-task.ts's alert is private, so the source of all three files is pinned here as well: every
 * catch that follows a sendTelegramMessage / sendTelegramPhoto call logs `err: scrubErrForLog(err, <chat>)`, at any log level.
 */
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest'
import { mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

// The agents folder is a constant of agent-config.ts, computed when that module loads: the root exists from the start and the cases fill it.
const { state } = await vi.hoisted(async () => {
  const { mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  return { state: { root: mkdtempSync(join(tmpdir(), 'tgscrub-')), chat: '42424' } }
})

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return { ...real, get PROJECT_ROOT() { return state.root }, get AGENTS_BASE_DIR() { return join(state.root, 'agents') } }
})
vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  return { ...real, resolveOwnerChatId: () => state.chat }
})

const { logger } = await import('../logger.js')
const tg = await import('../web/telegram.js')

const TOKEN_SHAPE = ['123456789', 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'].join(':')
const CHAT = '42424' // five digits: only the explicit chat id argument masks it, the long-digit rule does not
const USER = '9876543210'

describe('telegram.ts: a failed send reaches the log scrubbed, as a string', () => {
  let root: string
  let warn: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    root = state.root
    state.chat = CHAT
    writeFileSync(join(root, '.env'), `TELEGRAM_BOT_TOKEN=${TOKEN_SHAPE}\n`)
    mkdirSync(join(root, 'agents', 'zed', '.claude', 'channels', 'telegram'), { recursive: true })
    writeFileSync(join(root, 'agents', 'zed', '.claude', 'channels', 'telegram', '.env'), `TELEGRAM_BOT_TOKEN=${TOKEN_SHAPE}\n`)
    writeFileSync(join(root, 'avatar.png'), 'x')
    vi.stubGlobal('fetch', vi.fn(async () => new Response(`Bad Request: chat ${CHAT} not found at https://api.telegram.org/bot${TOKEN_SHAPE}/sendMessage user ${USER}`, { status: 400 })))
    warn = vi.spyOn(logger, 'warn')
  })

  afterEach(() => {
    warn.mockRestore()
    vi.unstubAllGlobals()
    for (const f of ['.env', 'agents', 'avatar.png']) rmSync(join(root, f), { recursive: true, force: true })
  })

  afterAll(() => rmSync(state.root, { recursive: true, force: true }))

  /** The one log line with an err field that the failed send produced. */
  function errLine(message: string): { err?: unknown } {
    const calls = warn.mock.calls.filter((c: unknown[]) => String(c[1]) === message)
    expect(calls.length).toBe(1)
    return calls[0][0] as { err?: unknown }
  }

  function expectScrubbed(obj: { err?: unknown }) {
    expect(typeof obj.err).toBe('string')
    expect(obj.err).toContain('Telegram API 400') // the status the operator needs survives
    const all = JSON.stringify(obj)
    expect(all).not.toContain(TOKEN_SHAPE)
    expect(all).not.toContain(CHAT)
    expect(all).not.toContain(USER)
    expect(all).not.toContain('stack')
  }

  it('sendWelcomeMessage', async () => {
    await tg.sendWelcomeMessage('zed', TOKEN_SHAPE)
    expectScrubbed(errLine('Failed to send welcome message'))
  })

  it('sendMarveenAvatarChange', async () => {
    await tg.sendMarveenAvatarChange(join(root, 'avatar.png'))
    expectScrubbed(errLine('Failed to send Marveen avatar change message'))
  })

  it('sendAvatarChangeMessage', async () => {
    await tg.sendAvatarChangeMessage('zed', join(root, 'avatar.png'))
    expectScrubbed(errLine('Failed to send avatar change message'))
  })

  it('sendMarveenAlert', async () => {
    await tg.sendMarveenAlert('proba')
    expectScrubbed(errLine('Failed to send marveen plugin alert'))
  })
})

describe('the send catch blocks of telegram.ts, routes/approvals.ts and command-task.ts never log the Error object', () => {
  const FILES: Array<[string, string, number]> = [
    ['telegram.ts', join(__dirname, '..', 'web', 'telegram.ts'), 4],
    ['approvals.ts', join(__dirname, '..', 'web', 'routes', 'approvals.ts'), 1],
    ['command-task.ts', join(__dirname, '..', 'web', 'command-task.ts'), 1],
  ]

  /** [log object text] of the first logger call behind the catch that follows each send call (one per catch, however many sends it wraps). */
  function sendCatchLogs(src: string): string[] {
    const out: string[] = []
    const seen = new Set<number>()
    for (const m of src.matchAll(/(?<!function )\bsendTelegram(?:Message|Photo)\(/g)) {
      const at = [src.indexOf('catch (err)', m.index), src.indexOf('.catch((err)', m.index)].filter(x => x >= 0).sort((a, b) => a - b)[0]
      if (at === undefined || seen.has(at)) continue
      seen.add(at)
      const log = /logger\.(?:warn|error|info|debug)\(\{([^}]*)\}/.exec(src.slice(at))
      out.push(log ? log[1] : '')
    }
    return out
  }

  for (const [name, path, expected] of FILES) {
    it(`${name}: ${expected} send catch block(s), each logging a scrubbed err`, () => {
      const logs = sendCatchLogs(readFileSync(path, 'utf8'))
      expect(logs.length).toBe(expected) // a rename must not silently empty this pin
      for (const body of logs) expect(body).toMatch(/\berr: scrubErrForLog\(err, \w+\)/)
    })
  }
})
