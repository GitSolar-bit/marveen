import { describe, it, expect, beforeEach, vi } from 'vitest'
import { initDatabase, listAgentMessages, getApproval } from '../db.js'
import type { RouteContext } from '../web/routes/types.js'
import { logger } from '../logger.js'

// PR1655 review (delta of 82694550), asks 2 and 3: the route's owner
// notification has two branches -- Telegram (kept because it records the
// message id) and every other provider (through sendOwnerMessage) -- and the
// tests so far ran the second one with TELEGRAM_BOT_TOKEN always empty. So:
//   - the Telegram branch's failure fallback could be deleted with the suite
//     green (mutant 4),
//   - the branch condition could become `if (false)` or `if (TELEGRAM_BOT_TOKEN)`
//     with the suite green (mutant 5),
//   - the no-token / no-owner-chat route branches could be deleted, the
//     fallback then firing under the wrong label (mutant 6).
// These cases pin each branch by BEHAVIOUR -- which sender ran, whether the
// in-band [OWNER_UNREACHED <reason>] row appeared -- for every provider, so
// the choice of branch is tested from both sides.

const { cfg } = vi.hoisted(() => ({
  cfg: {
    provider: 'telegram' as string,
    telegramToken: 'tg-token' as string,
    ownerChat: '111' as string | null,
    ownerResult: { sent: true } as { sent: boolean; reason?: string },
    telegramThrows: false,
    telegramError: 'Telegram API 400',
  },
}))

const ownerSends: string[] = []
vi.mock('../notify.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../notify.js')>()
  return {
    sendOwnerMessage: async (text: string) => { ownerSends.push(text); return cfg.ownerResult },
    notifyChannel: async () => {},
    notifyTelegram: async () => {},
    notifySecurityEvent: async () => {},
    scrubErrForLog: real.scrubErrForLog, // the real one: the log line of a failed send is pinned below
  }
})

const telegramSends: unknown[][] = []
vi.mock('../web/telegram.js', () => ({
  sendTelegramMessage: async (...args: unknown[]) => {
    telegramSends.push(args)
    if (cfg.telegramThrows) throw new Error(cfg.telegramError)
    return 42
  },
}))

// The Telegram branch resolves the owner through resolveOwnerChatId, which
// would otherwise read this machine's real access.json.
vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  return { ...real, resolveOwnerChatId: () => cfg.ownerChat }
})

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return {
    ...real,
    MAIN_AGENT_ID: 'fo-agens',
    get CHANNEL_PROVIDER() { return cfg.provider },
    get TELEGRAM_BOT_TOKEN() { return cfg.telegramToken },
  }
})

const { tryHandleApprovals } = await import('../web/routes/approvals.js')

function fakePost(path: string, body: unknown): { ctx: RouteContext; out: { status: number; body: any } } {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const url = new URL(`http://localhost:3420${path}`)
  const bodyStr = JSON.stringify(body)
  const req: any = {
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(Buffer.from(bodyStr))
      if (event === 'end') cb()
    },
  }
  return { ctx: { req, res, path: url.pathname, method: 'POST', url } as RouteContext, out }
}

/** The in-band fallback rows, as the main agent would receive them. */
function ownerUnreached(): string[] {
  return listAgentMessages(100).map((m) => m.content).filter((c) => c.includes('[OWNER_UNREACHED'))
}

async function kerest() {
  const { ctx, out } = fakePost('/api/approvals', {
    agent_id: 'fo-agens',
    category: 'email_send',
    action_description: 'proba',
    timeout_seconds: 600,
  })
  await tryHandleApprovals(ctx)
  await new Promise((r) => setTimeout(r, 0))
  expect(out.status).toBe(201)
  return out
}

beforeEach(() => {
  initDatabase(':memory:')
  ownerSends.length = 0
  telegramSends.length = 0
  cfg.provider = 'telegram'
  cfg.telegramToken = 'tg-token'
  cfg.ownerChat = '111'
  cfg.ownerResult = { sent: true }
  cfg.telegramThrows = false
})

describe('a Telegram install: the Telegram branch, with its own fallback', () => {
  // Mutant 5a, `if (false)`: the request would still reach the owner through
  // sendOwnerMessage, but without the message id the reply-to-approve link is gone.
  it('a delivered send goes through sendTelegramMessage and records the message id', async () => {
    const out = await kerest()
    expect(telegramSends).toHaveLength(1)
    expect(telegramSends[0][1]).toBe('111')
    expect(ownerSends).toHaveLength(0)
    expect(getApproval(out.body.id)?.telegram_message_id).toBe(42)
    expect(ownerUnreached()).toHaveLength(0)
  })

  // Mutant 4: the Telegram branch's `fallbackInBand(approval, 'send-failed')` removed.
  it('a FAILED Telegram send falls back in band as send-failed', async () => {
    cfg.telegramThrows = true
    await kerest()
    expect(telegramSends).toHaveLength(1)
    const rows = ownerUnreached()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toContain('[OWNER_UNREACHED send-failed]')
  })

  // Card 9964813a (Sam 2775, the class of fdd71470): the log line of the failed send carries the scrubbed MESSAGE, a string. The chat id is not
  // numeric here on purpose (a long-digit rule cannot mask it): only the chat id ARGUMENT of the scrub does.
  it('a FAILED Telegram send logs the scrubbed message, not the Error: the token shape, the chat id and a user id are masked', async () => {
    const TOKEN_SHAPE = ['123456789', 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'].join(':')
    cfg.telegramThrows = true
    cfg.ownerChat = 'C04ABCD12'
    cfg.telegramError = `Telegram API 400: channel C04ABCD12 not found at https://api.telegram.org/bot${TOKEN_SHAPE}/sendMessage user 9876543210`
    const warn = vi.spyOn(logger, 'warn')
    try {
      await kerest()
      const calls = warn.mock.calls.filter(c => String(c[1]).includes('approval owner notification FAILED'))
      expect(calls.length).toBe(1)
      const obj = calls[0][0] as { err?: unknown }
      expect(typeof obj.err).toBe('string')
      expect(obj.err).toContain('Telegram API 400')
      const all = JSON.stringify(obj)
      expect(all).not.toContain(TOKEN_SHAPE)
      expect(all).not.toContain('C04ABCD12')
      expect(all).not.toContain('9876543210')
      expect(all).not.toContain('stack')
    } finally {
      warn.mockRestore()
    }
  })

  it('no owner chat on a Telegram install: no send, in-band fallback as no-owner-chat', async () => {
    cfg.ownerChat = null
    await kerest()
    expect(telegramSends).toHaveLength(0)
    const rows = ownerUnreached()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toContain('[OWNER_UNREACHED no-owner-chat]')
  })

  it('a Telegram provider with no bot token goes through the channel funnel instead', async () => {
    cfg.telegramToken = ''
    cfg.ownerResult = { sent: false, reason: 'no-token' }
    await kerest()
    expect(telegramSends).toHaveLength(0)
    expect(ownerSends).toHaveLength(1)
    expect(ownerUnreached()[0]).toContain('[OWNER_UNREACHED no-token]')
  })
})

describe.each(['discord', 'slack', 'googlechat', 'teams'])('a %s install: the channel funnel', (provider) => {
  beforeEach(() => {
    cfg.provider = provider
    // A leftover Telegram token from an earlier setup. Mutant 5b,
    // `if (TELEGRAM_BOT_TOKEN)` (the pre-fix gate), would send this install's
    // approval requests to Telegram instead of the configured provider.
    cfg.telegramToken = 'leftover-tg-token'
  })

  it('a delivered send goes through sendOwnerMessage, never Telegram, with no fallback', async () => {
    await kerest()
    expect(ownerSends).toHaveLength(1)
    expect(telegramSends).toHaveLength(0)
    expect(ownerUnreached()).toHaveLength(0)
  })

  // Mutant 6: with the no-token / no-owner-chat branches removed, the fallback
  // still fires, but labelled send-failed -- the reason has to survive.
  it.each(['no-token', 'no-owner-chat', 'send-failed', 'partial'])(
    'a %s result falls back in band under the right label',
    async (reason) => {
      cfg.ownerResult = { sent: false, reason }
      await kerest()
      const rows = ownerUnreached()
      expect(rows).toHaveLength(1)
      // partial has no branch of its own: half a notification is a failed send
      expect(rows[0]).toContain(`[OWNER_UNREACHED ${reason === 'partial' ? 'send-failed' : reason}]`)
    },
  )
})
