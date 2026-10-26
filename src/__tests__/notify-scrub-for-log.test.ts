/**
 * Card fdd71470 (Sam 5629, round 2): notify.ts scrubForLog / scrubErrForLog are what every failed-channel-send log line puts between a
 * provider's error text and the log. The provider's error text is not under our control: the configured token, the chat id or a long digit
 * run can end up in it. No provider error is MEASURED to carry the bot URL, so the fixtures below are a defensive worst case, not a
 * measured shape, and this is hygiene, not a known leak.
 */
import { describe, it, expect, vi } from 'vitest'

vi.mock('../config.js', async (orig) => ({
  ...(await orig<typeof import('../config.js')>()),
  CHANNEL_TOKEN: 'bot-token-SECRET',
}))

import { scrubForLog, scrubErrForLog } from '../notify.js'

// assembled from pieces, so secret scanning does not take the fixture for a live token
const TOKEN_SHAPE = ['123456789', 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'].join(':')

describe('scrubForLog', () => {
  it('masks a bot-token shape, the chat id and long digit runs', () => {
    const out = scrubForLog(`x ${TOKEN_SHAPE} 5040302010 user 9876543210 ok`, '5040302010')
    expect(out).not.toContain(TOKEN_SHAPE)
    expect(out).not.toContain('123456789')
    expect(out).not.toMatch(/\d{7,}/)
    expect(out).toContain('ok')
  })

  it('masks the CONFIGURED token itself, whatever shape it has (it is not a digits:secret token here)', () => {
    const out = scrubForLog('Telegram API 401: bad token bot-token-SECRET given', 'x')
    expect(out).not.toContain('bot-token-SECRET')
    expect(out).toContain('<redacted>')
    expect(out).toContain('Telegram API 401')
  })

  it('masks a bot-token shape that is NOT the configured token (the shape rule stands on its own)', () => {
    expect(scrubForLog(`at https://api.telegram.org/bot${TOKEN_SHAPE}/sendMessage`, 'x')).toBe('at https://api.telegram.org/bot<token>/sendMessage')
  })

  it('masks a short, non-numeric chat id passed in by the caller, and leaves plain words alone', () => {
    expect(scrubForLog('channel_not_found for C04ABCD12', 'C04ABCD12')).toBe('channel_not_found for <redacted>')
  })
})

describe('scrubErrForLog', () => {
  it('an Error: its message, masked; no stack', () => {
    const out = scrubErrForLog(new Error(`Telegram API 400: at /bot${TOKEN_SHAPE}/sendMessage chat 5040302010 user 9876543210`), '5040302010')
    expect(out).toContain('Telegram API 400')
    expect(out).not.toContain(TOKEN_SHAPE)
    expect(out).not.toContain('5040302010')
    expect(out).not.toContain('9876543210')
    expect(out).not.toContain('\n    at ')
  })

  it('the chat id it is given is the one it masks: a non-numeric one too (Slack)', () => {
    expect(scrubErrForLog(new Error('channel_not_found for C04ABCD12'), 'C04ABCD12')).toBe('channel_not_found for <redacted>')
  })

  it('a non-Error throw is stringified, not lost', () => {
    expect(scrubErrForLog('boom 1234567', 'x')).toBe('boom <id>')
    expect(scrubErrForLog(undefined, 'x')).toBe('undefined')
  })
})
