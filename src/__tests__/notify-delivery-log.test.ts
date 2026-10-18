/**
 * ALERTVAK923 (card c1445b93): an alert's delivery used to leave no trace. sendAlert swallowed any rejection
 * with `.catch(() => {})`, a Telegram chunk that failed twice was dropped in a `/* give up *\/` catch, and a
 * delivered alert logged nothing, so "did it go out?" could only be answered by the owner's eyes (measured
 * 2026-09-23 on the STUCKALLCLEAR923 closing message: dashboard.log showed the decision, never the send).
 * Now one line per send: info when it went out, error when it did not, warn when sendAlert itself caught
 * an exception. The lines carry a short preview, never the chat id or the token.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const { cfg, mockSend, log, settings, split } = vi.hoisted(() => ({
  cfg: { token: 'bot-token-SECRET', chatId: '5040302010' },
  mockSend: vi.fn(async (..._a: unknown[]) => {}),
  log: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
  settings: {} as Record<string, string>,
  split: { fn: (t: string) => [t] },
}))

vi.mock('../config.js', () => ({
  get CHANNEL_PROVIDER() { return 'telegram' },
  get CHANNEL_TOKEN() { return cfg.token },
  get CHANNEL_CHAT_ID() { return cfg.chatId },
  get ALLOWED_CHAT_ID() { return cfg.chatId },
  get ALERT_CHAT_ID() { return '' },
  MAIN_AGENT_ID: 'marveen',
  PROJECT_ROOT: '/tmp/notify-delivery-log',
}))
vi.mock('../channel-provider.js', () => ({
  getProvider: () => ({ formatMessage: (t: string) => t, splitMessage: (t: string) => split.fn(t), sendMessage: mockSend }),
  channelStateDir: () => '/tmp/notify-delivery-log/none',
}))
vi.mock('../logger.js', () => ({ logger: log }))
vi.mock('../test-run-marker.js', () => ({ markIfTestRun: (t: string) => t }))
vi.mock('../settings-store.js', () => ({ getEffectiveSettingValue: (k: string) => settings[k] ?? '' }))

import { notifyChannel, notifyOwner, deliverWithSlack } from '../notify.js'

const logged = (fn: ReturnType<typeof vi.fn>) => fn.mock.calls.map((c) => ({ obj: c[0] as Record<string, unknown>, msg: String(c[1]) }))

beforeEach(() => {
  for (const f of [mockSend, log.info, log.warn, log.error, log.debug]) f.mockReset()
  mockSend.mockImplementation(async () => {})
  split.fn = (t: string) => [t]
  cfg.token = 'bot-token-SECRET'
  for (const k of Object.keys(settings)) delete settings[k]
})

describe('notifyChannel logs its outcome', () => {
  it('a delivered alert leaves an info line with a preview, and nothing secret', async () => {
    await notifyChannel('A  fo   session\nbemenete beragadt')
    const rows = logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')
    expect(rows).toHaveLength(1)
    expect(rows[0].obj).toMatchObject({ provider: 'telegram', chunks: 1, plainFallback: 0, preview: 'A fo session bemenete beragadt' })
    const everything = JSON.stringify([log.info.mock.calls, log.warn.mock.calls, log.error.mock.calls])
    expect(everything).not.toContain('bot-token-SECRET')
    expect(everything).not.toContain('5040302010')
    expect(log.error).not.toHaveBeenCalled()
  })

  it('the formatted send fails but the plain retry goes out: delivered, and the fallback is counted', async () => {
    mockSend.mockImplementationOnce(async () => { throw new Error('can\'t parse entities') })
    await notifyChannel('alert <b>')
    expect(logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')[0].obj).toMatchObject({ chunks: 1, plainFallback: 1 })
    expect(log.error).not.toHaveBeenCalled()
  })

  it('NEGATIVE CONTROL: both attempts fail -> an ERROR line naming the loss, and NO "elkuldve" line', async () => {
    mockSend.mockImplementation(async () => { throw new Error('403 bot was blocked') })
    await notifyChannel('a riasztas amit nem kapott meg senki')
    const err = logged(log.error)
    expect(err).toHaveLength(1)
    expect(err[0].msg).toContain('ELVESZETT')
    expect(err[0].obj).toMatchObject({ chunks: 1, failed: 1, err: '403 bot was blocked', preview: 'a riasztas amit nem kapott meg senki' })
    expect(logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')).toHaveLength(0)
  })

  it('a long alert in two chunks, one of them lost: the line counts 2 chunks and 1 failed', async () => {
    split.fn = (t: string) => [t.slice(0, 5), t.slice(5)]
    let n = 0
    mockSend.mockImplementation(async () => { n++; if (n >= 2) throw new Error('flood') })   // chunk 2, both attempts
    await notifyChannel('0123456789')
    expect(logged(log.error)[0].obj).toMatchObject({ chunks: 2, failed: 1 })
  })

  it('no token: skipped as before, with its own warn and no delivery line', async () => {
    cfg.token = ''
    await notifyChannel('x')
    expect(mockSend).not.toHaveBeenCalled()
    expect(logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')).toHaveLength(0)
  })
})

describe('deliverWithSlack logs a Slack send that went out', () => {
  it('Slack ok -> an info line with the target and kind; Slack failed -> no such line (the existing warn stays)', async () => {
    settings.NOTIFY_SLACK_TARGET = 'dm'
    await deliverWithSlack('alert', 'hello', async () => {}, (async () => ({ ok: true })) as never)
    expect(logged(log.info).filter((r) => r.msg === 'Slack ertesites elkuldve')[0].obj).toMatchObject({ target: 'dm', kind: 'alert' })
    log.info.mockClear()
    await deliverWithSlack('alert', 'hello', async () => {}, (async () => ({ ok: false, error: 'boom' })) as never)
    expect(logged(log.info).filter((r) => r.msg === 'Slack ertesites elkuldve')).toHaveLength(0)
    expect(logged(log.warn).some((r) => r.msg.includes('nem ment ki'))).toBe(true)
  })
})

// Sam 3550: (1) the plain-text fallback re-sends the HEAD of the whole message, so a multi-chunk alert whose
// later chunk needed it is NOT known to have gone out; (2) the log is read by the whole fleet: owner-facing
// content gets no preview, and an alert's preview and a provider's error text are scrubbed of ids and tokens.
describe('partial delivery, previews and what may reach the log (Sam 3550)', () => {
  it('a multi-chunk alert whose second chunk needed the plain fallback is logged as PARTIAL (warn), not as delivered', async () => {
    split.fn = (t: string) => [t.slice(0, 5), t.slice(5)]
    let n = 0
    mockSend.mockImplementation(async () => { n++; if (n === 2) throw new Error('can\'t parse entities') })  // chunk 2, formatted attempt only
    await notifyChannel('0123456789')
    expect(logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')).toHaveLength(0)
    const warn = logged(log.warn).filter((r) => r.msg.includes('RESZBEN'))
    expect(warn).toHaveLength(1)
    expect(warn[0].obj).toMatchObject({ chunks: 2, plainFallback: 1 })
    expect(log.error).not.toHaveBeenCalled()
  })

  it('CONTROL: a single-chunk alert that needed the plain fallback is complete, so it stays an info line', async () => {
    mockSend.mockImplementationOnce(async () => { throw new Error('can\'t parse entities') })
    await notifyChannel('short alert')
    expect(logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')[0].obj).toMatchObject({ chunks: 1, plainFallback: 1 })
    expect(logged(log.warn).filter((r) => r.msg.includes('RESZBEN'))).toHaveLength(0)
  })

  it('owner-facing content (notifyOwner) leaves NO preview in the log, success or failure', async () => {
    await notifyOwner('Napi osszefoglalo: a break-glass jelszo-visszaallitas a gazda nevu felhasznalohoz')
    const ok = logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')
    expect(ok).toHaveLength(1)
    expect('preview' in ok[0].obj && ok[0].obj.preview !== undefined).toBe(false)
    mockSend.mockImplementation(async () => { throw new Error('boom') })
    await notifyOwner('titkos tulajdonosi szoveg')
    const err = logged(log.error)
    expect(err).toHaveLength(1)
    expect(err[0].obj.preview).toBeUndefined()
    expect(JSON.stringify([log.info.mock.calls, log.error.mock.calls])).not.toContain('titkos')
    expect(JSON.stringify([log.info.mock.calls, log.error.mock.calls])).not.toContain('break-glass')
  })

  it('an alert whose text carries a chat id or a token shape is masked in the preview', async () => {
    await notifyChannel('A 5040302010 chat, 9988776655 user, bot 1234567890:AAH-abcdefghijklmnopqrstuvwxyz0123456 hibaja')
    const row = logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')[0]
    expect(row.obj.preview).toContain('<redacted>')   // the configured chat id
    expect(row.obj.preview).toContain('<id>')         // any other long id
    expect(String(row.obj.preview)).not.toContain('9988776655')
    expect(JSON.stringify(log.info.mock.calls)).not.toContain('5040302010')
    expect(JSON.stringify(log.info.mock.calls)).not.toContain('AAH-abcdef')
  })

  // Sam 3566 (P5): the 80-character cut ran BEFORE the masking, so a token on the boundary lost its tail and the
  // 9-character head that was left no longer looked like a token.
  it('a token that straddles the 80th character is masked whole, not cut and then left half-visible', async () => {
    const token = '1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'
    const lead = 'x'.repeat(80 - 'bot '.length - 14)   // the token starts 14 characters before the cut
    await notifyChannel(`${lead}bot ${token} vege`)
    const row = logged(log.info).filter((r) => r.msg === 'Channel ertesites elkuldve')[0]
    const preview = String(row.obj.preview)
    expect(preview.length).toBeLessThanOrEqual(80)
    expect(preview).toContain('<token>')
    expect(preview).not.toContain('AAHd')
    expect(preview).not.toContain('1234567890')
  })

  it('a provider error that carries the token or the chat id is masked in the error line', async () => {
    mockSend.mockImplementation(async () => { throw new Error('POST https://api.telegram.org/botbot-token-SECRET/sendMessage chat 5040302010 failed') })
    await notifyChannel('an alert')
    const e = logged(log.error)[0].obj
    expect(String(e.err)).not.toContain('bot-token-SECRET')
    expect(String(e.err)).not.toContain('5040302010')
    expect(String(e.err)).toContain('<redacted>')
  })
})
