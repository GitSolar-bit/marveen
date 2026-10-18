/**
 * ALERTVAK923 (card c1445b93): sendAlert used to be `notifyChannel(text).catch(() => {})`. An exception that
 * notifyChannel did not handle made the alert vanish with no line anywhere. It is a warn now.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const { notify, log } = vi.hoisted(() => ({
  notify: { fn: vi.fn(async (_t: string) => {}) },
  log: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))
vi.mock('../logger.js', () => ({ logger: log }))
vi.mock('../notify.js', async () => {
  const actual = await vi.importActual<typeof import('../notify.js')>('../notify.js')
  return { ...actual, notifyChannel: (t: string) => notify.fn(t) }
})

import { sendAlert } from '../web/channel-monitor.js'

const settle = () => new Promise((r) => setTimeout(r, 10))

beforeEach(() => { notify.fn.mockReset(); notify.fn.mockImplementation(async () => {}); for (const f of Object.values(log)) f.mockReset() })

describe('sendAlert', () => {
  it('hands the text to notifyChannel and stays quiet when that succeeds', async () => {
    sendAlert('hello')
    await settle()
    expect(notify.fn).toHaveBeenCalledWith('hello')
    expect(log.warn).not.toHaveBeenCalled()
  })

  it('NEGATIVE CONTROL: an exception from notifyChannel is a warn naming the loss, with a preview of the alert', async () => {
    notify.fn.mockImplementation(async () => { throw new Error('socket hang up') })
    sendAlert('A fo  channel\nkeep-alive nem frissul')
    await settle()
    expect(log.warn).toHaveBeenCalledTimes(1)
    const [obj, msg] = log.warn.mock.calls[0] as [Record<string, unknown>, string]
    expect(msg).toContain('elveszett')
    expect(obj).toMatchObject({ err: 'socket hang up', preview: 'A fo channel keep-alive nem frissul' })
  })

  it('a chat id in the alert text is masked in the preview', async () => {
    notify.fn.mockImplementation(async () => { throw new Error('x') })
    sendAlert('A 5040302010 chat nem elerheto')
    await settle()
    expect((log.warn.mock.calls[0][0] as Record<string, unknown>).preview).toBe('A <id> chat nem elerheto')
  })

  // Sam 3566: the preview was masked, the error text was not
  it('a token or a long id in the exception text is masked in the err field too', async () => {
    notify.fn.mockImplementation(async () => { throw new Error('POST https://api.telegram.org/bot1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage chat 5040302010 failed') })
    sendAlert('x')
    await settle()
    const err = String((log.warn.mock.calls[0][0] as Record<string, unknown>).err)
    expect(err).not.toContain('AAHdqTcvC')
    expect(err).not.toContain('5040302010')
    expect(err).toContain('<token>')
  })

  it('a non-Error rejection is logged too', async () => {
    notify.fn.mockImplementation(async () => { throw 'plain string' })
    sendAlert('x')
    await settle()
    expect((log.warn.mock.calls[0][0] as Record<string, unknown>).err).toBe('plain string')
  })
})
