import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdirSync, rmSync } from 'node:fs'
import { EventEmitter } from 'node:events'
import { agentDir } from '../web/agent-config.js'
import { initDatabase, getAgentMessage, getDispatchedPendingStats } from '../db.js'
import { MAIN_AGENT_ID } from '../config.js'
import { tryHandleMessages } from '../web/routes/messages.js'
import type { RouteContext } from '../web/routes/types.js'

// Card 5e4110d7 (HEX 3570, direction A): POST /api/messages accepts `kind` ('task' default, 'info'). The kind is what
// the restart gate reads (getDispatchedPendingStats); the route must store it, default it, and refuse anything else.

function fakeCtx(body: unknown): { ctx: RouteContext; res: { statusCode: number; body: string } } {
  const req = new EventEmitter() as unknown as RouteContext['req'] & { destroy(): void }
  ;(req as unknown as { headers: Record<string, string> }).headers = {}
  ;(req as { destroy(): void }).destroy = () => { /* readBody over-limit hook */ }
  const state = { statusCode: 0, body: '' }
  const res = {
    writeHead(code: number) { state.statusCode = code; return res },
    end(data?: unknown) { state.body = String(data ?? '') },
    setHeader() { /* not used by json() */ },
  } as unknown as RouteContext['res']
  process.nextTick(() => {
    ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
    ;(req as unknown as EventEmitter).emit('end')
  })
  const path = '/api/messages'
  return { ctx: { req, res, path, method: 'POST', url: new URL(`http://localhost${path}`), fedPeer: null }, res: state }
}

async function post(body: unknown): Promise<{ statusCode: number; json: Record<string, unknown> }> {
  const { ctx, res } = fakeCtx(body)
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: res.statusCode, json: JSON.parse(res.body) }
}

const PEER = 'kindtest-peer'
beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  mkdirSync(agentDir(PEER), { recursive: true })   // a known recipient, so the route does not stop at the unknown-agent check
})
afterAll(() => { rmSync(agentDir(PEER), { recursive: true, force: true }) })

const TWO_HOURS = 2 * 60 * 60 * 1000

describe('POST /api/messages kind', () => {
  it('kind: "info" is stored as info and does not count as work in flight', async () => {
    const r = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'tajekoztato', kind: 'info' })
    expect(r.statusCode).toBe(200)
    expect(getAgentMessage(Number(r.json.id))?.kind).toBe('info')
    const x = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'tajekoztato 2', kind: 'info' })
    expect(x.statusCode).toBe(200)
    expect(getDispatchedPendingStats(MAIN_AGENT_ID, Date.now(), TWO_HOURS, MAIN_AGENT_ID).count).toBe(0)
  })

  it('NEGATIVE CONTROLS: no kind, and kind: "task", are tasks and count', async () => {
    const a = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'feladat jelolet nelkul' })
    const b = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'feladat', kind: 'task' })
    expect(getAgentMessage(Number(a.json.id))?.kind).toBe('task')
    expect(getAgentMessage(Number(b.json.id))?.kind).toBe('task')
    expect(getDispatchedPendingStats(MAIN_AGENT_ID, Date.now(), TWO_HOURS, MAIN_AGENT_ID).count).toBe(2)
  })

  it('kind: null is "not given": a task, 200 (a serializer that writes every field as null keeps working)', async () => {
    const r = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'null kind', kind: null })
    expect(r.statusCode).toBe(200)
    expect(getAgentMessage(Number(r.json.id))?.kind).toBe('task')
  })

  it('anything else is a 400 and writes nothing: a typo does not silently send a task', async () => {
    const before = getDispatchedPendingStats(MAIN_AGENT_ID, Date.now(), TWO_HOURS, MAIN_AGENT_ID).count
    for (const kind of ['Info', 'INFO', 'report', '', 1, true, {}, ['info']]) {
      const r = await post({ from: MAIN_AGENT_ID, to: PEER, content: 'x', kind })
      expect({ kind, status: r.statusCode }).toEqual({ kind, status: 400 })
      expect(String(r.json.error)).toContain("'task' or 'info'")
    }
    expect(getDispatchedPendingStats(MAIN_AGENT_ID, Date.now(), TWO_HOURS, MAIN_AGENT_ID).count).toBe(before)
  })
})
