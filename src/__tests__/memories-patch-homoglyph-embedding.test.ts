/**
 * HOMOPATCH926 (card 57a4249f) and card 7a21ded9: the memory EDIT path.
 *
 *  - PATCH/PUT /api/memories/:id warns about a Cyrillic/Greek look-alike in the text the caller sent,
 *    warn-only like POST (the write stays), and the database journals an edit that brings a look-alike
 *    into a row that had none (homoglyph_findings, src_table 'memories').
 *  - An edit drops the stale vector; the route now refills it fire-and-forget instead of leaving the row
 *    invisible to the semantic search until the nightly backfill. A second edit while the first refill is
 *    in flight must not get the first edit's vector.
 *
 * Cyrillic letters are built from codepoints: a literal would make this file a hit for the artifact sweep.
 */
import { describe, it, expect, vi, beforeAll, beforeEach, afterAll } from 'vitest'
import { Readable } from 'stream'
import { initDatabase, saveAgentMemory, saveMemory, getDb, refreshMemoryEmbedding, backfillEmbeddings } from '../db.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import type { RouteContext } from '../web/routes/types.js'

vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  return { ...actual, MAIN_AGENT_ID: 'agent-a', ALLOWED_CHAT_ID: 'test-chat', OLLAMA_URL: 'http://embed.test', EMBED_URL: 'http://embed.test' }
})
vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

const CYR_E = String.fromCodePoint(0x0435) // looks like Latin e
const CYR_O = String.fromCodePoint(0x043e) // looks like Latin o

async function call(path: string, method: string, body?: unknown): Promise<{ status: number; body: any }> {
  const url = new URL(`http://localhost:3420${path}`)
  let responseBody = ''
  let statusCode = 200
  const res = {
    writeHead: (code: number) => { statusCode = code },
    setHeader: () => {},
    end: (b?: string) => { responseBody = b || '' },
  }
  const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]) as any
  const ctx: RouteContext = { req, res: res as any, path, method, url }
  await tryHandleMemories(ctx)
  return { status: statusCode, body: responseBody ? JSON.parse(responseBody) : null }
}

const row = (id: number) => getDb().prepare('SELECT content, embedding FROM memories WHERE id = ?').get(id) as { content: string; embedding: string | null }
const findings = (id: number) => getDb().prepare("SELECT sample FROM homoglyph_findings WHERE src_table = 'memories' AND src_id = ?").all(String(id)) as { sample: string }[]

// The embedding backend: every call answers with a vector carrying the text's length, so a vector says
// which text it was made from. `gate` lets a test hold a call open.
let embedCalls: string[] = []
let backendDown = false
let gate: Promise<void> | null = null
function stubBackend() {
  vi.stubGlobal('fetch', vi.fn(async (_u: string, init: { body: string }) => {
    const prompt = (JSON.parse(init.body) as { prompt: string }).prompt
    embedCalls.push(prompt)
    if (backendDown) throw new Error('backend down')
    if (gate) { const g = gate; gate = null; await g }
    return { json: async () => ({ embedding: [prompt.length, 1] }) }
  }))
}
const settle = () => new Promise((r) => setTimeout(r, 20))

beforeAll(() => { initDatabase(':memory:') })
beforeEach(() => { embedCalls = []; backendDown = false; gate = null; stubBackend() })
afterAll(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('PATCH warns about a look-alike in the text it was sent (HOMOPATCH926)', () => {
  it('a Cyrillic letter in the new content: 200, the text saved unchanged, a warning citing the codepoint', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    const bad = `mer${CYR_E}se kesz`
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: bad })
    expect(r.status).toBe(200)
    expect(r.body.ok).toBe(true)
    expect(r.body.homoglyph_warning).toContain('U+0435')
    expect(r.body.homoglyph_warning).not.toContain(CYR_E)
    expect(row(id).content).toBe(bad)
  })

  it('NEGATIVE CONTROL: clean text carries no warning key', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: 'meres kesz, arvizturo tukorfurogep' })
    expect(r.status).toBe(200)
    expect('homoglyph_warning' in r.body).toBe(false)
  })

  it('the FIX path is checked too: a correction that brings in a NEW look-alike warns', async () => {
    const id = saveAgentMemory('agent-a', `mer${CYR_E}se`, 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: `mer${CYR_E}se jav${CYR_O}tva` })
    expect(r.body.homoglyph_warning).toContain('U+043E')
  })

  it('PUT is the same route and warns the same way', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PUT', { content: `x${CYR_O}y` })
    expect(r.body.homoglyph_warning).toContain('U+043E')
  })

  it('prepend is the caller\'s text: a look-alike in it warns', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { prepend: `[2026] mer${CYR_E}s` })
    expect(r.body.homoglyph_warning).toContain('U+0435')
  })

  it('a category-only move resends the STORED content and is not the caller\'s text: no warning', async () => {
    const id = saveAgentMemory('agent-a', `legit foreign record ${CYR_E}`, 'hot', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { category: 'cold' })
    expect(r.status).toBe(200)
    expect('homoglyph_warning' in r.body).toBe(false)
  })
})

describe('the database journals an edit that brings a look-alike into a clean row (HOMOPATCH926)', () => {
  it('a PATCH that introduces one leaves a journal row naming the memory', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    expect(findings(id)).toHaveLength(0)
    await call(`/api/memories/${id}`, 'PATCH', { content: `mer${CYR_E}se kesz` })
    const f = findings(id)
    expect(f).toHaveLength(1)
    expect(f[0].sample).toContain('kesz')
  })

  it('the write bypasses the API entirely (direct SQL): the trigger still journals it', () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    getDb().prepare('UPDATE memories SET content = ? WHERE id = ?').run(`d${CYR_O}rect sql`, id)
    expect(findings(id)).toHaveLength(1)
  })

  it('NEGATIVE CONTROLS: a clean edit, a category-only move and an edit that REMOVES the look-alike journal nothing', async () => {
    const id = saveAgentMemory('agent-a', `mer${CYR_E}se`, 'warm', 'k').id
    await call(`/api/memories/${id}`, 'PATCH', { content: 'meres clean now' })
    await call(`/api/memories/${id}`, 'PATCH', { category: 'cold' })
    expect(findings(id)).toHaveLength(0)
  })

  it('a row that already carries one is not journaled again on every later edit (the response still warns)', async () => {
    const id = saveAgentMemory('agent-a', 'clean start', 'warm', 'k').id
    await call(`/api/memories/${id}`, 'PATCH', { content: `a${CYR_E}` })
    const again = await call(`/api/memories/${id}`, 'PATCH', { content: `a${CYR_E} and more${CYR_O}` })
    expect(findings(id)).toHaveLength(1)
    expect(again.body.homoglyph_warning).toContain('U+043E')
  })
})

describe('an edit refills its vector at once instead of at the nightly backfill (7a21ded9)', () => {
  it('after a content PATCH the row has a vector made from the NEW text, without any backfill', async () => {
    const id = saveAgentMemory('agent-a', 'old text', 'warm', 'kw').id
    await settle()
    embedCalls = []
    await call(`/api/memories/${id}`, 'PATCH', { content: 'the corrected memory' })
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    expect(embedCalls).toEqual(['the corrected memory kw'])
    expect(JSON.parse(row(id).embedding as string)[0]).toBe('the corrected memory kw'.length)
  })

  it('the PATCH response does not wait for the embedding backend', async () => {
    const id = saveAgentMemory('agent-a', 'old text', 'warm', 'kw').id
    await settle()
    let release!: () => void
    gate = new Promise<void>((r) => { release = r })
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: 'slow backend edit' })
    expect(r.status).toBe(200)
    expect(row(id).embedding).toBeNull()
    release()
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
  })

  it('a backend that is down leaves the vector NULL for the nightly backfill and the PATCH still succeeds', async () => {
    const id = saveAgentMemory('agent-a', 'old text', 'warm', 'kw').id
    await settle()
    backendDown = true
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: 'edit while down' })
    expect(r.status).toBe(200)
    await settle()
    expect(row(id).embedding).toBeNull()
  })

  it('a category-only move keeps the vector and does not call the backend', async () => {
    const id = saveAgentMemory('agent-a', 'stays embedded', 'hot', 'kw').id
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    const before = row(id).embedding
    embedCalls = []
    await call(`/api/memories/${id}`, 'PATCH', { category: 'cold' })
    await settle()
    expect(embedCalls).toEqual([])
    expect(row(id).embedding).toBe(before)
  })

  it('RACE: a second edit while the first refill is in flight never receives the first edit\'s vector', async () => {
    const id = saveAgentMemory('agent-a', 'old text', 'warm', 'kw').id
    await settle()
    let release!: () => void
    gate = new Promise<void>((r) => { release = r })
    await call(`/api/memories/${id}`, 'PATCH', { content: 'first edit, long long long' })   // refill #1 held open
    await call(`/api/memories/${id}`, 'PATCH', { content: 'second' })                       // refill #2 runs free
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    release()
    await settle()
    expect(row(id).content).toBe('second')
    // the vector belongs to the stored text, not to the stale in-flight one
    expect(JSON.parse(row(id).embedding as string)[0]).toBe('second kw'.length)
  })

  it('refreshMemoryEmbedding is a no-op for a row that has a vector, and for a row that does not exist', async () => {
    const id = saveAgentMemory('agent-a', 'has a vector', 'warm', 'kw').id
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    embedCalls = []
    expect(await refreshMemoryEmbedding(id)).toBe(false)
    expect(await refreshMemoryEmbedding(999999)).toBe(false)
    expect(embedCalls).toEqual([])
  })
})

// Sam 3540 (1): the vector of a memory is written by FOUR paths (the POST's fire-and-forget, saveMemory, the
// refill after a PATCH, and the nightly backfill). Only the refill used to check that the row still holds the
// text the vector was made from, so a slow POST or backfill finishing after a quick PATCH wrote the OLD text's
// vector on the NEW text, for good (the backfill only looks at NULL). All of them go through one guarded
// UPDATE now. Here the order of events is forced with a held backend call.
describe('a late vector write never lands on text it was not made from (Sam 3540)', () => {
  const vecOf = (id: number) => (JSON.parse(row(id).embedding as string) as number[])[0]

  it('R1: the POST\'s embedding comes back AFTER a quick PATCH-fix -> the vector stays the PATCH text\'s', async () => {
    let release!: () => void
    gate = new Promise<void>((r) => { release = r })
    const id = saveAgentMemory('agent-a', 'POSTTEXT first draft, long long long', 'warm', 'kw').id   // its embed call is held
    await call(`/api/memories/${id}`, 'PATCH', { content: 'fixed' })                                    // refill runs free
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    expect(vecOf(id)).toBe('fixed kw'.length)
    release()
    await settle()
    expect(row(id).content).toBe('fixed')
    expect(vecOf(id)).toBe('fixed kw'.length)   // NOT the 36-character draft's
  })

  it('R2: a backfill that read the old text comes back AFTER a PATCH -> the vector stays the PATCH text\'s', async () => {
    const id = saveAgentMemory('agent-a', 'BFTEXT seed, long long long long', 'warm', 'kw').id
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    // only this row is pending for the backfill: every other row gets a dummy vector, this one is NULLed
    getDb().prepare('UPDATE memories SET embedding = ? WHERE id != ?').run('[1,1]', id)
    getDb().prepare('UPDATE memories SET embedding = NULL WHERE id = ?').run(id)
    let release!: () => void
    gate = new Promise<void>((r) => { release = r })
    const bf = backfillEmbeddings()                                   // snapshot of the old text, its embed call held
    await settle()
    await call(`/api/memories/${id}`, 'PATCH', { content: 'edited' }) // refill runs free
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    release()
    await bf
    expect(row(id).content).toBe('edited')
    expect(vecOf(id)).toBe('edited kw'.length)
  })

  // Sam 3566 (M4): the nightly digest save had the same guard and no test, so a mutant without it passed.
  it('R3: the digest save (saveMemory) has the same guard: its late vector does not land on an edited row', async () => {
    let release!: () => void
    gate = new Promise<void>((r) => { release = r })
    saveMemory('test-chat', 'DIGESTTEXT first draft, long long long long', 'episodic', undefined, 'agent-a')   // its embed call is held
    const id = (getDb().prepare("SELECT id FROM memories WHERE content LIKE 'DIGESTTEXT%'").get() as { id: number }).id
    await call(`/api/memories/${id}`, 'PATCH', { content: 'fixed' })                                          // refill runs free
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    const mine = vecOf(id)
    expect(mine).not.toBe('DIGESTTEXT first draft, long long long long'.length)
    release()
    await settle()
    expect(row(id).content).toBe('fixed')
    expect(vecOf(id)).toBe(mine)
  })

  it('a keywords-only change in flight: the OLD keywords\' refill returns while the row is already NULL again -> it must not write (the keywords half of the guard)', async () => {
    const id = saveAgentMemory('agent-a', 'same text', 'warm', 'k0').id
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    let releaseOld!: () => void
    let releaseNew!: () => void
    gate = new Promise<void>((r) => { releaseOld = r })
    await call(`/api/memories/${id}`, 'PATCH', { content: 'same text', keywords: 'kk1' })           // refill #1 (kk1), held
    gate = new Promise<void>((r) => { releaseNew = r })
    await call(`/api/memories/${id}`, 'PATCH', { content: 'same text', keywords: 'kkkkkk2' })       // refill #2 (kkkkkk2), held
    expect(row(id).embedding).toBeNull()
    releaseOld()                                                    // #1 returns FIRST: same content, other keywords
    await settle()
    expect(row(id).embedding).toBeNull()                            // without the keywords guard it stored the kk1 vector here
    releaseNew()
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    expect(vecOf(id)).toBe('same text kkkkkk2'.length)
  })

  it('NEGATIVE CONTROL: without a competing edit the POST\'s own vector is stored (the guard does not block honest writes)', async () => {
    const id = saveAgentMemory('agent-a', 'plain post', 'warm', 'kw').id
    await vi.waitFor(() => expect(row(id).embedding).not.toBeNull())
    expect(vecOf(id)).toBe('plain post kw'.length)
  })
})

// Sam 3540 (3): the PATCH warning is about what the edit ADDS, not about everything the stored text contains.
describe('the PATCH warning is about the look-alikes the edit adds (Sam 3540)', () => {
  it('W1: a clean prepend onto a row that legitimately carries Cyrillic is silent', async () => {
    const id = saveAgentMemory('agent-a', `real foreign record ${CYR_E}${CYR_O}`, 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { prepend: '[2026-10-13] note' })
    expect('homoglyph_warning' in r.body).toBe(false)
  })
  it('W2: resending the stored content unchanged (the dashboard does on every save) is silent', async () => {
    const text = `real foreign record ${CYR_E}${CYR_O}`
    const id = saveAgentMemory('agent-a', text, 'hot', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: text, category: 'cold' })
    expect('homoglyph_warning' in r.body).toBe(false)
  })
  it('FIXING a flagged memory (fewer look-alikes) is silent', async () => {
    const id = saveAgentMemory('agent-a', `mer${CYR_E}se`, 'warm', 'k').id
    const r = await call(`/api/memories/${id}`, 'PATCH', { content: 'merese' })
    expect('homoglyph_warning' in r.body).toBe(false)
  })
  it('NEGATIVE CONTROLS: adding one, or swapping one for a different one, still warns', async () => {
    const id = saveAgentMemory('agent-a', `mer${CYR_E}se`, 'warm', 'k').id
    const more = await call(`/api/memories/${id}`, 'PATCH', { content: `mer${CYR_E}se ${CYR_E}` })
    expect(more.body.homoglyph_warning).toContain('U+0435')
    const swapped = await call(`/api/memories/${id}`, 'PATCH', { content: `mer${CYR_O}se` })
    expect(swapped.body.homoglyph_warning).toContain('U+043E')
  })
})
