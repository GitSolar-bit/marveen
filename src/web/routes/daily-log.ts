import { appendDailyLog, getDailyLog, getDailyLogDates } from '../../db.js'
import { MAIN_AGENT_ID } from '../../config.js'
import { logger } from '../../logger.js'
import { readBody, json } from '../http-helpers.js'
import { detectHomoglyphs, formatHomoglyphWarning } from '../../homoglyph.js'
import type { RouteContext } from './types.js'

export async function tryHandleDailyLog(ctx: RouteContext): Promise<boolean> {
  const { req, res, path, method, url } = ctx

  if (path === '/api/daily-log' && method === 'POST') {
    const body = await readBody(req)
    const data = JSON.parse(body.toString()) as { agent_id?: string; content: string }
    if (!data.content?.trim()) { json(res, { error: 'Content required' }, 400); return true }
    appendDailyLog(data.agent_id || MAIN_AGENT_ID, data.content.trim())
    // Warn-only homoglyph check (GATEHOMOGLIFSWEEP816) -- see memories.ts.
    const homoglyphs = detectHomoglyphs(data.content)
    if (homoglyphs.length > 0) {
      const warning = formatHomoglyphWarning(homoglyphs)
      logger.warn({ agent: data.agent_id }, `daily-log entry saved with ${warning}`)
      json(res, { ok: true, homoglyph_warning: warning })
      return true
    }
    json(res, { ok: true })
    return true
  }

  // The two halves name the agent differently: POST reads `agent_id`, GET reads
  // `agent`. That is deliberate, but it makes `?agent_id=igor` the single most
  // likely typo here -- and until DAILYLOGPARAM920 it fell through to the
  // MAIN_AGENT_ID default and answered with the MAIN AGENT'S log. Measured
  // 2026-09-23: `?agent=igor` returned [], `?agent_id=igor` and `?nonsense=xyz`
  // both returned hex's entries, HTTP 200, no warning. Asking for one agent's
  // day and being handed another's is the expensive direction to be wrong in,
  // because the answer looks valid. Same guard as /api/messages (messages.ts).
  const rejectUnknownParams = (known: string[]): boolean => {
    const unknown = [...url.searchParams.keys()].filter((k) => !known.includes(k))
    if (!unknown.length) return false
    json(res, {
      error: 'unknown query parameter',
      unknown,
      known,
      hint: 'the agent filter is "agent" on GET; "agent_id" is the POST body field, not a query param',
    }, 400)
    return true
  }

  if (path === '/api/daily-log' && method === 'GET') {
    if (rejectUnknownParams(['agent', 'date'])) return true
    const agent = url.searchParams.get('agent') || MAIN_AGENT_ID
    const date = url.searchParams.get('date') || new Date().toISOString().split('T')[0]
    json(res, getDailyLog(agent, date))
    return true
  }

  if (path === '/api/daily-log/dates' && method === 'GET') {
    if (rejectUnknownParams(['agent'])) return true
    const agent = url.searchParams.get('agent') || MAIN_AGENT_ID
    json(res, getDailyLogDates(agent))
    return true
  }

  return false
}
