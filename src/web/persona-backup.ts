import { readFileSync, readdirSync, existsSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { PROJECT_ROOT, STORE_DIR } from '../config.js'
import { logger } from '../logger.js'
import { atomicWriteFileSync } from './atomic-write.js'

// Card dc598b53 (RECONSCAFFOLD929, HEX 3572): a copy of an agent's CLAUDE.md BEFORE the startup scaffold rewrites it.
//
// The scaffold owns the text between the `BEGIN GENERATED` / `END GENERATED` markers and replaces it with its
// template every time an agent starts. That is by design, and it means a line somebody added INSIDE a generated
// block is gone after the next start. Measured 2026-09-29: one line vanished from each of four sub-agents'
// CLAUDE.md, and nothing on disk could say which one (agents/ is not under git, and store/persona-backups only ever
// held hand-made copies of the MAIN agent's file). So every rewrite that changes the file keeps what it replaced.
//
// Where: store/persona-backups/<agent>/CLAUDE.md.bak-<UTC stamp>. store/, not the repo: the copy must survive a
// checkout and must not be committed. The main agent's key is `main`.
//
// INTERMEDIATE STATES. One agent start runs up to eleven ensure* functions in a row, each of which may write. Every
// rewrite after the first starts from text THIS process wrote a moment ago, and a copy of that is noise that would
// push the file we want (the state BEFORE the first rewrite of the start) out of a bounded history. So a rewrite
// whose on-disk text is exactly what this process last wrote to that path adds nothing. The rule is about the TEXT,
// not about time (Sam, 2026-10-13): a hand edit between two starts, even seconds apart, makes the on-disk text differ
// from what we last wrote, and that edit is exactly what the copy exists to keep. The memory is per process: after a
// dashboard restart the first rewrite of a path always keeps a copy.
//
// RETENTION is bounded: the newest KEEP copies per agent stay, older ones are removed (only files this module
// named).
//
// A backup that cannot be written is a warning, never a reason to block the rewrite or the agent's start.
export const PERSONA_BACKUP_KEEP = 10

const NAME_RE = /^CLAUDE\.md\.bak-(\d{8}T\d{9}Z)(?:-(\d+))?$/

// path -> the text this process last wrote there (set only after the write succeeded)
const lastWritten = new Map<string, string>()
export function forgetLastWrittenForTests(): void { lastWritten.clear() }

// UTC, to the millisecond, so two copies made in the same second get two names
function stamp(ms: number): string {
  return new Date(ms).toISOString().replace(/[-:.]/g, '')
}

export function personaAgentKey(claudeMdPath: string): string {
  if (claudeMdPath === join(PROJECT_ROOT, 'CLAUDE.md')) return 'main'
  return basename(dirname(claudeMdPath)).replace(/[^A-Za-z0-9_.-]/g, '_') || 'unknown'
}

export function personaBackupDir(agentKey: string): string {
  return join(STORE_DIR, 'persona-backups', agentKey)
}

export function listPersonaBackups(agentKey: string): string[] {
  try {
    // oldest first: by stamp, then by the collision number (stamp alone is the 0th, `-1`, `-2` ... follow)
    const rank = (n: string): [string, number] => { const m = NAME_RE.exec(n)!; return [m[1], m[2] ? Number(m[2]) : 0] }
    return readdirSync(personaBackupDir(agentKey)).filter((n) => NAME_RE.test(n))
      .sort((a, b) => { const [sa, na] = rank(a), [sb, nb] = rank(b); return sa < sb ? -1 : sa > sb ? 1 : na - nb })
  } catch {
    return []
  }
}

/** Keep `before` (the file's text as it is on disk) if the rewrite to `updated` would change it. Returns the copy's
 *  path, or null when nothing was written (no change, an intermediate state this process wrote itself, or a failure that was logged). */
export function backupBeforeRewrite(claudeMdPath: string, updated: string, nowMs: number = Date.now()): string | null {
  const key = personaAgentKey(claudeMdPath)
  try {
    if (!existsSync(claudeMdPath)) return null
    const before = readFileSync(claudeMdPath, 'utf-8')
    if (before === updated) return null
    // what this process wrote itself a moment ago is an intermediate state, not something worth a copy
    if (lastWritten.get(claudeMdPath) === before) return null
    const dir = personaBackupDir(key)
    mkdirSync(dir, { recursive: true })
    // EXCLUSIVE creation ('wx'): a copy that already exists under this name (two copies in the same millisecond, two
    // processes) is never overwritten; the next free `-N` takes the new one (Sam, 2026-10-13: an equal-millisecond copy
    // used to replace the ORIGINAL silently). Not an atomic rename, but a half-written copy is only a backup.
    const base = `CLAUDE.md.bak-${stamp(nowMs)}`
    let target = ''
    // continue after the highest number already used for this stamp, not at the first FREE one: retention may have
    // removed the unnumbered oldest, and a new copy must never take its place at the head of the order
    const used = listPersonaBackups(key).map((f) => NAME_RE.exec(f)!).filter((m) => m[1] === stamp(nowMs)).map((m) => (m[2] ? Number(m[2]) : 0))
    const first = used.length ? Math.max(...used) + 1 : 0
    for (let n = first; n < first + 1000 && !target; n++) {
      const candidate = join(dir, n === 0 ? base : `${base}-${n}`)
      try { writeFileSync(candidate, before, { flag: 'wx', mode: 0o600 }); target = candidate } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      }
    }
    if (!target) throw new Error('no free backup name after 1000 tries')
    for (const old of listPersonaBackups(key).slice(0, -PERSONA_BACKUP_KEEP)) {
      try { unlinkSync(join(dir, old)) } catch { /* a copy that will not go away is not a reason to fail */ }
    }
    return target
  } catch (err) {
    logger.warn({ err, agent: key, path: claudeMdPath }, 'persona backup before the scaffold rewrite failed -- the rewrite goes on')
    return null
  }
}

/** The one door every scaffold rewrite of an agent's CLAUDE.md goes through: keep the old text, then write. */
export function writeClaudeMdKeepingBackup(claudeMdPath: string, updated: string): void {
  backupBeforeRewrite(claudeMdPath, updated)
  atomicWriteFileSync(claudeMdPath, updated)
  lastWritten.set(claudeMdPath, updated)
}
