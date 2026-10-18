// Card dc598b53 (RECONSCAFFOLD929, HEX 3572): the scaffold keeps what it replaces. A line added inside a generated block
// of an agent's CLAUDE.md is gone after the next start (by design); the copy made before the rewrite is the only way to
// know which line it was. One door for the 12 rewrites (writeClaudeMdKeepingBackup), a copy only when the file really
// changes, one copy per start (the state before the first rewrite, decided by the TEXT not by time), bounded history, and a failed copy never blocks the rewrite.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const tmpRoot = mkdtempSync(join(tmpdir(), 'marveen-personabak-test-'))
const storeDir = join(tmpRoot, 'store')
const warn = vi.hoisted(() => vi.fn())

vi.mock('../config.js', () => ({
  STORE_DIR: join(tmpRoot, 'store'),
  PROJECT_ROOT: tmpRoot,
  OWNER_NAME: 'TestOwner',
  MAIN_AGENT_ID: 'agent-a',
  BOT_NAME: 'agent-a',
  CHANNEL_PROVIDER: 'telegram',
  WEB_PORT: 3420,
  OWNER_DRIVE_FOLDER: '',
  DASHBOARD_PUBLIC_URL: '',
  AGENT_API_ORIGIN: '',
  APP_TZ: 'Europe/Budapest',
}))
vi.mock('../logger.js', () => ({ logger: { info: vi.fn(), warn, debug: vi.fn(), error: vi.fn() } }))
vi.mock('../web/agent-config.js', () => ({
  agentDir: (name: string) => join(tmpRoot, 'agents', name),
  agentConfigRoot: () => join(tmpRoot, 'agents'),
  listAgentNames: () => ['agent-a', 'agent-b'],
  readAgentCapabilities: () => [],
}))

const { backupBeforeRewrite, writeClaudeMdKeepingBackup, listPersonaBackups, personaBackupDir, personaAgentKey,
  PERSONA_BACKUP_KEEP } = await import('../web/persona-backup.js')
const { ensureFleetAuthSection } = await import('../web/agent-scaffold.js')

let n = 0
function agentFile(name: string, content: string): string {
  const dir = join(tmpRoot, 'agents', name)
  mkdirSync(dir, { recursive: true })
  const p = join(dir, 'CLAUDE.md')
  writeFileSync(p, content, 'utf-8')
  return p
}
const fresh = () => `agent-${++n}`
const T0 = Date.UTC(2026, 9, 13, 18, 0, 0)

beforeEach(() => { warn.mockReset() })

describe('backupBeforeRewrite', () => {
  it('a rewrite that changes the file keeps the OLD text under store/persona-backups/<agent>/', () => {
    const name = fresh()
    const p = agentFile(name, 'regi szoveg\n')
    const copy = backupBeforeRewrite(p, 'uj szoveg\n', T0)
    expect(copy).toBe(join(storeDir, 'persona-backups', name, 'CLAUDE.md.bak-20261013T180000000Z'))
    expect(readFileSync(copy!, 'utf-8')).toBe('regi szoveg\n')
    expect(readFileSync(p, 'utf-8')).toBe('regi szoveg\n')   // it only copies; the write is the caller's
  })

  it('NEGATIVE CONTROL: a rewrite that changes nothing keeps nothing', () => {
    const name = fresh()
    const p = agentFile(name, 'ugyanaz\n')
    expect(backupBeforeRewrite(p, 'ugyanaz\n', T0)).toBeNull()
    expect(listPersonaBackups(name)).toEqual([])
    expect(existsSync(personaBackupDir(name))).toBe(false)
  })

  it('a file that does not exist yet has nothing to keep', () => {
    expect(backupBeforeRewrite(join(tmpRoot, 'agents', 'nincs-ilyen', 'CLAUDE.md'), 'x', T0)).toBeNull()
  })

  it('INTERMEDIATE STATES: rewrites that start from text this process wrote add no copy, so the ONE copy is the state before the first rewrite', () => {
    const name = fresh()
    const p = agentFile(name, 'eredeti\n')
    writeClaudeMdKeepingBackup(p, 'fel-atirt 1\n')
    writeClaudeMdKeepingBackup(p, 'fel-atirt 2\n')
    writeClaudeMdKeepingBackup(p, 'kesz\n')
    const files = listPersonaBackups(name)
    expect(files).toHaveLength(1)
    expect(readFileSync(join(personaBackupDir(name), files[0]), 'utf-8')).toBe('eredeti\n')
    expect(readFileSync(p, 'utf-8')).toBe('kesz\n')
  })

  it('SAM B1: a hand edit between two starts is kept even seconds later, because the rule is about the text, not about time', () => {
    const name = fresh()
    const p = agentFile(name, 'ORIGINAL\n')
    writeClaudeMdKeepingBackup(p, 'SCAFFOLDED\n')              // start 1
    writeFileSync(p, 'SCAFFOLDED\nHAND EDIT INSIDE BLOCK\n')    // somebody edits the block
    writeClaudeMdKeepingBackup(p, 'SCAFFOLDED\n')              // start 2, a moment later: the edit would vanish
    const bodies = listPersonaBackups(name).map((f) => readFileSync(join(personaBackupDir(name), f), 'utf-8'))
    expect(bodies).toEqual(['ORIGINAL\n', 'SCAFFOLDED\nHAND EDIT INSIDE BLOCK\n'])
  })

  it('SAM 3613: two copies in the SAME millisecond are both kept (an equal name used to overwrite the first)', () => {
    const name = fresh()
    const p = agentFile(name, 'ORIGINAL\n')
    expect(backupBeforeRewrite(p, 'x\n', T0)).not.toBeNull()
    writeFileSync(p, 'EDITED\n')
    const second = backupBeforeRewrite(p, 'y\n', T0)          // the very same millisecond
    expect(second).toMatch(/-1$/)
    writeFileSync(p, 'EDITED 2\n')
    expect(backupBeforeRewrite(p, 'z\n', T0)).toMatch(/-2$/)
    const bodies = listPersonaBackups(name).map((f) => readFileSync(join(personaBackupDir(name), f), 'utf-8'))
    expect(bodies).toEqual(['ORIGINAL\n', 'EDITED\n', 'EDITED 2\n'])   // oldest first, none lost
  })

  it('the collision numbers sort numerically (-10 after -2), so retention removes the OLDEST', () => {
    const name = fresh()
    const p = agentFile(name, 'v0\n')
    for (let i = 1; i <= 12; i++) { backupBeforeRewrite(p, `n${i}\n`, T0); writeFileSync(p, `v${i}\n`) }
    const bodies = listPersonaBackups(name).map((f) => readFileSync(join(personaBackupDir(name), f), 'utf-8'))
    expect(bodies).toHaveLength(PERSONA_BACKUP_KEEP)
    expect(bodies[0]).toBe('v2\n')            // v0 and v1 were the two oldest of the twelve
    expect(bodies[bodies.length - 1]).toBe('v11\n')
  })

  it('two copies made in the same second get two names', () => {
    const name = fresh()
    const p = agentFile(name, 'a\n')
    backupBeforeRewrite(p, 'b\n', T0)
    expect(backupBeforeRewrite(p, 'c\n', T0 + 1)).not.toBeNull()
    expect(listPersonaBackups(name)).toHaveLength(2)
  })

  it('after a restart of the process (nothing remembered) the first rewrite keeps a copy', async () => {
    const name = fresh()
    const p = agentFile(name, 'x\n')
    writeClaudeMdKeepingBackup(p, 'y\n')
    const { forgetLastWrittenForTests } = await import('../web/persona-backup.js')
    forgetLastWrittenForTests()
    writeClaudeMdKeepingBackup(p, 'z\n')
    expect(listPersonaBackups(name)).toHaveLength(2)
  })

  it('RETENTION: only the newest KEEP copies stay, the oldest go', () => {
    const name = fresh()
    const p = agentFile(name, 'v0\n')
    const total = PERSONA_BACKUP_KEEP + 3
    for (let i = 0; i < total; i++) {
      backupBeforeRewrite(p, `v${i + 1}\n`, T0 + i * 1_000)
      writeFileSync(p, `v${i + 1}\n`)
    }
    const files = listPersonaBackups(name)
    expect(files).toHaveLength(PERSONA_BACKUP_KEEP)
    // the copies hold v3 .. v12 (the states BEFORE rewrites 4 .. 13); v0 .. v2 are gone
    const bodies = files.map((f) => readFileSync(join(personaBackupDir(name), f), 'utf-8'))
    expect(bodies[0]).toBe('v3\n')
    expect(bodies[bodies.length - 1]).toBe(`v${total - 1}\n`)
  })

  it('the main agent\'s file (at PROJECT_ROOT) is filed under "main"', () => {
    const p = join(tmpRoot, 'CLAUDE.md')
    writeFileSync(p, 'fo ugynok\n')
    expect(personaAgentKey(p)).toBe('main')
    const copy = backupBeforeRewrite(p, 'masik\n', T0)
    expect(copy).toContain(join('persona-backups', 'main'))
  })

  it('an agent directory name cannot climb out of the backup folder', () => {
    expect(personaAgentKey(join(tmpRoot, 'agents', '..evil', 'CLAUDE.md'))).not.toContain('/')
    expect(personaAgentKey(join(tmpRoot, 'agents', 'a b', 'CLAUDE.md'))).toBe('a_b')
  })
})

describe('writeClaudeMdKeepingBackup', () => {
  it('writes the new text and keeps the old', () => {
    const name = fresh()
    const p = agentFile(name, 'regi\n')
    writeClaudeMdKeepingBackup(p, 'uj\n')
    expect(readFileSync(p, 'utf-8')).toBe('uj\n')
    expect(listPersonaBackups(name)).toHaveLength(1)
  })

  it('a copy that cannot be written is a warning and the rewrite still happens', () => {
    const name = fresh()
    const p = agentFile(name, 'regi\n')
    // the backup folder of this agent is a FILE, so mkdir/write under it fails
    mkdirSync(join(storeDir, 'persona-backups'), { recursive: true })
    writeFileSync(join(storeDir, 'persona-backups', name), 'nem mappa')
    writeClaudeMdKeepingBackup(p, 'uj\n')
    expect(readFileSync(p, 'utf-8')).toBe('uj\n')
    expect(warn).toHaveBeenCalled()
    expect(String(warn.mock.calls[0][1])).toContain('rewrite goes on')
  })
})

describe('the scaffold really goes through it', () => {
  it('END TO END: a line added inside a generated block is replaced by the scaffold, and the copy still has it', () => {
    const name = fresh()
    const BEGIN = '<!-- BEGIN GENERATED: fleet-auth (auto-generated, do not edit by hand) -->'
    const END = '<!-- END GENERATED: fleet-auth -->'
    const p = agentFile(name, `# ${name}\n\nsaját rész\n\n${BEGIN}\nrégi tartalom\nKEZZEL BEIRT SOR A BLOKKON BELUL\n${END}\n`)
    ensureFleetAuthSection(name)
    const now = readFileSync(p, 'utf-8')
    expect(now).not.toContain('KEZZEL BEIRT SOR A BLOKKON BELUL')
    expect(now).toContain('saját rész')
    const files = listPersonaBackups(name)
    expect(files).toHaveLength(1)
    expect(readFileSync(join(personaBackupDir(name), files[0]), 'utf-8')).toContain('KEZZEL BEIRT SOR A BLOKKON BELUL')
  })

  it('a second run with nothing to change adds no copy and no write', () => {
    const name = fresh()
    agentFile(name, `# ${name}\n`)
    ensureFleetAuthSection(name)           // adds the block: one copy of the block-less file
    const after = listPersonaBackups(name)
    ensureFleetAuthSection(name)           // idempotent: nothing changes
    expect(listPersonaBackups(name)).toEqual(after)
  })

  it('NO REWRITE OF A CLAUDE.md BYPASSES THE DOOR: every atomicWriteFileSync(claudeMdPath, ...) in agent-scaffold.ts is gone', () => {
    const src = readFileSync(join(__dirname, '..', 'web', 'agent-scaffold.ts'), 'utf-8')
    expect(src).not.toMatch(/atomicWriteFileSync\(\s*claudeMdPath\s*,/)
    expect((src.match(/writeClaudeMdKeepingBackup\(claudeMdPath,/g) ?? []).length).toBe(12)
  })
})
