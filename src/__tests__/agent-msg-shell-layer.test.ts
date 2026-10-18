/**
 * MSGIDEZES927 (card 639c7ba5): the usage line of scripts/agent-msg.sh said "plain text (quotes / newlines OK) --
 * no quoting pitfalls". True for the JSON layer, false for the SHELL layer: the calling shell executes a
 * `backtick word` and a $(command) inside double quotes BEFORE the helper starts, so the text it receives is
 * already damaged (measured 2026-09-27: a hook name and a command name vanished from a real message).
 *
 * This file pins the claim the header now makes, by running the helper against a local stub server:
 *   - the route the header recommends (STDIN, quoted heredoc) delivers backticks, $(...), $VAR and quotes verbatim;
 *   - the argument route in double quotes does NOT (that is what the header warns about);
 *   - the header and the reliability doc keep saying so.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const REPO = process.cwd()
const SCRIPT = join(REPO, 'scripts', 'agent-msg.sh')

let server: Server
let base = ''
let tmp = ''
let tokenFile = ''
const received: string[] = []

beforeAll(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'agent-msg-shell-'))
  tokenFile = join(tmp, 'token')
  writeFileSync(tokenFile, 'test-token')
  server = createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      try { received.push((JSON.parse(body) as { content: string }).content) } catch { received.push('<unparseable>') }
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('{"id":1,"status":"pending"}')
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
})
afterAll(() => { server.close(); rmSync(tmp, { recursive: true, force: true }) })

// async on purpose: spawnSync would block this process's event loop, and the stub server lives in it
function run(script: string): Promise<{ out: string; sent: string | undefined }> {
  const before = received.length
  return new Promise((resolve) => {
    const child = spawn('bash', ['-c', script], {
      env: { ...process.env, MARVEEN_API_BASE: base, MARVEEN_TOKEN_FILE: tokenFile, MARVEEN_QUEUE_WARN_AT: '0' },
    })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', () => resolve({ out, sent: received.length > before ? received[received.length - 1] : undefined }))
  })
}

// the text that was damaged in the real incident: a hook name and a command name in backticks / $( )
const TEXT = 'a `pre-merge-commit` hook es a $(git var GIT_AUTHOR_IDENT) parancs, $HOME es "idezet" es \\ perjel'

describe('agent-msg.sh: the STDIN + quoted-heredoc route delivers the text verbatim', () => {
  it('backticks, $(...), $VAR, double quotes and a backslash arrive unchanged', async () => {
    const r = await run(`bash ${JSON.stringify(SCRIPT)} igor hex - <<'MSG'\n${TEXT}\nMSG`)
    expect(r.out).toContain('OK id=1')
    expect(r.sent).toBe(TEXT)
  })

  it('`- < file` and a pipe from cat are the same route', async () => {
    const f = join(tmp, 'msg.txt')
    writeFileSync(f, TEXT)
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex - < ${JSON.stringify(f)}`)).sent).toBe(TEXT)
    expect((await run(`cat ${JSON.stringify(f)} | bash ${JSON.stringify(SCRIPT)} igor hex -`)).sent).toBe(TEXT)
  })
})

describe('agent-msg.sh: the argument route in double quotes loses text BEFORE the helper starts (what the header warns about)', () => {
  it('a `backtick word` and a $(command) are replaced by their output; the helper cannot know', async () => {
    const r = await run(`bash ${JSON.stringify(SCRIPT)} igor hex "a \`echo ELTUNT\` hook es a $(echo MASIK) parancs"`)
    expect(r.out).toContain('OK id=1')
    // the helper reports success and sends what it was given: the words are gone, their OUTPUT is there
    expect(r.sent).toBe('a ELTUNT hook es a MASIK parancs')
  })

  it('NOT the same route: echo with double quotes expands first, exactly like the argument', async () => {
    const r = await run(`echo "a \`echo ELTUNT\` hook" | bash ${JSON.stringify(SCRIPT)} igor hex -`)
    expect(r.sent).toBe('a ELTUNT hook')
  })

  it('single quotes keep them (the other half of the header\'s claim)', async () => {
    const r = await run(`bash ${JSON.stringify(SCRIPT)} igor hex 'a \`pre-merge-commit\` hook es a $(git var) parancs'`)
    expect(r.sent).toBe('a `pre-merge-commit` hook es a $(git var) parancs')
  })
})

describe('the documentation says it', () => {
  const header = readFileSync(SCRIPT, 'utf8').split('\n').slice(0, 40).join('\n')
  it('the script header names the shell layer, the executed backtick / $( ), and the quoted-heredoc route', () => {
    expect(header).toMatch(/EXECUTED by the\s*#?\s*calling shell/)
    expect(header).toContain("<<'MSG'")
    expect(header).toContain('RUNS AS A SHELL COMMAND')
    expect(header).toContain('Empty lines at the END')
    expect(header).toContain('JSON-encoded with json.dumps')
    // the sentence that was true for one layer only must not come back
    expect(header).not.toContain('no quoting pitfalls')
  })
  it('docs/inter-agent-send-reliability.md carries the same warning', () => {
    const doc = readFileSync(join(REPO, 'docs', 'inter-agent-send-reliability.md'), 'utf8')
    expect(doc).toContain('cannot see is what your shell did to the argument first')
    expect(doc).toContain("<<'MSG'")
    expect(doc).toContain('RUNS AS')
    expect(doc).toContain('empty lines at the END of the text')
  })
  // Sam 3566: the round-2 commit dropped these two sentences without saying so, and the tests above only look
  // for the NEW text, so nothing noticed. They were there before this card and stay.
  it('docs/inter-agent-send-reliability.md keeps what it said before this card', () => {
    const doc = readFileSync(join(REPO, 'docs', 'inter-agent-send-reliability.md'), 'utf8')
    expect(doc).toContain('Base dir is auto-detected, port from')
    expect(doc).toContain('`MARVEEN_WEB_PORT` (default 3420), so it runs from any CWD / any install.')
    expect(doc).toContain('The generated agent `CLAUDE.md` (from `templates/CLAUDE.md.template`) now documents this rule')
    expect(doc).toContain('so every agent in every fleet verifies its sends by default.')
  })
})

// Sam 3550: the limits of the recommended route, pinned as they behave (so the docs cannot drift from them).
describe('the limits of the STDIN + quoted-heredoc route', () => {
  it('a line that is exactly the delimiter ends the heredoc; the rest RUNS in the calling shell and the helper still says OK', async () => {
    const r = await run(`bash ${JSON.stringify(SCRIPT)} igor hex - <<'MSG'\nelso sor\nMSG\nharmadik\nMSG`)
    expect(r.out).toContain('OK id=1')
    expect(r.sent).toBe('elso sor')                       // shortened
    expect(r.out).toContain('harmadik: command not found') // the tail was executed as a command
  })

  it('NEGATIVE CONTROL: another delimiter, or a file, carries the same text whole', async () => {
    const text = 'elso sor\nMSG\nharmadik'
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex - <<'ZZEND'\n${text}\nZZEND`)).sent).toBe(text)
    const f = join(tmp, 'msg2.txt')
    writeFileSync(f, text)
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex - < ${JSON.stringify(f)}`)).sent).toBe(text)
  })

  it('a backslash survives in double quotes except before $ ` " \\ and a newline; empty lines at the END of heredoc text are dropped', async () => {
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex "C:\\temp\\new"`)).sent).toBe('C:\\temp\\new')
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex "a \\$HOME b"`)).sent).toBe('a $HOME b')
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex - <<'MSG'\nsor\n\n\nMSG`)).sent).toBe('sor')
    expect((await run(`bash ${JSON.stringify(SCRIPT)} igor hex - <<'MSG'\n\nelso\n\nutolso\nMSG`)).sent).toBe('\nelso\n\nutolso')
  })
})
