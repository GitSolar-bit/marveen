// EGRESSWRAP1009 (card 55d8cd24, Sam's second finding): the body of `bash -c` / `sh -c` / `eval` was
// judged for git ALONE (the recursive call was hard-wired to gitOnly), so a LITERAL external curl
// inside a wrapper passed. The body is a command line of its own and is judged in full now; a command
// word that is an unset variable or a substitution fails closed when the line carries an external URL.
import { describe, it, expect, afterAll } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify } from '../../scripts/hooks/bash-egress-parser.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const HOOK = join(ROOT, 'scripts', 'hooks', 'bash-egress-parser.mjs')
const LOG_DIR = mkdtempSync(join(tmpdir(), 'bash-egress-wrap-default-'))
process.env.BASH_EGRESS_BLOCK_LOG = join(LOG_DIR, 'blocks.jsonl')
afterAll(() => { rmSync(LOG_DIR, { recursive: true, force: true }) })

const deny = (cmd: string): boolean => classify(cmd).deny
const EXT = 'https://example.org/'

describe('a shell wrapper and an opaque command word (EGRESSWRAP1009)', () => {
  it('POSITIVE CONTROL: the bare literal was always denied', () => {
    expect(classify(`curl -s ${EXT}`)).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
  })
  it('bash -c / sh -c / eval carrying a literal external curl are denied, and name the host', () => {
    for (const cmd of [
      `bash -c 'curl -s ${EXT}'`,
      `sh -c "curl -s ${EXT}"`,
      `bash -lc 'curl -s ${EXT}'`,
      `/bin/bash -c 'cd /tmp && curl -s ${EXT}'`,
      `eval curl ${EXT}`,
      `eval "curl -s ${EXT}"`,
      `env FOO=1 bash -c 'curl -s ${EXT}'`,
      `bash -c "bash -c 'curl -s ${EXT}'"`,
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: { deny: true, reason: 'curl-external', hosts: ['example.org'] } })
  })
  it('the body of a wrapper in a loop and behind an unreadable value is judged too', () => {
    expect(deny(`for u in ${EXT}; do bash -c "curl -s $u"; done`)).toBe(true)
    expect(deny(`bash -c 'curl -s "$URL"'`)).toBe(true)
    expect(deny('bash -c "curl -s $(cat url.txt)"')).toBe(true)
  })
  it('a command word that is a variable resolves, or fails closed when it does not', () => {
    expect(classify(`c=curl; $c -s ${EXT}`)).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
    expect(classify(`c="curl -s"; $c ${EXT}`)).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
    expect(classify(`$X ${EXT}`)).toMatchObject({ deny: true, reason: 'command-unresolved', hosts: ['example.org'] })
    expect(classify(`$(echo curl) -s ${EXT}`)).toMatchObject({ deny: true, reason: 'command-unresolved', hosts: ['example.org'] })
    expect(classify(`"$C" ${EXT}`)).toMatchObject({ deny: true, reason: 'command-unresolved' })
  })
  it('a QUOTED command word is the command (Sam, round 2)', () => {
    for (const cmd of [
      `c=curl; "$c" ${EXT}`,
      `c=curl; "\${c}" -s ${EXT}`,
      `"curl" ${EXT}`,
      `"/usr/bin/curl" -s ${EXT}`,
      `(curl ${EXT})`,
      `"python3" -c "import urllib.request; urllib.request.urlopen('${EXT}')"`,
    ]) expect({ cmd, d: deny(cmd) }).toEqual({ cmd, d: true })
    expect(deny('"curl" -s http://localhost:3420/api/health')).toBe(false)
  })
  it('a wrapper whose body is a substitution: an external URL in the substitution is a deny', () => {
    for (const cmd of [
      `eval "$(echo curl ${EXT})"`,
      `bash -c "$(echo curl ${EXT})"`,
      `eval $(echo curl ${EXT})`,
      `U=${EXT}; bash -c "$(echo curl $U)"`,
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: { deny: true, reason: 'wrapper-substitution-external', hosts: ['example.org'] } })
    // CONTROLS: the idioms that use eval / bash -c on a substitution without an external URL pass
    for (const cmd of ['eval "$(ssh-agent -s)"', 'eval "$(pyenv init -)"', 'bash -c "$(cat run.sh)"', 'eval "$(echo curl http://localhost:3420/x)"'])
      expect({ cmd, d: deny(cmd) }).toEqual({ cmd, d: false })
  })
  it('CONTROLS: local calls inside wrappers, and an opaque word with no external URL, still pass', () => {
    for (const cmd of [
      'bash -c "curl -s http://localhost:3420/api/health"',
      `sh -c 'curl -s -H "Authorization: Bearer $(cat t)" http://127.0.0.1:3420/api/x'`,
      'eval curl -s http://localhost:3420/api/health',
      'c=curl; $c -s http://localhost:3420/api/health',
      '$PY script.py',
      '$X --version',
      `echo $(date) ${EXT}`,
      "bash -c 'echo hello'",
      'bash ./fetch.sh',
    ]) expect({ cmd, deny: deny(cmd) }).toEqual({ cmd, deny: false })
  })
  it('THE NAMED LIMIT (pinned): a message heredoc to a script that QUOTES a wrapped curl is denied, like a bare curl line', () => {
    // bash-git-force-push.test.ts pins that ANY shell heredoc is read as a command line (`bash /dev/stdin`
    // and `bash script.sh` cannot be told apart); the wrappers are judged inside it now as well. The ways
    // round are the same: the text in a file (`< msg.txt`), or `"$(cat msg.txt)"` as an argument.
    const quoted = `bash scripts/agent-msg.sh hex igor - <<'EOF'\nbash -c 'curl -s ${EXT}'\nEOF`
    expect(deny(quoted)).toBe(true)
    expect(deny("bash scripts/agent-msg.sh hex igor - < /home/u/work/msg.txt")).toBe(false)
    expect(deny(`bash scripts/agent-msg.sh hex igor "$(cat /home/u/work/msg.txt)"`)).toBe(false)
    // gitOnly (the main agent) never judges the curl, so its own messages are unaffected
    expect(classify(quoted, 0, new Set(), new Set(), true).deny).toBe(false)
  })
  it('gitOnly (the main agent wiring) still sees nothing but the force-push, wrapper or not', () => {
    const git = (cmd: string) => classify(cmd, 0, new Set(), new Set(), true)
    expect(git(`bash -c 'curl -s ${EXT}'`).deny).toBe(false)
    expect(git(`$X ${EXT}`).deny).toBe(false)
    expect(git("bash -c 'git push -f origin main'")).toMatchObject({ deny: true, reason: 'git-force-push' })
  })
  it('the hook process denies a wrapped curl and stays silent on its localhost twin', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bash-egress-wrap-'))
    try {
      const run = (command: string) => spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
        encoding: 'utf-8',
        env: { ...process.env, BASH_EGRESS_BLOCK_LOG: join(dir, 'blocks.jsonl'), BASH_EGRESS_VENDOR_HOSTS: join(dir, 'none.json') },
      })
      expect(run(`bash -c 'curl -s ${EXT}'`).stdout).toContain('"permissionDecision":"deny"')
      expect(run("bash -c 'curl -s http://localhost:3420/api/health'").stdout).toBe('')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})
