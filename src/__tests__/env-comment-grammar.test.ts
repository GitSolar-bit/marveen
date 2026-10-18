import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseEnvContent, stripTrailingComment } from '../env-parse.js'

// Card 6600f89b (HEX 3549): a trailing ` #` comment in a .env value. Outside quotes a `#` with a space or tab
// before it starts a comment, and the comment plus the whitespace before it are dropped; a `#` without a space
// stays; a value quoted as a whole is untouched; a quote that never closes switches the rule off.
// The rule exists in THREE readers (src/env-parse.ts, scripts/hooks/persona-change-notify.py, the awk in
// scripts/install-prod-tree-guard-hook.sh). persona-guard-env-parity.test.ts pins the Python one; this file
// pins the rule itself and the installer's awk.
const K = 'SYSTEM_SENDER_IDS'
const read = (text: string) => parseEnvContent(text)[K]

// [.env line, expected value]
const CASES: Array<[string, string]> = [
  [`${K}=abc # note`, 'abc'],
  [`${K}=abc\t# note`, 'abc'],
  [`${K}=abc   #   note`, 'abc'],
  [`${K}= # only a comment`, ''],
  [`${K}=a#b`, 'a#b'],
  [`${K}=#abc`, '#abc'],
  [`${K}=http://x/#frag`, 'http://x/#frag'],
  [`${K}=http://x/#frag # note`, 'http://x/#frag'],
  [`${K}="a #b"`, 'a #b'],
  [`${K}='a #b'`, 'a #b'],
  [`${K}="a" # note`, 'a'],
  [`${K}='a' # note`, 'a'],
  // Sam 3575: a value that starts AND ends with the same quote but closes earlier is a quoted value plus a
  // comment, not a value quoted as a whole
  [`${K}="a" # "b"`, 'a'],
  [`${K}="a" # see "docs"`, 'a'],
  [`${K}='a' # it's 'x'`, 'a'],
  [`${K}="x"#y`, '"x"#y'],                  // no space before the #: no comment, and the end is not a quote
  [`${K}="a"b"`, 'a"b'],                    // the old rule, unchanged: starts and ends with a quote, so one pair goes
  [`${K}="a \\"b\\" # c"`, 'a \\"b\\" # c'],  // no escapes: the inner quotes close and reopen, the hash is inside a quote
  [`${K}="a\\"b" # c`, '"a\\"b" # c'],     // NAMED LIMIT: a backslash does not protect a quote, so this comment stays
  [`${K}=a\u00a0# b`, 'a\u00a0# b'],         // a no-break space is not a space or a tab
  [`${K}=it's # x`, "it's # x"],            // a quote that never closes: no cut
  [`${K}="a # b`, '"a # b'],
  [`${K}=a "b # c" d`, 'a "b # c" d'],      // the hash is inside a quote
  [`${K}=a "b c" # d`, 'a "b c"'],
  [`${K}=a # b # c`, 'a'],
  [`${K}=a # b=c`, 'a'],
  [`${K}=1 # on\r`, '1'],
  [`${K}=a,b # c`, 'a,b'],
  [`${K}=`, ''],
]

describe('stripTrailingComment / parseEnvContent', () => {
  for (const [line, want] of CASES) {
    it(JSON.stringify(line), () => { expect(read(`${line}\n`)).toBe(want) })
  }
  it('a whole-line comment and a commented-out key are still skipped', () => {
    expect(parseEnvContent(`# ${K}=1\n  # ${K}=2\n`)).toEqual({})
  })
  it('the helper leaves a value alone when there is nothing to cut', () => {
    expect(stripTrailingComment('plain')).toBe('plain')
    expect(stripTrailingComment('a#b')).toBe('a#b')
    expect(stripTrailingComment('"a #b"')).toBe('"a #b"')
  })
})

// The installer's awk, extracted from the installer itself so the test runs the code that ships.
function installerAwk(): string {
  const text = readFileSync(join(__dirname, '..', '..', 'scripts', 'install-prod-tree-guard-hook.sh'), 'utf-8')
  const m = /ENV_SYSTEM_SENDERS="\$\(awk '\n([\s\S]*?)' "\$PROD_ROOT\/\.env"/.exec(text)
  if (!m) throw new Error('the awk reader was not found in the installer')
  return m[1]
}
function awkValue(env: string): string | null {
  const dir = mkdtempSync(join(tmpdir(), 'env-comment-awk-'))
  try {
    const file = join(dir, '.env')
    writeFileSync(file, env)
    const r = spawnSync('awk', [installerAwk(), file], { encoding: 'utf-8' })
    expect(r.status, r.stderr).toBe(0)
    return r.stdout === '' ? null : r.stdout.replace(/\n$/, '')
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

describe('the installer awk reads the comment rule like src/env-parse.ts', () => {
  for (const [line, want] of CASES) {
    it(JSON.stringify(line), () => {
      const env = `${line}\n`
      expect(awkValue(env)).toBe(want)
      expect(awkValue(env)).toBe(read(env) ?? null)
    })
  }
  it('last wins, with a comment on each line', () => {
    expect(awkValue(`${K}=0 # off\n${K}=1 # on\n`)).toBe('1')
  })
})
