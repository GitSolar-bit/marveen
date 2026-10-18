import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseEnvContent } from '../env-parse.js'

// The persona guard hook is Python and reads the install .env itself. If its
// reader drifts from the product's grammar (src/env-parse.ts), the same .env
// answers differently for the hook and for the app: an owner who writes
// PERSONA_GUARD_NOTIFY="1" would get no alert and no warning. This pins the two
// together on a corpus, comparing the RAW parsed value, not just the on/off verdict.

const HOOK = join(__dirname, '..', '..', 'scripts', 'hooks', 'persona-change-notify.py')
const KEY = 'PERSONA_GUARD_NOTIFY'

const CORPUS: Record<string, string | Buffer> = {
  plain: `${KEY}=1\n`,
  'double quoted': `${KEY}="1"\n`,
  'single quoted': `${KEY}='1'\n`,
  'indented': `   ${KEY}=1\n`,
  'spaces around =': `${KEY} = 1\n`,
  'value with spaces': `${KEY}=  yes  \n`,
  CRLF: `WEB_PORT=3420\r\n${KEY}=1\r\n`,
  'last wins': `${KEY}=0\n${KEY}=1\n`,
  'commented out': `# ${KEY}=1\n`,
  'inline comment': `${KEY}=1 # on\n`,
  // card 6600f89b: the trailing-comment rule, in the product and in the hook alike
  'inline comment after a tab': `${KEY}=1\t# on\n`,
  'hash without a space stays': `${KEY}=a#b\n`,
  'value that is only a hash word': `${KEY}=#abc\n`,
  'only a comment': `${KEY}= # note\n`,
  'quoted value keeps its hash': `${KEY}="a #b"\n`,
  'single quoted value keeps its hash': `${KEY}='a #b'\n`,
  'quoted value then a comment': `${KEY}="a" # c\n`,
  'quoted both ends, comment-like inside': `${KEY}="a" # "b"\n`,
  'quoted value, comment ends with the same quote': `${KEY}="a" # see "docs"\n`,
  'single quoted value, comment with quotes': `${KEY}='a' # it's 'x'\n`,
  'hash right after the closing quote': `${KEY}="x"#y\n`,
  'backslash does not protect a quote': `${KEY}="a\\"b" # c\n`,
  'no-break space before the hash': `${KEY}=a\u00a0# b\n`,
  'unclosed quote switches the rule off': `${KEY}=it's # x\n`,
  'unclosed double quote': `${KEY}="a # b\n`,
  'hash inside a mid-value quote': `${KEY}=a "b # c" d\n`,
  'comment after a mid-value quote': `${KEY}=a "b c" # d\n`,
  'several hashes': `${KEY}=a # b # c\n`,
  'equals in the comment': `${KEY}=a # b=c\n`,
  'url fragment then a comment': `${KEY}=http://x/#frag # note\n`,
  'CRLF with a comment': `${KEY}=1 # on\r\n`,
  'last wins, comment on the last': `${KEY}=0 # off\n${KEY}=1 # on\n`,
  'export prefix': `export ${KEY}=1\n`,
  'mismatched quotes': `${KEY}="1'\n`,
  'lone quote': `${KEY}="\n`,
  'empty value': `${KEY}=\n`,
  'no equals': `${KEY}\n`,
  'quoted empty': `${KEY}=""\n`,
  'other key only': `WEB_PORT=1\n`,
  'equals in value': `${KEY}=a=b\n`,
  'BOM first line': `\ufeff${KEY}=1\n`,
  // A lone \r is not a line break for the product (it splits on \n only).
  'lone CR, key first': `${KEY}=1\rX=2`,
  'lone CR, key second': `X=0\r${KEY}=1`,
  // Invalid UTF-8 (a Latin-2 comment): Node decodes to U+FFFD and carries on.
  'invalid UTF-8 before the key': Buffer.concat([Buffer.from('FOO='), Buffer.from([0xff, 0xfe]), Buffer.from(`\n${KEY}=1\n`)]),
}

function hookValue(env: string | Buffer): string | null {
  const root = mkdtempSync(join(tmpdir(), 'persona-parity-'))
  try {
    mkdirSync(join(root, 'scripts', 'hooks'), { recursive: true })
    copyFileSync(HOOK, join(root, 'scripts', 'hooks', 'persona-change-notify.py'))
    // Raw bytes: a text-mode write would turn \r\n into something else on Windows hosts.
    spawnSync('python3', ['-c', `open(${JSON.stringify(join(root, '.env'))},'wb').write(${JSON.stringify((typeof env === 'string' ? Buffer.from(env, 'utf-8') : env).toString('latin1'))}.encode('latin1'))`])
    const r = spawnSync(
      'python3',
      [
        '-c',
        `import importlib.util,json,sys;s=importlib.util.spec_from_file_location('h',${JSON.stringify(join(root, 'scripts', 'hooks', 'persona-change-notify.py'))});m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(m._env_file_value(${JSON.stringify(join(root, '.env'))},${JSON.stringify(KEY)})))`,
      ],
      { encoding: 'utf-8' },
    )
    expect(r.status, r.stderr).toBe(0)
    return JSON.parse(r.stdout.trim())
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

describe('persona guard .env reader matches src/env-parse.ts', () => {
  for (const [label, content] of Object.entries(CORPUS)) {
    it(label, () => {
      const product = parseEnvContent(typeof content === 'string' ? content : content.toString('utf-8'))[KEY]
      expect(hookValue(content)).toBe(product === undefined ? null : product)
    })
  }
})
