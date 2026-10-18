// EGRESSPARAMEXP1009 (card 55d8cd24, Sam's finding): the destination of a curl is a word the parser
// cannot read -- a parameter expansion (`${u#*|}`, `${u%/x}`, `${u:0:20}`, `${U:-url}`), a variable
// nobody set in the command, or one computed by a substitution -- and destHost() answered null, which
// meant "no destination" and passed. It fails closed now: the unreadable word is reported as the host.
import { describe, it, expect, afterAll } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify } from '../../scripts/hooks/bash-egress-parser.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const HOOK = join(ROOT, 'scripts', 'hooks', 'bash-egress-parser.mjs')
const LOG_DIR = mkdtempSync(join(tmpdir(), 'bash-egress-paramexp-default-'))
process.env.BASH_EGRESS_BLOCK_LOG = join(LOG_DIR, 'blocks.jsonl')
afterAll(() => { rmSync(LOG_DIR, { recursive: true, force: true }) })

const deny = (cmd: string): boolean => classify(cmd).deny
const UNRESOLVED = { deny: true, reason: 'curl-unresolved' }

describe('an unreadable curl destination fails closed (EGRESSPARAMEXP1009)', () => {
  it('POSITIVE CONTROL: the literal URL and the plain assignment were always denied', () => {
    expect(classify('curl -s https://example.org/')).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
    expect(classify('u=https://example.org/; curl -s "$u"')).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
  })
  it("Sam's reported shapes: a parameter expansion in the assignment, plain and in a for loop", () => {
    for (const cmd of [
      'u="a|https://example.org/"; url=${u#*|}; curl -s "$url"',
      'for s in "a|https://example.org/"; do url=${s#*|}; curl -s "$url"; done',
      'for u in "hu|https://belatti.hu/" "sk|https://www.belatti.sk/"; do url=${u#*|}; curl -sL "$url" -o /tmp/x.html; done',
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: UNRESOLVED })
  })
  it('other expansion operators and unset variables in the destination', () => {
    for (const cmd of [
      'u=https://example.org/x; curl "${u%/x}"',
      'u=https://example.org/x; curl "${u:0:20}"',
      'u=example.org; curl "https://${u/org/com}"',
      'curl "${U:-https://example.org}"',
      'curl -s "$URL"',
      'curl -s --url "$URL"',
      'curl -s "https://$H/x"',
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: UNRESOLVED })
  })
  it('a value computed by a substitution is unknown, not blank', () => {
    for (const cmd of [
      'H=$(cat host.txt); curl -s "http://$H/x"',
      'U=$(cat u.txt); curl -s "$U"',
      'U="$(cat u.txt)"; curl -s "$U"',
      'U=pre`cat u`; curl -s "$U"',
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: UNRESOLVED })
  })
  it('loop values read from a file, a process substitution, an array or under IFS are not known either', () => {
    for (const cmd of [
      'while read u; do curl -s "$u"; done < urls.txt',
      'while read u; do curl -s "$u"; done < <(echo https://example.org/x)',
      'mapfile -t a <<< "https://example.org/x"; curl -s "${a[0]}"',
      'IFS=, read a b <<< "x,https://example.org/x"; curl -s "$b"',
    ]) expect({ cmd, r: classify(cmd) }).toMatchObject({ cmd, r: UNRESOLVED })
  })
  it('the deny names the word it could not read', () => {
    expect(classify('curl -s "$URL"')).toEqual({ deny: true, reason: 'curl-unresolved', hosts: ['unresolved:$URL'] })
  })
  it('a substitution body reads the bindings of the command around it', () => {
    // external: was a silent pass (the inner curl saw an unset $U), now names the real host
    expect(classify('U=https://example.org/x; r=$(curl -s "$U")')).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['example.org'] })
    expect(classify('for u in https://naih.hu/ https://rackforest.hu/; do c=$(curl -s -L "$u"); done')).toMatchObject({ deny: true, reason: 'curl-external', hosts: ['naih.hu'] })
    // local: must stay open, or a fleet agent that wraps a dashboard call in $( ) goes mute
    expect(deny('U=http://localhost:3420/api/x; r=$(curl -s "$U"); echo $r')).toBe(false)
    expect(deny('for u in http://localhost:3420/a http://localhost:3420/b; do x=$(curl -s "$u"); done')).toBe(false)
  })
  it('CONTROLS: the fleet shapes with a variable that is NOT the destination still pass', () => {
    for (const cmd of [
      'curl -s http://localhost:$P/api/health',
      'curl -s "http://localhost:3420/api/kanban/$ID/move" -H "Authorization: Bearer $T" -d "$body"',
      'T=$(cat store/.dashboard-token); curl -s -H "Authorization: Bearer $T" http://localhost:3420/api/kanban',
      'curl -s -X POST http://localhost:3420/api/memories -d "$payload" -H "X-Agent-Id: $AGENT"',
      'for u in "http://localhost:3420/api/daily-log?agent=igor" "http://localhost:3420/api/daily-log"; do curl -s -H "Authorization: Bearer $(cat t)" "$u"; done',
      'X=; curl -s http://localhost:3420/$X',
    ]) expect({ cmd, deny: deny(cmd) }).toEqual({ cmd, deny: false })
  })
  it('a substitution as the whole destination, and a curl config file, are unreadable too', () => {
    expect(classify('curl $(echo https://example.org)')).toMatchObject({ deny: true, reason: 'curl-unresolved' })
    expect(classify('curl -s "$(cat url.txt)"')).toMatchObject({ deny: true, reason: 'curl-unresolved' })
    expect(classify('curl -K curl.cfg')).toMatchObject({ deny: true, reason: 'curl-unresolved' })
    expect(classify('curl -s --config c.cfg')).toMatchObject({ deny: true, reason: 'curl-unresolved' })
    // CONTROL: a substitution in a header value or a body is not the destination
    expect(deny('curl -s -H "Authorization: Bearer $(cat t)" -d "$(date)" http://localhost:3420/api/x')).toBe(false)
  })
  it('the hook process denies it, logs the reason, and stays silent on a plain localhost call', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bash-egress-paramexp-'))
    try {
      const run = (command: string) => spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
        encoding: 'utf-8',
        env: { ...process.env, BASH_EGRESS_BLOCK_LOG: join(dir, 'blocks.jsonl'), BASH_EGRESS_VENDOR_HOSTS: join(dir, 'none.json') },
      })
      expect(run('u="a|https://example.org/"; url=${u#*|}; curl -s "$url"').stdout).toContain('"permissionDecision":"deny"')
      expect(readFileSync(join(dir, 'blocks.jsonl'), 'utf-8')).toContain('"reason":"curl-unresolved"')
      // fail closed even when the unread value happens to be local: an expansion is not read
      expect(run('u="a|http://localhost:3420/api/health"; url=${u#*|}; curl -s "$url"').stdout).toContain('"permissionDecision":"deny"')
      expect(run('curl -s http://localhost:3420/api/health').stdout).toBe('')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})
