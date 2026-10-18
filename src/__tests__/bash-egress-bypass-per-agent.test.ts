// BYPASSPERAGENT1014 (card 521f1f39, owner Telegram 4554): the shell routes to the web that are not curl and not an
// interpreter one-liner -- yt-dlp, `npx playwright`, `git clone`, `git ls-remote`, wget, `pip download` -- are decided
// PER AGENT. igor: git clone + npx playwright. willy: yt-dlp + npx playwright. zola, sam, ponder: none. The main agent:
// not covered. Standing rule 11 (Telegram 4539): INVERTED PROOF -- the default is deny; a call is silent only when the
// agent is allowed the shape or the call is PROVABLY without network. The expectations below are written out by hand and
// do NOT read BYPASS_ALLOW, so a wrong table cannot make its own test pass.
import { describe, it, expect, afterAll } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify, agentFromTranscript, BYPASS_ALLOW, BYPASS_SHAPES } from '../../scripts/hooks/bash-egress-parser.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const HOOK = join(ROOT, 'scripts', 'hooks', 'bash-egress-parser.mjs')
const LOG_DIR = mkdtempSync(join(tmpdir(), 'bash-egress-bypass-'))
process.env.BASH_EGRESS_BLOCK_LOG = join(LOG_DIR, 'blocks.jsonl')
afterAll(() => { rmSync(LOG_DIR, { recursive: true, force: true }) })

type Shape = 'yt-dlp' | 'playwright' | 'git-clone' | 'git-ls-remote' | 'wget' | 'pip-download'
const verdict = (cmd: string, agent: string | null, gitOnly = false) =>
  classify(cmd, 0, new Set(), new Set(), gitOnly, { env: {}, loops: {}, agent })

// Each shape in many spellings. Every one must be the SAME shape for the matrix below.
const SPELLINGS: Record<Shape, string[]> = {
  'yt-dlp': [
    'yt-dlp https://example.org/watch?v=1',
    'yt-dlp -x --audio-format mp3 https://example.org/v',
    'youtube-dl https://example.org/v',
    '/usr/local/bin/yt-dlp https://example.org/v',
    'env FOO=1 timeout 60 yt-dlp https://example.org/v',
    'python3 -m yt_dlp https://example.org/v',
    'pipx run yt-dlp https://example.org/v',
    'uvx yt-dlp https://example.org/v',
    'cd /tmp && yt-dlp https://example.org/v',
    'bash -c "yt-dlp https://example.org/v"',
    '"yt-dlp" https://example.org/v',
  ],
  playwright: [
    'npx playwright screenshot https://example.org/ out.png',
    'npx playwright install chromium',
    'npx -y playwright@1.50.0 install',
    'npx --yes playwright screenshot https://example.org/ a.png',
    'pnpm dlx playwright install',
    'npm exec playwright -- install',
    'bunx playwright install',
    'playwright install',
    "npx -c 'playwright install chromium'", 'npx --package=playwright true',
    'npx @playwright/test test',
    'python3 -m playwright install',
    'cd /tmp && npx playwright screenshot https://example.org/ a.png',
  ],
  'git-clone': [
    'git clone https://github.com/a/b.git',
    'git clone --depth 1 https://github.com/a/b.git /tmp/b',
    'git clone git@github.com:a/b.git',
    'git clone ssh://git@github.com/a/b.git',
    'git -C /tmp clone https://github.com/a/b.git',
    'git -c http.sslVerify=false clone https://github.com/a/b.git',
    '/usr/bin/git clone https://github.com/a/b.git',
    'bash -c "git clone https://github.com/a/b.git"',
    'timeout 100 git clone -b main https://github.com/a/b.git',
    'git clone git://example.org/a.git',
    // the same download without the word `clone` (HEX 3769): for an agent without the allowance a URL literal is denied
    'git fetch https://example.org/r.git main', 'git -C r fetch https://example.org/r.git', 'git init r && git -C r pull https://example.org/r.git',
    'git fetch git@example.org:r.git', 'git pull ssh://git@example.org/r.git main', 'git fetch --upload-pack=x origin',
    'git fetch --recurse-submodules origin', 'git -c remote.o.url=https://example.org/r.git fetch o',
    'git remote add o https://example.org/r.git', 'git remote add -f o https://example.org/r.git', 'git remote set-url o https://example.org/r.git',
    'git remote add o https://example.org/r.git && git fetch o', 'git submodule add https://example.org/r.git sub',
    'git archive --remote=https://example.org/r.git HEAD', 'git archive --remote https://example.org/r.git HEAD', 'git archive --rem=https://example.org/r.git HEAD',
    'git clone -u /tmp/x /a/b', 'git clone --upload-pack /tmp/x /a/b', 'git -c --no-pager clone /a/b d', 'git clone -x /a/b d', 'git clone -qx /a/b d',
    'git clone file://example.org/r.git d', 'git clone file://localhost/x d',
    'git fetch example.org:r.git', 'git pull example.org:r.git main', 'git fetch -u origin', 'git fetch "$URL"',
  ],
  'git-ls-remote': [
    'git ls-remote origin',
    'git ls-remote --heads fork refs/heads/x',
    'git ls-remote https://github.com/a/b.git',
    'git ls-remote',
    'git -c credential.helper= ls-remote fork',
    'git ls-remote git@github.com:a/b.git',
    'echo x; git ls-remote origin | head',
  ],
  wget: [
    'wget https://example.org/f',
    'wget -q -O- https://example.org/f',
    '/usr/bin/wget https://example.org/f',
    'env wget https://example.org/f',
    'timeout 5 wget http://example.org/f',
    'cd /tmp && wget https://example.org/f',
    'wget2 https://example.org/f',
  ],
  'pip-download': [
    'pip download requests',
    'pip3 download -d /tmp/w requests',
    'python3 -m pip download requests',
    'pip3.11 download requests',
    'pip --quiet download requests',
  ],
}
// WHO may do WHAT, from the card (owner 4554), written by hand.
const ALLOWED: Record<string, Shape[]> = {
  igor: ['git-clone', 'playwright'],
  willy: ['yt-dlp', 'playwright'],
  zola: [], sam: [], ponder: [],
}
const SHAPES = Object.keys(SPELLINGS) as Shape[]

describe('the table pins the owner decision (owner 4554)', () => {
  it('BYPASS_ALLOW is exactly igor and willy, and nobody else', () => {
    expect(Object.keys(BYPASS_ALLOW).sort()).toEqual(['igor', 'willy'])
    expect([...BYPASS_ALLOW.igor].sort()).toEqual(['git-clone', 'playwright'])
    expect([...BYPASS_ALLOW.willy].sort()).toEqual(['playwright', 'yt-dlp'])
    expect([...BYPASS_SHAPES].sort()).toEqual([...SHAPES].sort())
  })
})

describe('the matrix: agent x shape x spelling', () => {
  for (const shape of SHAPES) {
    for (const cmd of SPELLINGS[shape]) {
      for (const agent of ['igor', 'willy', 'zola', 'sam', 'ponder'] as const) {
        const allowed = ALLOWED[agent].includes(shape)
        it(`${agent} / ${shape}: ${cmd}  ->  ${allowed ? 'allowed' : 'DENIED'}`, () => {
          const r = verdict(cmd, agent)
          if (allowed) expect(r).toMatchObject({ deny: false })
          else expect(r).toMatchObject({ deny: true, reason: `bypass-${shape}` })
        })
      }
    }
  }
})

describe('inverted proof: an agent that cannot be named has NO allowance', () => {
  for (const shape of SHAPES) {
    for (const cmd of SPELLINGS[shape]) {
      it(`unknown agent / ${shape}: ${cmd}`, () => {
        expect(verdict(cmd, null)).toMatchObject({ deny: true, reason: `bypass-${shape}` })
        expect(verdict(cmd, undefined as unknown as null)).toMatchObject({ deny: true, reason: `bypass-${shape}` })
      })
    }
  }
  it('a name that is not in the table (hex, a typo, an empty string) gets nothing either', () => {
    for (const a of ['hex', 'igorr', 'IGOR', '', 'igor ']) expect(verdict('git clone https://github.com/a/b.git', a)).toMatchObject({ deny: true })
  })
})

describe('the main agent is not covered (--git-only wiring)', () => {
  for (const shape of SHAPES) for (const cmd of SPELLINGS[shape]) {
    it(`gitOnly / ${shape}: ${cmd}`, () => { expect(verdict(cmd, null, true)).toMatchObject({ deny: false }) })
  }
})

describe('PROVABLY without network stays silent for an agent that is not allowed (zola)', () => {
  it.each([
    'yt-dlp --version', 'yt-dlp --help', 'yt-dlp -h', 'wget -h', 'wget --version', 'wget -V', 'wget --version 2>&1 | head -1', '/usr/bin/wget --version 2>&1 | head -1',
    'wget --version 2> /dev/null', 'wget --version > /tmp/v.txt', 'wget --version >/tmp/v.txt 2>&1', 'yt-dlp --version 2>/dev/null | head -1',
    'env wget --version 2>&1 | head -1', 'pip download --help', 'npx playwright --version', 'playwright --help',
    'git clone /home/x/repo /tmp/y', 'git clone ./repo y', 'git clone ../repo', 'git clone ~/repo y', 'git clone file:///home/x/repo',
    'git clone repo-dir copy',
    'git clone --depth 1 -b main /home/x/repo y', 'git ls-remote /home/x/repo', 'git ls-remote ./repo', 'git ls-remote file:///home/x/repo',
    // every option spelled out in the allowlist, the remote a path or file:///
    'git clone -q --bare /a/b c', 'git clone --depth=1 --branch=main /a/b c', 'git clone -qn /a/b c', 'git -C /tmp clone /a/b c',
    'git --no-pager clone /a/b c', 'git ls-remote --heads /a/b', 'git ls-remote -q --refs /a/b refs/heads/x', 'git clone -- /a/b c',
    'git clone --origin up /a/b c', 'git clone --revision v1 /a/b c', 'git clone --ref-format files /a/b c',
    // fetch / pull / archive / submodule / remote: a remote that is already NAMED (origin, fork) or a local path (HEX 3769)
    'git fetch', 'git fetch origin', 'git fetch fork some-branch', 'git fetch --all --prune', 'git fetch -p origin', 'git -C /a/b fetch origin',
    'git pull', 'git pull --ff-only origin main', 'git pull --rebase origin main', 'git fetch /a/b', 'git fetch file:///a/b',
    'git archive HEAD -o /tmp/a.tar', 'git archive --format=tar --prefix=x/ HEAD', 'git archive --remote=origin HEAD',
    'git remote add o /a/b', 'git remote set-url o ../b', 'git submodule add /a/b sub', 'git submodule add file:///a/b sub',
    'git remote -v', 'git remote show origin', 'git submodule status', 'git submodule set-url sub /a/b',
    // a config READ is not a redirect, even with a value pattern after the key
    'git config --get alias.dl clone', 'git config --get-all url.https://x/.insteadOf value', 'git config --unset alias.dl', 'git config --list',
    // a redirection word is not a positional argument
    // help is not a download (not for ls-remote, where -h is --heads)
    'git clone -h', 'git clone --help', 'git fetch -h', 'git fetch --help', 'git ls-remote --help',
    'git clone -q /a/b c 2>&1', 'git clone -q /a/b c 2>/dev/null', 'git remote add o /a/b 2>/dev/null', 'git fetch -q origin 2>&1', 'git ls-remote -q /a/b 2> /dev/null',
  ])('silent: %s', (cmd) => { expect(verdict(cmd, 'zola')).toMatchObject({ deny: false }) })
})

describe('everything that is not provably clean speaks (zola)', () => {
  it.each([
    'git clone --recurse-submodules /home/x/repo y',           // a local clone can still fetch submodules over the network
    'git clone --recursive /home/x/repo y',
    'git clone --shallow-submodules /home/x/repo y',
    'git ls-remote origin', 'git ls-remote', 'git ls-remote repo-name',      // a bare word to ls-remote is a NAMED REMOTE
    // a loopback / private HOST is not provably free: the proxy and ssh environment still apply (Sam 521f1f39 round 1, SEVERE 1)
    'git clone http://localhost:3420/x.git', 'git clone git@localhost:x.git', 'git clone ssh://git@192.168.1.5/x.git',
    'git ls-remote http://127.0.0.1:3000/x.git', 'git clone localhost:r.git d',
    // an option the allowlist does not spell out: it can shift the positional word, run a command or rewrite the remote
    'git clone --revision v1 https://example.org/r.git d', 'git clone --ref-format files https://example.org/r.git d',
    'git clone --bran main https://example.org/r.git d', 'git clone --rev v1 https://example.org/r.git d',
    'git clone --orig o https://example.org/r.git d', 'git clone --bran main /a/b d', 'git clone --unknown-opt /a/b d',
    'git -c url.https://example.org/.insteadOf=file:///fake/ clone file:///fake/r.git d',
    'git clone -c url.https://example.org/.insteadOf=file:///fake/ file:///fake/r.git d',
    'git -c url.https://example.org/.insteadOf=localhost: clone localhost:r.git d',
    'git -c url.https://example.org/.insteadOf=file:///fake/ ls-remote file:///fake/r.git',
    "git clone -u 'wget https://example.org/x -O /tmp/y; git-upload-pack' file:///home/x/repo d",
    "git clone --upload-pack='wget https://example.org/x; git-upload-pack' /home/x/repo d",
    "git ls-remote --upload-pack='wget https://example.org/x; git-upload-pack' /home/x/repo",
    "git ls-remote --exec='wget https://example.org/x' /home/x/repo",
    "git -c core.sshCommand='wget https://example.org/x;' clone localhost:r d",
    'git clone --config core.sshCommand=x /a/b d', 'git --exec-path=/tmp clone /a/b d', 'git --git-dir=/x clone /a/b d',
    'git clone /a/b c d',                     // three positionals: not a clone git understands
    'git clone --bundle-uri https://example.org/b /a/b d', 'git clone --filter=blob:none /a/b d',
    // wrappers the pip / python / runner readers did not see through (Sam 521f1f39 round 1, SEVERE 2)
    'python3 -mpip download requests', 'python3 -Im pip download requests', 'python3 -X dev -m pip download requests',
    'python3 -myt_dlp https://example.org/v', 'python3 -mplaywright install',
    'pip --proxy http://p:3128 download requests', 'pip --cache-dir /tmp/c download requests', 'pip --retries 2 download requests',
    'pip --some-future-option x download requests', 'pip wheel requests', 'pip3 --proxy http://p:3128 wheel requests',
    "npx --package=playwright -c 'playwright install chromium'", 'npx --package playwright playwright install',
    'corepack pnpm dlx playwright install', 'corepack npx playwright install',
    // round 2 (Sam msg 3804, case lists cases1-3 are now fixed)
    'git submodule add ../../evil/x.git sub', 'git submodule add ../x.git sub', 'git submodule add ./x sub',
    'git clone --template=/tmp/t /a/b d', 'git clone --template /tmp/t /a/b d',
    "npx -c 'pla\"\"ywright install chromium'", "npx -c 'p=playwright; $p install chromium'", "npx --call 'pla\"\"ywright install'",
    'python3 -m pip._internal download requests', 'python3 -m pip.__main__ download requests', 'python3 -m yt_dlp.__main__ https://example.org/v',
    'python3 -Wignore -m pip download requests', 'python3 -bb -m pip download requests', 'python3 -I -s -E -mpip download requests',
    'pip3 --isolated download requests', 'pip --no-cache-dir download requests', 'pip -q -q download requests', 'pip --python /usr/bin/python3 download requests',
    'pip --proxy=http://p:3128 download requests', 'pip -vvv --log=/tmp/l download requests',
    'uv pip download requests', 'pipx run pip download requests', 'uvx pip wheel requests',
    'git config --global url.https://example.org/.insteadOf file:///fake/ && git clone file:///fake/r.git d',
    'git config url.https://example.org/.insteadOf file:///fake/', 'git -C w config url.http://127.0.0.1:9/.insteadOf file:///fake/',
    "npx --call='pla\"\"ywright install chromium'", 'git ls-remote -h', 'git ls-remote -h origin',
    'git submodule set-url sub https://example.org/x.git', 'git submodule set-url sub ../x.git',
    'git config alias.dl clone && git dl https://example.org/r.git d', "git config alias.dl '!wget https://example.org/x'",
    'git config remote.o.url https://example.org/r.git', 'git config core.sshCommand "wget x"',
    'git dl https://example.org/r.git d', 'git dl git@example.org:r.git',
    'git pull https://example.org/r.git', 'git -C r pull --rebase https://example.org/r.git main', 'git fetch -j4 https://example.org/r.git',
    'git pull -Xours https://example.org/r.git', 'git pull -s ours https://example.org/r.git', 'git fetch -- https://example.org/r.git',
    'git fetch --refmap= https://example.org/r.git', 'git fetch origin --upload-pack \'wget x; git-upload-pack\'',
    // wrappers and substitutions in front of a command (Sam 521f1f39 round 1, MEDIUM 4: older than this branch)
    'setsid wget https://example.org/x', 'watch -n 60 wget https://example.org/x', 'cat <(wget -qO- https://example.org/x)',
    'git clone "$URL"', 'git clone $URL', 'git clone $(cat url.txt)', 'git clone `cat url.txt`',
    'git clone', 'git clone --depth 1',
    'git clone https://github.com.evil.example/a.git', 'git clone git@github.com:a/b.git',
    'git clone https://localhost.evil.com/a.git', 'git clone https://localhost@evil.com/a.git',
    'git clone ssh://git@10.1/a.git',                      // not a canonical private address: external (the private-network rule)
    'yt-dlp', 'yt-dlp -U', 'wget', 'wget -q', 'pip download', 'npx playwright', 'npx playwright test',
    'wget --version https://example.org/', 'yt-dlp --version https://example.org/',
    'wget --version 2> err.txt https://example.org/', 'wget 2> /dev/null https://example.org/',   // a redirection target is not a flag
    'npx playwright-core install', 'npx -y playwright-core@1.50 install',
  ])('denied: %s', (cmd) => { expect(verdict(cmd, 'zola')).toMatchObject({ deny: true }) })
})

describe('text is not a run: nothing speaks when the shape is only mentioned', () => {
  it.each([
    'command -v yt-dlp', 'command -v wget pip', 'command -V playwright', 'for c in yt-dlp wget; do command -v $c; done',
    'which wget', 'type -a yt-dlp', 'echo yt-dlp', 'echo "git clone https://github.com/a/b.git"', "echo 'npx playwright install'",
    'grep -rn "wget" docs/', 'ls ~/.cache/ms-playwright', 'git log --oneline -3', 'git fetch origin', 'git push fork main',
    'npx vitest run src/__tests__/x.test.ts', 'npm test', 'pip install requests', 'pip list', 'python3 -m pytest', 'npx tsc --noEmit',
    "cat > /tmp/note.md <<'EOF'\nrun git clone https://github.com/a/b.git and wget https://x.org/f\nEOF",
    'ssh-keygen -t ed25519', 'git status --short',
    "cat > /tmp/n.md <<'EOF'\nyt-dlp https://example.org/v\ngit clone https://github.com/a/b.git\nwget https://example.org/f\nEOF",   // a body line that STARTS with the command is still text
    "cat <<'EOF'\nnpx playwright install\nEOF",
  ])('silent: %s', (cmd) => { expect(verdict(cmd, 'zola')).toMatchObject({ deny: false }) })
})

describe('nested and indirect forms are read through', () => {
  it('a shell heredoc body is a command line', () => {
    expect(verdict("bash <<'EOF'\nyt-dlp https://example.org/v\nEOF", 'zola')).toMatchObject({ deny: true, reason: expect.stringContaining('bypass-yt-dlp') })
    expect(verdict("bash <<'EOF'\nyt-dlp https://example.org/v\nEOF", 'willy')).toMatchObject({ deny: false })
  })
  it('a command substitution is read', () => {
    expect(verdict('echo $(git clone https://github.com/a/b.git)', 'zola')).toMatchObject({ deny: true, reason: 'bypass-git-clone' })
  })
  it('a pipeline stage and a loop are read', () => {
    expect(verdict('echo hi | wget -i -', 'zola')).toMatchObject({ deny: true, reason: 'bypass-wget' })
    expect(verdict('for u in a b; do yt-dlp "https://example.org/$u"; done', 'zola')).toMatchObject({ deny: true, reason: 'bypass-yt-dlp' })
  })
  it('the old shapes are unchanged: curl is still judged on its destination, for every agent', () => {
    for (const a of ['igor', 'willy', 'zola']) {
      expect(verdict('curl -s https://example.org/', a)).toMatchObject({ deny: true, reason: 'curl-external' })
      expect(verdict('curl -s http://localhost:3420/api/x', a)).toMatchObject({ deny: false })
    }
  })
})

describe('who: the agent comes from transcript_path, not from the cwd', () => {
  const T = (n: string) => join(ROOT, 'agents', n, '.claude-config', 'projects', '-x', 'abc.jsonl')
  it('a sub-agent transcript names the agent', () => { expect(agentFromTranscript(T('igor'))).toBe('igor'); expect(agentFromTranscript(T('zola'))).toBe('zola') })
  it('everything else is unknown (null)', () => {
    for (const p of [
      undefined, null, '', '   ', 42, '/srv/other/.claude/projects/x/abc.jsonl',
      join(ROOT, 'agents', 'igor', 'abc.jsonl'),                                      // not under .claude-config
      join(ROOT, 'agents', 'igor', 'other-config', 'abc.jsonl'),
      join(ROOT, 'agents', '.claude-config', 'abc.jsonl'),                           // no agent segment
      join(ROOT, 'agents', '..', 'agents', 'x y', '.claude-config', 'a.jsonl'),        // a space is not an agent id
      'agents/igor/.claude-config/projects/x/abc.jsonl',                              // relative
      '/elsewhere/agents/igor/.claude-config/projects/x/abc.jsonl',                   // another install root
    ]) expect(agentFromTranscript(p as string)).toBeNull()
  })
  it('a path that stops at the config dir has no session file under it: unknown', () => {
    expect(agentFromTranscript(join(ROOT, 'agents', 'igor', '.claude-config'))).toBeNull()
    expect(agentFromTranscript(join(ROOT, 'agents', 'igor', '.claude-config') + '/')).toBeNull()
  })
  it('the install root is part of the identity: the same shape under another root of the SAME length is unknown', () => {
    const other = ROOT.slice(0, -1) + (ROOT.endsWith('X') ? 'Y' : 'X')
    expect(other.length).toBe(ROOT.length)
    expect(agentFromTranscript(`${other}/agents/igor/.claude-config/projects/x/a.jsonl`)).toBeNull()
    expect(agentFromTranscript(`${ROOT}/agents/igor/.claude-config/projects/x/a.jsonl`)).toBe('igor')
  })
  it('a RAW ../ walk (string, not path.join) is resolved before the agent is read', () => {
    expect(agentFromTranscript(`${ROOT}/agents/igor/.claude-config/../../zola/.claude-config/a.jsonl`)).toBe('zola')
    expect(agentFromTranscript(`${ROOT}/agents/igor/.claude-config/../../../x/.claude-config/a.jsonl`)).toBeNull()
    expect(agentFromTranscript(`${ROOT}/agents//igor/./.claude-config/projects/a.jsonl`)).toBe('igor')
  })
  it('a ../ walk out of one agent into another is resolved before it is read', () => {
    expect(agentFromTranscript(join(ROOT, 'agents', 'igor', '.claude-config', '..', '..', 'zola', '.claude-config', 'a.jsonl'))).toBe('zola')
    expect(agentFromTranscript(join(ROOT, 'agents', 'igor', '..', '..', 'x', 'a.jsonl'))).toBeNull()
  })
})

describe('the hook process, end to end (real stdin / stdout / block log)', () => {
  const run = (cmd: string, transcript: string | undefined, args: string[] = []) => {
    const payload = { tool_name: 'Bash', tool_input: { command: cmd }, ...(transcript ? { transcript_path: transcript } : {}) }
    const r = spawnSync('node', [HOOK, ...args], { input: JSON.stringify(payload), encoding: 'utf-8', env: { ...process.env, BASH_EGRESS_BLOCK_LOG: join(LOG_DIR, 'e2e.jsonl') } })
    return { status: r.status, out: r.stdout ? JSON.parse(r.stdout) : null }
  }
  const T = (n: string) => join(ROOT, 'agents', n, '.claude-config', 'projects', '-x', 'abc.jsonl')
  it('zola: git clone is denied with the per-agent message', () => {
    const r = run('git clone https://github.com/a/b.git', T('zola'))
    expect(r.status).toBe(0)
    expect(r.out.hookSpecificOutput.permissionDecision).toBe('deny')
    expect(r.out.hookSpecificOutput.permissionDecisionReason).toContain('te: zola')
    expect(r.out.hookSpecificOutput.permissionDecisionReason).toContain('bypass-git-clone')
    expect(r.out.hookSpecificOutput.permissionDecisionReason).not.toContain('Force-push')
  })
  it('igor: the same command passes (positive control: the instrument can tell the two agents apart)', () => {
    expect(run('git clone https://github.com/a/b.git', T('igor')).out).toBeNull()
  })
  it('willy: git clone denied, yt-dlp passes', () => {
    expect(run('git clone https://github.com/a/b.git', T('willy')).out.hookSpecificOutput.permissionDecision).toBe('deny')
    expect(run('yt-dlp https://example.org/v', T('willy')).out).toBeNull()
  })
  it('no transcript_path: denied, and the message says the agent could not be identified', () => {
    const r = run('yt-dlp https://example.org/v', undefined)
    expect(r.out.hookSpecificOutput.permissionDecision).toBe('deny')
    expect(r.out.hookSpecificOutput.permissionDecisionReason).toContain('nem azonosithato')
  })
  it('the main agent wiring (--git-only) lets every bypass shape through', () => {
    expect(run('git clone https://github.com/a/b.git', undefined, ['--git-only']).out).toBeNull()
    expect(run('yt-dlp https://example.org/v', undefined, ['--git-only']).out).toBeNull()
  })
  it('a force-push still gets the force-push message, not the bypass one', () => {
    const r = run('git push --force fork main', T('zola'))
    expect(r.out.hookSpecificOutput.permissionDecisionReason).toContain('Force-push')
  })
  it('the block log carries the agent', () => {
    const log = join(LOG_DIR, 'e2e.jsonl')
    expect(existsSync(log)).toBe(true)
    const lines = readFileSync(log, 'utf-8').trim().split('\n').map((l) => JSON.parse(l))
    expect(lines.some((l) => l.agent === 'zola' && l.reason === 'bypass-git-clone')).toBe(true)
    expect(lines.some((l) => l.agent === null && l.reason === 'bypass-yt-dlp')).toBe(true)
  })
})
