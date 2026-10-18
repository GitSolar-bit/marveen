import { describe, it, expect } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

// @ts-expect-error -- plain .mjs hook script, no types
import { classify, gitForcePush } from '../../scripts/hooks/bash-egress-parser.mjs'

// GITFORCE1003 (kanban 3b4e46f3, DENYARGS925). The deny list's `Bash(git push --force:*)` matches the
// command's leading words, and these forms RAN on a list carrying it (measured 2026-09-25 and again
// 2026-10-03, in a session with that list active): an inserted flag, an absolute path, `git -C`.
// The hook parses the command instead.

const HOOK = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'hooks', 'bash-egress-parser.mjs')
const reasonOf = (cmd: string): string | null => classify(cmd).reason
// the per-agent bypass shapes (bypass-git-clone ...) are a different decision (card 521f1f39); this file is about the force-push reasons
const isGit = (cmd: string): boolean => { const r = reasonOf(cmd) ?? ''; return /(?:^|-)git-/.test(r) && !r.startsWith('bypass-') }

describe('the three measured bypasses, plus the literal form', () => {
  it('denies the literal form, the inserted flag, the absolute path and git -C', () => {
    for (const cmd of [
      'git push --force r',
      'git push --quiet --force r',
      '/usr/bin/git push --force r',
      'git -C /some/where push --force r',
    ]) expect({ cmd, r: classify(cmd) }).toEqual({ cmd, r: { deny: true, reason: 'git-force-push', hosts: [] } })
  })
})

describe('every spelling of a force-push is denied', () => {
  const DENY = [
    'git push -f r b', 'git push r b -f', 'git push -fu r b', 'git push -uf r b', 'git push -vfq r',
    'git push --force-with-lease r b', 'git push --force-with-lease=main:abc123 r main', 'git push --force-if-includes r',
    'git push --mirror r', 'git push --forc r', 'git push --force-w r', 'git push --mirr r',
    'git push r +main', 'git push r +HEAD:main', 'git push r -- +main',
    'git -c core.editor=x push -f r', 'git -C /w -c k=v push --force r', 'git --git-dir=/g push -f r', 'git --git-dir /g push -f r',
    'timeout 5 git push --force r', 'env A=1 git push -f r', 'nice -n 5 git push -f r', 'GIT_TERMINAL_PROMPT=0 git push -f r',
    'cd /w && git push -f r', 'true; git push -f r', 'echo hi\ngit push -f r', 'false || git push -f r',
    "bash -c 'git push --force r'", 'sh -lc "git -C /w push -f r"', "eval 'git push -f r'", 'eval git push -f r',
    "bash -c \"bash -c 'git push -f r'\"",
    'F=--force; git push $F r', 'for f in --quiet --force; do git push $f r; done',
    'bash <<EOF\ngit push --force r\nEOF',
    '$(git push -f r)',
    'git -c credential.helper=x push -o ci.skip -f r',
  ]
  it('denies each form, naming the reason', () => {
    for (const cmd of DENY) expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: true })
  })
  it('an alias given on the command line is refused: it can name push and its own flags', () => {
    expect(reasonOf('git -c alias.p=push p -f r')).toBe('git-alias-override')
    expect(reasonOf('git -calias.p=push p r')).toBe('git-alias-override')
  })
})

describe('CONTROLS: ordinary git, and text that merely mentions a force-push, passes', () => {
  const ALLOW = [
    'git push origin main', 'git push -u fork HEAD:fix/x', 'git push --quiet fork HEAD', 'git -C /w push origin main',
    'git push --dry-run fork HEAD', 'git push -o ci.skip fork HEAD', 'git push -o force fork HEAD', 'git push --follow-tags fork main',
    'git push --no-force-with-lease x', 'git push --no-verify fork HEAD', 'git push fork HEAD:refs/heads/f-orce', 'git push origin feature-f',
    'git push --delete fork b', 'git push --repo fork main',
    // an option VALUE that looks like a flag is a value, not a flag; after `--` a leading dash is a refspec
    'git push -o -f fork HEAD', 'git push -o-f fork HEAD', 'git push --push-option -f fork HEAD', 'git push fork -- -f',
    'git status', 'git log --oneline -3 -- push', 'git remote add fork https://example.org/x.git',
    'ls /usr/bin/git /opt/git', '/usr/bin/git -C /w status --short', 'git -C /w rev-parse HEAD', 'git fetch -f origin',
    'git commit -m "docs: push --force is denied"', "git commit -m 'push -f'", 'echo "git push --force"', "echo 'git push -f r'",
    "python3 - <<'PY'\nprint('git push --force')\nPY",
    'cat <<EOF\ngit push --force\nEOF',
    "cat > /tmp/notes.md <<'EOF'\ngit push -f\nEOF",
    "bash -c 'git push origin main'", 'eval git status',
    'F=--quiet; git push $F fork HEAD',
  ]
  it('lets every one through', () => {
    for (const cmd of ALLOW) expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: false })
  })
})

describe('forms the first review round found (Sam, 2026-10-03)', () => {
  const DENY = [
    'git.exe push --force origin x', '"/mnt/c/Program Files/Git/cmd/git.exe" push --force origin x', '"git" push --force origin x',
    '\\git push --force origin x', 'git push --"force" origin x', "git push --'force' origin x",
    '(git push --force origin x)', '( git push -f r )', '{ git push --force origin x; }', 'if true; then git push --force origin x; fi',
    'git push --{force,quiet} origin x', 'git push --{quiet,force} origin x', 'git push -{q,f} origin x',
    'git -c remote.origin.push=+refs/heads/x:refs/heads/x push origin',
    'echo "git push --force origin x" | sh', 'echo git push -f r | bash', 'printf "git push -f r" | sh -s',
    // second probe round (Sam): a config mirror, a function definition, a variable in the command word
    'git -c remote.origin.mirror=true push origin', 'git -c remote.origin.mirror=yes push origin',
    'f(){ git push --force origin x; }; f', 'function f { git push -f origin x; }; f', 'g=git; $g push --force origin x',
    'nohup git push -f origin x &', "bash -s <<'EOS'\ngit push --force origin x\nEOS",
    // GITFORCEMAIN1003 (HEX's probe, measured ALLOW before): the command word is a substitution / variable
    '$(echo git) push --force x', '"$(command -v git)" push -f r', '`which git` push --force r', '$GIT push -f r',
    '$(echo git) push --force-with-lease r', 'push -f r',
    // a force-push behind an external curl in a shell body was shadowed by the curl deny and passed
    'bash -c "curl http://example.org/x; git push -f r"', 'sh -c "curl https://example.org/x && git push --force r"',
  ]
  it('denies each', () => {
    for (const cmd of DENY) expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: true })
  })
  const ALLOW = [
    'git.exe status', '"git" push origin main', '\\git push origin main', '(git push origin main)', '{ git push origin main; }',
    'git push --{quiet,verbose} fork HEAD', 'git -c remote.origin.url=x push origin main',
    'git -c remote.origin.push=refs/heads/x:refs/heads/x push origin',
    'echo "git push origin x" | sh', 'echo hi | sh', 'ls | sh', 'echo "git push -f" | cat', 'echo x | sh script.sh',
    'git -c remote.origin.mirror=false push origin', 'f(){ git push origin x; }; f', 'function f { git status; }; f',
    'echo "git push -f" > /tmp/note.txt', "cat <<'EOF' | cat\ngit push --force\nEOF",
    '$(echo git) push r main', '"$(command -v git)" status', '$GIT push r main', 'echo push -f', 'pushd /tmp', 'push r main',
  ]
  it('lets the ordinary twins through', () => {
    for (const cmd of ALLOW) expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: false })
  })
  it('a heredoc body is still inert text after the quoted-command change', () => {
    expect(isGit('cat <<EOF\ngit push --force\nEOF')).toBe(false)
    expect(isGit('"cat" <<EOF\ngit push -f r\nEOF')).toBe(false)
  })
  it('the open families are NAMED in the code, so the list cannot be read as complete', () => {
    const src = readFileSync(HOOK, 'utf-8').replace(/\n\/\/\s*/g, ' ')
    for (const phrase of ['GIT_CONFIG_*', 'cat file | sh', 'xargs', 'unresolved variable', '{a..b}', 'python subprocess', 'git send-pack', 'command substitution at the command-word', 'alias defined in the same command'])
      expect({ phrase, named: src.includes(phrase) || src.toLowerCase().includes(phrase.toLowerCase()) }).toEqual({ phrase, named: true })
  })
})

describe('gitForcePush on a bare argv', () => {
  it('is null for a non-git command and for a git command with another subcommand', () => {
    expect(gitForcePush(['ls', '-f'])).toBeNull()
    expect(gitForcePush(['git', 'fetch', '-f'])).toBeNull()
    expect(gitForcePush(['git', 'push', 'origin', 'main'])).toBeNull()
  })
  it('reads a git.exe path', () => {
    expect(gitForcePush(['C:/Program Files/Git/cmd/git.exe', 'push', '-f'])).toBe('git-force-push')
  })
})

describe('the hook process', () => {
  const run = (command: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'git-force-hook-'))
    try {
      return spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
        encoding: 'utf-8',
        env: { ...process.env, BASH_EGRESS_BLOCK_LOG: join(dir, 'blocks.jsonl'), BASH_EGRESS_VENDOR_HOSTS: join(dir, 'none.json') },
      })
    } finally { rmSync(dir, { recursive: true, force: true }) }
  }
  it('denies with the force-push message, not the network one, and stays silent on a plain push', () => {
    const denied = run('git push --quiet --force r')
    expect(denied.stdout).toContain('"permissionDecision":"deny"')
    expect(denied.stdout).toContain('Force-push TILTVA')
    expect(denied.stdout).toContain('git-force-push')
    expect(denied.stdout).not.toContain('halozati hivas')
    expect(run('git push fork HEAD').stdout).toBe('')
  })
  it('a force-push inside a heredoc-fed shell is denied with the same message', () => {
    expect(run('bash <<EOF\ngit push -f r\nEOF').stdout).toContain('Force-push TILTVA')
  })
})

// GITFORCEMAIN1003: the main agent runs the hook with `--git-only`. Its own work reaches external APIs from
// python heredocs (120 of 9286 distinct commands, replayed), so the egress half must stay OFF there, and the
// force-push half must still bite, including when an egress shape sits in the same command.
describe('--git-only mode (the main agent)', () => {
  const go = (cmd: string): string | null => classify(cmd, 0, new Set(), new Set(), true).reason
  const EGRESS = [
    'curl -s http://example.org/x',
    `python3 -c "import urllib.request; urllib.request.urlopen('https://api.github.com/x')"`,
    "python3 - <<'PY'\nimport urllib.request\nurllib.request.urlopen('https://api.open-meteo.com/v1/forecast')\nPY",
    'U=https://example.org/x; curl -s "$U"',
    'echo "$(curl -s http://example.org/x)"',
    "bash <<'EOF'\ncurl http://example.org/x\nEOF",
  ]
  it('lets every egress shape through (the full mode denies the same commands: the control)', () => {
    for (const cmd of EGRESS) {
      expect({ cmd, full: classify(cmd).deny }).toEqual({ cmd, full: true })
      expect({ cmd, gitOnly: go(cmd) }).toEqual({ cmd, gitOnly: null })
    }
  })
  it('still denies a force-push, alone or next to an egress shape, in every nesting', () => {
    for (const cmd of [
      'git push --force r', '$(echo git) push --force x',
      'curl -s http://example.org/x; git push -f r',
      'echo "$(curl -s http://example.org/x)" && git push -f r',
      'bash -c "curl http://example.org/x; git push -f r"',
      "bash <<'EOF'\ncurl http://example.org/x\ngit push --force r\nEOF",
      "python3 - <<'PY'\nimport urllib.request\nPY\ngit push -f r",
    ]) expect({ cmd, isGit: /(?:^|-)git-/.test(go(cmd) ?? '') }).toEqual({ cmd, isGit: true })
  })
  it('lets ordinary git through', () => {
    for (const cmd of ['git push fork HEAD', 'git status', 'git push --set-upstream fork feat/x']) expect(go(cmd)).toBeNull()
  })
  it('the hook process honours --git-only: silent on an egress shape, denying on a force-push', () => {
    const dir = mkdtempSync(join(tmpdir(), 'git-only-hook-'))
    try {
      const run = (command: string) => spawnSync(process.execPath, [HOOK, '--git-only'], {
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
        encoding: 'utf-8',
        env: { ...process.env, BASH_EGRESS_BLOCK_LOG: join(dir, 'blocks.jsonl'), BASH_EGRESS_VENDOR_HOSTS: join(dir, 'none.json') },
      })
      expect(run('curl -s http://example.org/x').stdout).toBe('')
      const d = run('curl -s http://example.org/x; git push --force r')
      expect(d.stdout).toContain('"permissionDecision":"deny"')
      expect(d.stdout).toContain('Force-push TILTVA')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})

// DENYARGS925 v3: there is NO general "a heredoc to a shell that runs a script file is data" exemption. The
// first two versions tried one (v1: script operand or -c = data; v2: a narrower detector), and an independent
// probe found a new spelling each time (`bash 2>/dev/null`, `bash -eo pipefail`, `bash /etc/../dev/stdin`,
// `X=/dev; bash $X/stdin`, `bash >f`, `bash <&0`, `bash -eO extglob`, `bash /de?/stdin`, `${X:-/dev/stdin}`,
// `{/dev/stdin,}`, `$'/dev/stdin'`, `../dev/stdin`): the set of ways to name "my stdin" is open-ended, and a
// parser that tries to list them loses. So the stdin-program logic is BYTE-IDENTICAL to the base (4a8c6fc):
// every heredoc / here-string fed to a shell is that shell's command line, whatever the head says, and is
// judged. These tests pin the base behaviour; each head below was measured DENY on the base AND here.
// KNOWN LIMIT, named on the card: `bash scripts/agent-msg.sh hex igor - <<'EOF'` whose body QUOTES a
// force-push is denied (the case that started the exemption). The measured ways around it, all allowed on
// the base and here: put the text in a FILE and `bash scripts/agent-msg.sh hex igor - < file`; pipe it
// (`echo "..." | bash scripts/agent-msg.sh hex igor -`); or pass it as an argument.
describe('a heredoc to ANY shell is judged as a command line, exactly as on the base (DENYARGS925 v3)', () => {
  const BODY = 'curl http://example.org/x\ngit push --force origin main'
  const GITBODY = 'git push --force origin main'
  const heredoc = (head: string, body: string) => `${head} <<'EOF'\n${body}\nEOF`
  const HEADS = [
    // the four HEX measured ALLOW on v2 (DENY on the base)
    'bash 2>/dev/null', 'bash -eo pipefail', 'bash /etc/../dev/stdin', 'X=/dev; bash $X/stdin',
    // the independent probe's list
    'bash >/tmp/f', 'bash 2>&1', 'bash <&0', 'bash 3</dev/null', 'bash -euo pipefail', 'sh -eo pipefail', 'bash -eO extglob',
    'bash /de?/stdin', 'bash ${X:-/dev/stdin}', 'bash {/dev/stdin,}', "bash $'/dev/stdin'", 'bash ../dev/stdin', 'bash ../../dev/stdin',
    // v2's own list: every other way a shell reads its program from stdin
    'bash /dev/stdin', 'sh /proc/self/fd/0', 'bash /dev/fd/0', 'bash //dev/./stdin', 'bash /proc/$$/fd/0', 'bash -- /dev/stdin', 'sh -- -',
    'bash -c bash', `bash -c 'eval "$(cat)"'`, "bash -c '. /dev/stdin'", "sh -c 'sh -s'", "bash -c 'cat'", 'bash -ec cat',
    'bash --rcfile /dev/null', 'bash --init-file /dev/null', 'bash --norc', 'bash +o pipefail', 'bash -o pipefail -s',
    'bash "$(echo /dev/stdin)"', 'S=/dev/stdin; bash $S', 'env bash', 'sudo -n bash', '/bin/bash', 'dash', 'zsh', 'bash', 'bash -s', 'bash -',
    // the script-file forms: the NAMED LIMIT (denied on the base, denied here)
    'bash scripts/agent-msg.sh hex igor -', 'bash /home/u/marveen/scripts/agent-msg.sh hex igor -',
    'bash ./x.sh', 'sh run.sh', 'bash -x script.sh', 'bash -o pipefail ./x.sh', 'bash -- ./x.sh', 'timeout 5 bash ./x.sh',
  ]
  it('denies each with a curl in the body, in the full mode and in --git-only (curl is not judged there, the force-push is)', () => {
    for (const head of HEADS) {
      const cmd = heredoc(head, BODY)
      expect({ cmd, full: classify(cmd).deny }).toEqual({ cmd, full: true })
      expect({ cmd, gitOnly: /(?:^|-)git-/.test(classify(cmd, 0, new Set(), new Set(), true).reason ?? '') }).toEqual({ cmd, gitOnly: true })
    }
  })
  it('denies each with only the force-push in the body, as a force-push reason, in BOTH modes', () => {
    for (const head of HEADS) {
      const cmd = heredoc(head, GITBODY)
      expect({ cmd, full: isGit(cmd) }).toEqual({ cmd, full: true })
      expect({ cmd, gitOnly: /(?:^|-)git-/.test(classify(cmd, 0, new Set(), new Set(), true).reason ?? '') }).toEqual({ cmd, gitOnly: true })
    }
  })
  it('a here-string is judged the same way', () => {
    for (const cmd of ["bash -c sh <<< 'git push --force r'", "sh /dev/stdin <<< 'git push -f r'", "bash <<< 'git push -f r'", "bash scripts/agent-msg.sh hex igor - <<< 'git push -f r'"])
      expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: true })
  })
  it('the named limit: the standard message helper with a heredoc that QUOTES a force-push is denied', () => {
    // the realistic shape: a message that quotes the command in backticks (a bare quoted line is not a command line)
    const cmd = heredoc('bash scripts/agent-msg.sh hex igor -', 'Mert: `git push --force x` ALLOW.\nA masik: git push -f r')
    expect({ cmd, isGit: isGit(cmd) }).toEqual({ cmd, isGit: true })
  })
  it('the ways around the limit pass, in both modes (measured allowed on the base too)', () => {
    for (const cmd of [
      'bash scripts/agent-msg.sh hex igor - < /home/u/work/msg.txt',
      'echo "git push --force origin main" | bash scripts/agent-msg.sh hex igor -',
      `printf '%s' 'git push -f origin main' | bash scripts/agent-msg.sh hex igor -`,
      'bash scripts/agent-msg.sh hex igor "$(cat /home/u/work/msg.txt)"',
      "bash scripts/agent-msg.sh hex igor 'git push --force origin main'",
    ]) {
      expect({ cmd, full: isGit(cmd) }).toEqual({ cmd, full: false })
      expect({ cmd, gitOnly: /(?:^|-)git-/.test(classify(cmd, 0, new Set(), new Set(), true).reason ?? '') }).toEqual({ cmd, gitOnly: false })
    }
  })
})

// CLOSED (card 55d8cd24, Sam 3528 / HEX 3530, 2026-10-13). This was a KNOWN, PRE-EXISTING gap, pinned as it
// was "so that closing it is a visible change and not a silent one": a heredoc piped through `cat` into a
// shell is that shell's program, and the parser did not follow the pipe. The code-sink rule in
// bash-egress-parser.mjs (codeSinkOf) follows it now, in both modes, so the pin is flipped to denies.
describe('a heredoc through cat into a shell is judged (was a pinned gap)', () => {
  it('denies in both modes', () => {
    for (const cmd of ["cat <<'EOF' | bash\ngit push --force r\nEOF", "cat <<'EOF' | sh\ngit push -f r\nEOF"]) {
      expect({ cmd, full: isGit(cmd) }).toEqual({ cmd, full: true })
      expect({ cmd, gitOnly: /(?:^|-)git-/.test(classify(cmd, 0, new Set(), new Set(), true).reason ?? '') }).toEqual({ cmd, gitOnly: true })
    }
  })
  it('NEGATIVE CONTROL: the same text piped into grep is data', () => {
    const cmd = "cat <<'EOF' | grep push\ngit push --force r\nEOF"
    expect({ cmd, full: isGit(cmd) }).toEqual({ cmd, full: false })
  })
})
