import { describe, it, expect, afterAll } from 'vitest'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, tmuxMentionAllowed } from '../../scripts/self-pace-gate.mjs'
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Card 9f57f705: the tmux write primitive, judged by INVERTED PROOF (loud by default, silent only on provably clean).
//
// Measured on the gate that was live (offline, the pure gateDecision, nothing executed, 32 cases): 20 got through.
// The literal-name pattern needs `tmux` AND one of four subcommand names in ONE segment, so tmux's own aliases, a
// variable, a list split over two lines, an env/xargs wrapper and a script FILE all passed. The rule now is: the word
// `tmux` may appear only as a read call, or as an argument of a plain reader in a command with no executing sink.
// Round 2 (owner's decision, rule 11: "cannot be proven = deny"): an interpreter may run a script FILE only when the gate can
// name and read it (a literal path, or a $NAME the same command set to a literal); a computed or unreadable path is a deny.

const SK = 'send' + '-keys'
const denies = (command: string, cwd?: string) => gateDecision('Bash', { command }, { cwd }).deny === true

describe('tmux write primitive: every spelling that is not a provable read is denied', () => {
  it.each([
    ['tmux alias send', 'tmux send -t x hello'],
    ['tmux alias send-prefix', 'tmux send-prefix -t x'],
    ['tmux alias pasteb', 'tmux pasteb -t x'],
    ['setb then pasteb', 'tmux setb hello; tmux pasteb -t x'],
    ['tmux alias run', "tmux run -b 'echo hi'"],
    ['tmux source-file', 'tmux source-file /tmp/x.conf'],
    ['tmux if-shell', "tmux if-shell true 'send -t x hi'"],
    ['tmux respawn-pane', "tmux respawn-pane -k -t x 'sh'"],
    ['command word in a variable', `X=tmux; $X ${SK} -t x hello`],
    ['subcommand in a variable', 'K=send; tmux ${K}-keys -t x hello'],
    ['env wrapper', 'env tmux send -t x hello'],
    ['xargs', 'echo x | xargs -I{} tmux send -t {} hello'],
    ['socket flag then an alias', 'tmux -S /tmp/tmux-1000/default send -t x hello'],
    ['absolute path to the binary', '/usr/bin/tmux send -t x hello'],
    ['backslash-split name', 't\\mux send -t x hello'],
    ['a chained second command after a read', "tmux ls \\; send -t x hi"],
    ['a chained second command, quoted semicolon', "tmux ls ';' send -t x hi"],
    ['format expansion runs a shell', "tmux display-message -p '#(touch /tmp/x)'"],
    ['an echoed command piped into a shell', "echo 'tmux send -t x hi' | sh"],
    ['an echoed command piped into python', "echo 'tmux send -t x hi' | python3"],
    ['python -c, same segment', `python3 -c "import subprocess;subprocess.run(['tmux','send','-t','x','hi'])"`],
    ['python heredoc, list over several lines', "python3 - <<'PY'\nimport subprocess\nsubprocess.run([\n  'tmux',\n  'send',\n  '-t', 'x', 'hi'])\nPY"],
    ['python heredoc, two statements', "python3 - <<'PY'\nimport subprocess\na='tmux'; b='send'\nsubprocess.run([a, b, '-t', 'x', 'hi'])\nPY"],
    ['node heredoc child_process', "node - <<'JS'\nrequire('child_process').execFileSync('tmux',['send','-t','x','hi'])\nJS"],
  ])('%s', (_label, command) => {
    expect(denies(command)).toBe(true)
  })
})

describe('tmux reads and ordinary work stay silent', () => {
  it.each([
    'tmux list-sessions',
    'tmux ls',
    'tmux -S /tmp/tmux-1000/default list-panes -a',
    'tmux capture-pane -p -t x',
    'tmux has-session -t x',
    "tmux display-message -p '#S'",
    'tmux show-options -g',
    'TMUX_TMPDIR=/tmp/x tmux ls',
    'tmux ls | grep agent',
    'tmux ls && echo done',
    'grep -rn tmux src/agent.ts',
    'cat docs/tmux.md',
    'echo "the tmux session is named after the agent"',
    'git diff --stat HEAD -- src/tmux.ts src/__tests__/tmux-exact-target.test.ts',
    'ls src/tmux*',
    'echo "$TMUX"',
    'git commit -m "route the tmux send path through the API"',
    'python3 -c "print(1)"',
  ])('%s', (command) => {
    expect(denies(command)).toBe(false)
  })
  it('a data payload that quotes the primitive stays silent (the existing -d rule is untouched)', () => {
    expect(denies(`curl -X POST http://localhost:3420/api/messages -d '{"content":"tmux send -t x"}'`)).toBe(false)
  })
})

describe('a script FILE a literal path runs may mention tmux only as a read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'selfpace-tmux-'))
  const write = (name: string, body: string, mode = 0o644) => {
    const p = join(dir, name)
    writeFileSync(p, body)
    chmodSync(p, mode)
    return p
  }
  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  it('denies a python driver that sends keys, run as `python3 <file>`', () => {
    const f = write('drv.py', "import subprocess\nsubprocess.run(['tmux','send','-t','x','hi'])\n")
    expect(denies(`python3 ${f}`)).toBe(true)
  })
  it('denies a shell driver, run as `bash <file>` and as a direct path', () => {
    const f = write('drv.sh', '#!/bin/bash\ntmux send -t x hi\n', 0o755)
    expect(denies(`bash ${f}`)).toBe(true)
    expect(denies(f)).toBe(true)
  })
  it('denies a relative path, resolved against the hook cwd', () => {
    write('rel.py', "import os\nos.system('tmux paste-buffer -t x')\n")
    expect(denies('python3 rel.py', dir)).toBe(true)
  })
  it('allows a file whose only mention is a comment (scripts/agent-msg.sh says "tmux" in one)', () => {
    const f = write('msg.sh', "#!/bin/bash\n# An agent's tmux session does not see this variable\ncurl -s localhost:3420\n", 0o755)
    expect(denies(`bash ${f}`)).toBe(false)
  })
  it('allows a file that only READS tmux', () => {
    const f = write('read.py', "import subprocess\nprint(subprocess.run(['tmux','ls'],capture_output=True).stdout)\n")
    // the list line is a python call, not a shell read: it is still a mention outside the two provable forms
    expect(denies(`python3 ${f}`)).toBe(true)
    const g = write('read.sh', '#!/bin/bash\ntmux ls\ntmux capture-pane -p -t x\n', 0o755)
    expect(denies(`bash ${g}`)).toBe(false)
  })
  it('allows a file that does not mention tmux at all', () => {
    const f = write('plain.py', 'print(1)\n')
    expect(denies(`python3 ${f}`)).toBe(false)
  })
  it('KNOWN LIMIT, pinned: a name that is never spelled tmux is not seen', () => {
    expect(denies("python3 - <<'PY'\nimport subprocess\nsubprocess.run(['tm'+'ux','se'+'nd','-t','x','hi'])\nPY")).toBe(false)
  })
})

describe('round 2: an interpreter runs a script FILE only when the gate can name and read it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'selfpace-path-'))
  const ok = join(dir, 'ok.py')
  writeFileSync(ok, 'print(1)\n')
  writeFileSync(join(dir, 'ok.sh'), '#!/bin/bash\necho hi\n')
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  const verdict = (command: string, cwd?: string) => gateDecision('Bash', { command }, { cwd })

  it('allows a literal path to a readable script with no tmux in it', () => {
    expect(verdict(`python3 ${ok}`).deny).toBe(false)
    expect(verdict(`bash ${join(dir, 'ok.sh')}`).deny).toBe(false)
    expect(verdict('python3 ok.py', dir).deny).toBe(false)
  })
  it('allows a $NAME the SAME command set to a literal earlier, and a literal cd before a relative path', () => {
    expect(verdict(`S=${dir}; python3 $S/ok.py`).deny).toBe(false)
    expect(verdict(`S=${dir} && python3 "$S/ok.py"`).deny).toBe(false)
    expect(verdict(`export S=${dir}; python3 \${S}/ok.py`).deny).toBe(false)
    expect(verdict(`cd ${dir} && python3 ok.py`).deny).toBe(false)
    expect(verdict(`S=${dir}; cd $S && python3 ok.py`).deny).toBe(false)
  })
  it('denies a computed path, with the script-path reason', () => {
    for (const command of [
      'python3 "$S/ok.py"',
      'python3 $HOME/x.py',
      `for t in a.py b.py; do python3 "$t"; done`,
      `python3 ${dir}/*.py`,
      'python3 $(ls x.py)',
      `S=$(mktemp -d); python3 $S/ok.py`,
    ]) {
      const d = verdict(command, dir)
      expect(d.deny, command).toBe(true)
      expect(d.reason, command).toBe('script-path')
    }
  })
  it('denies a path the gate cannot read: missing, a directory', () => {
    expect(verdict('python3 /no/such/file.py').deny).toBe(true)
    expect(verdict(`python3 ${dir}`).deny).toBe(true)
    expect(verdict('python3 missing.py', dir).deny).toBe(true)
  })
  it('denies a relative path after a cd the gate cannot follow', () => {
    expect(verdict(`cd "$(mktemp -d)" && python3 ok.py`, dir).deny).toBe(true)
    expect(verdict(`T=$(mktemp -d); cd "$T" && python3 ok.py`, dir).deny).toBe(true)
  })
  it('inline code and stdin are text, not a file: never a script-path deny', () => {
    for (const command of [
      'python3 -c "print(1)"',
      'python3 -m pytest -q',
      "python3 - <<'PY'\nprint(1)\nPY",
      'python3 -I -B -c "print(1)"',
      "bash -c 'echo hi'",
      'node -e "console.log(1)"',
      'node --require x -e "1"',
      'perl -e "print 1"',
      'ruby -e "puts 1"',
    ]) {
      expect(verdict(command, dir).deny, command).toBe(false)
    }
  })
  it('skips the value of an option that takes one (python -W, node --require) and judges the next word', () => {
    expect(verdict(`python3 -W ignore ${ok}`).deny).toBe(false)
    expect(verdict('python3 -W ignore "$S/ok.py"', dir).deny).toBe(true)
    expect(verdict(`node --require ${ok} ${ok}`).deny).toBe(false)
  })
  it('a path run directly: judged only when literal, readable and a script; a binary or a computed path is a named limit', () => {
    expect(verdict('/usr/bin/git --version').deny).toBe(false)
    expect(verdict('$S/whatever --flag').deny).toBe(false)
    expect(verdict(join(dir, 'ok.sh')).deny).toBe(false)
  })
  it('a substitution closing paren on the target is not part of the path', () => {
    expect(verdict(`T=$(python3 ${ok})`).deny).toBe(false)
    expect(verdict(`OUT=$(echo x | node ${ok})`).deny).toBe(false)
  })
  it('a test file under __tests__ has NO exemption (round 5, Sam\'s K13): the HEAD-blob rule decides, as for any script', () => {
    const repo = mkdtempSync(join(tmpdir(), 'selfpace-exempt-'))
    try {
      const g = (...args: string[]) => spawnSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf-8' })
      expect(g('init', '-q').status).toBe(0)
      mkdirSync(join(repo, 'scripts', '__tests__'), { recursive: true })
      const t = join(repo, 'scripts', '__tests__', 'gate.test.py')
      const DATA = "CASES = ['tmux send -t x hi']\nprint(CASES)\n"
      writeFileSync(t, DATA)
      const inRepo = (command: string) => gateDecision('Bash', { command }, { installRoot: repo })
      expect(inRepo(`python3 ${t}`).deny).toBe(true) // untracked
      expect(g('add', 'scripts/__tests__/gate.test.py').status).toBe(0)
      expect(inRepo(`python3 ${t}`).deny).toBe(true) // staged is not enough (it was, in round 4)
      expect(g('commit', '-q', '-m', 'test').status).toBe(0)
      expect(inRepo(`python3 ${t}`).deny).toBe(false) // the HEAD blob: the same rule as every script
      writeFileSync(t, DATA + "print('driver appended')\n")
      expect(inRepo(`python3 ${t}`).deny).toBe(true) // an EDITED tracked test (Sam's K13): scanned
      // the same file name outside the install checkout: scanned like any other file
      mkdirSync(join(dir, 'scripts', '__tests__'), { recursive: true })
      const outside = join(dir, 'scripts', '__tests__', 'gate.test.py')
      writeFileSync(outside, DATA)
      expect(inRepo(`python3 ${outside}`).deny).toBe(true)
      expect(verdict(`python3 ${outside}`).deny).toBe(true) // and against the real install (not this repo)
    } finally {
      rmSync(repo, { recursive: true, force: true })
    }
  })
  it('KNOWN LIMIT, pinned: a script that runs another script is judged by its own lines only', () => {
    const inner = join(dir, 'inner.py')
    writeFileSync(inner, "import subprocess\nsubprocess.run(['tmux','send','-t','x','hi'])\n")
    const outer = join(dir, 'outer.py')
    writeFileSync(outer, `import runpy\nrunpy.run_path('${inner}')\n`)
    expect(verdict(`python3 ${outer}`).deny).toBe(false)
  })
})

describe('what counts as the word', () => {
  it.each([
    ['src/tmux.ts', true],
    ['tmux-exact-target.test.ts', true],
    ['agent-tmux', true],
    ['$TMUX', true],
    ['${TMUX}', true],
    ['$TMUX_TMPDIR', true],
  ])('%s is not a mention of the binary', (text, silent) => {
    expect(tmuxMentionAllowed(`echo ${text}`)).toBe(silent)
    expect(tmuxMentionAllowed(`git add ${text}`)).toBe(silent)
  })
  it('a bare tmux outside a read form is a mention', () => {
    expect(tmuxMentionAllowed('git add tmux')).toBe(false)
  })
})

// Sam's round-1 review of card 9f57f705 (comment 1665): the shapes that got through b30c860b, each with the allowed twin.
describe('round 3: write-then-run in ONE command, wrappers, source, language-bound comments, tmux own options', () => {
  const dir = mkdtempSync(join(tmpdir(), 'selfpace-r3-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  const f = (name: string, body: string) => {
    const p = join(dir, name)
    writeFileSync(p, body)
    return p
  }
  const SEND_PY = "import subprocess\nsubprocess.run(['tmux','send','-t','x','hi'])\n"
  const CLEAN_PY = 'print(1)\n'
  const drvPy = f('drv.py', SEND_PY)
  const cleanPy = f('clean.py', CLEAN_PY)
  const drvSh = f('drv.sh', '#!/bin/bash\ntmux send -t x hi\n')
  const cleanSh = f('clean.sh', '#!/bin/bash\necho hi\n')
  const drvTs = f('drv.ts', "import { execFileSync } from 'node:child_process'\nexecFileSync('tmux', ['send', '-t', 'x', 'hi'])\n")
  const cleanTs = f('clean.ts', 'console.log(1)\n')
  const dd = (command: string, cwd?: string) => denies(command, cwd)

  it.each([
    ['heredoc to a .sh, then bash it', `cat > ${dir}/a1.sh <<'EOF'\ntmux send -t x hi\nEOF\nbash ${dir}/a1.sh`],
    ['heredoc to a .py, then python it', `cat > ${dir}/a2.py <<'EOF'\n${SEND_PY}EOF\npython3 ${dir}/a2.py`],
    ['cd, heredoc to a relative .py, then run it', `cd ${dir} && cat > a3.py <<'EOF'\n${SEND_PY}EOF\npython3 a3.py`],
    ['echo > file, then bash it', `echo 'tmux send -t x hi' > ${dir}/a4.sh; bash ${dir}/a4.sh`],
    ['printf > file && bash', `printf 'tmux send -t x hi\\n' > ${dir}/a5.sh && bash ${dir}/a5.sh`],
    ['a variable path written then run', `S=${dir}; cat > $S/a6.sh <<'EOF'\ntmux send -t x hi\nEOF\nbash $S/a6.sh`],
    ['tee with a heredoc, then run', `tee ${dir}/a7.sh <<'EOF'\ntmux send -t x hi\nEOF\nbash ${dir}/a7.sh`],
    ['heredoc redirect after the marker', `cat <<'EOF' > ${dir}/a8.sh\ntmux send -t x hi\nEOF\nbash ${dir}/a8.sh`],
  ])('S1 denied: %s', (_l, command) => {
    // the reason matters: a file that does not exist yet would also be a deny (script-path), the scan of the WRITTEN text is the point
    expect(gateDecision('Bash', { command }, {})).toEqual({ deny: true, reason: 'tmux-script' })
  })
  it.each([
    ['a clean script written and run', `cat > ${dir}/b1.sh <<'EOF'\necho hi\nEOF\nbash ${dir}/b1.sh`],
    ['a script that only READS tmux, written and run', `cat > ${dir}/b2.sh <<'EOF'\ntmux ls\ntmux capture-pane -p -t x\nEOF\nbash ${dir}/b2.sh`],
    ['prose about tmux written to a text file and not run', `cat > ${dir}/b3.txt <<'EOF'\nthe tmux send path is closed\nEOF`],
    ['prose written to a .md and a clean script run', `cat > ${dir}/b4.md <<'EOF'\nthe tmux send path\nEOF\nbash ${cleanSh}`],
    ['echo a clean line to a file, then run it', `echo 'echo hi' > ${dir}/b5.sh; bash ${dir}/b5.sh`],
    ['printf a read to a file, then run it', `printf 'tmux ls\\n' > ${dir}/b6.sh && bash ${dir}/b6.sh`],
  ])('S1 allowed: %s', (_l, command) => {
    expect(dd(command)).toBe(false)
  })

  it.each([
    ['timeout', `timeout 5 python3 ${drvPy}`],
    ['timeout with a flag', `timeout -k 2 5 python3 ${drvPy}`],
    ['stdbuf', `stdbuf -oL python3 ${drvPy}`],
    ['env', `env python3 ${drvPy}`],
    ['env with an assignment', `env FOO=1 python3 ${drvPy}`],
    ['a leading assignment and a wrapper', `FOO=1 timeout 5 bash ${drvSh}`],
    ['nice -n', `nice -n 10 python3 ${drvPy}`],
    ['sudo -u', `sudo -u bob python3 ${drvPy}`],
    ['time', `time bash ${drvSh}`],
    ['npx tsx', `npx tsx ${drvTs}`],
    ['tsx', `tsx ${drvTs}`],
    ['uv run a script', `uv run ${drvPy}`],
    ['uv run python', `uv run python3 ${drvPy}`],
    ['python -m runpy', `python3 -m runpy ${drvPy}`],
    ['source', `source ${drvSh}`],
    ['dot', `. ${drvSh}`],
    ['direct path to a script', `${drvSh}`],
  ])('S2 denied behind a wrapper: %s', (_l, command) => {
    expect(dd(command)).toBe(true)
  })
  it.each([
    ['timeout', `timeout 5 python3 ${cleanPy}`],
    ['env', `env FOO=1 python3 ${cleanPy}`],
    ['nice -n', `nice -n 10 bash ${cleanSh}`],
    ['npx tsx', `npx tsx ${cleanTs}`],
    ['uv run', `uv run ${cleanPy}`],
    ['python -m runpy', `python3 -m runpy ${cleanPy}`],
    ['source', `source ${cleanSh}`],
    ['python -m pytest (a module, not a file)', 'python3 -m pytest -q'],
  ])('S2 allowed when the file is clean: %s', (_l, command) => {
    expect(dd(command)).toBe(false)
  })
  it('a path run directly with no extension: the shebang makes it a script; a file without one is a binary and is not read', () => {
    const noext = join(dir, 'drv-noext')
    writeFileSync(noext, '#!/bin/bash\ntmux send -t x hi\n')
    chmodSync(noext, 0o755)
    expect(dd(noext)).toBe(true)
    const bin = join(dir, 'fake-binary')
    writeFileSync(bin, 'ELF\u0000\u0001 tmux send -t x hi')
    chmodSync(bin, 0o755)
    expect(dd(bin)).toBe(false)
  })
  it('S2: cd is followed, so a relative script is found from the cd target and not from the session cwd', () => {
    expect(dd(`cd ${dir} && python3 drv.py`, '/tmp')).toBe(true)
    expect(dd(`cd ${dir} && python3 clean.py`, '/tmp')).toBe(false)
    expect(dd('python3 drv.py', dir)).toBe(true)
    expect(dd('python3 clean.py', dir)).toBe(false)
  })

  it.each([
    ['bash case arm', 'bash', 'drv-case.sh', '#!/bin/bash\ncase "$1" in\n  *) tmux send -t x "$1" ;;\nesac\n'],
    ['JS block comment, then code on the line', 'node', 'drv-c.js', "/* c */ require('child_process').execFileSync('tmux',['send','-t','x','hi'])\n"],
    ['JS class field starting with #', 'node', 'drv-f.js', "class A {\n  #r = require('child_process').execFileSync('tmux',['send','-t','x','hi'])\n}\n"],
    ['python star-unpacking line', 'python3', 'drv-s.py', "import subprocess\n*_, = [subprocess.run(['tmux','send','-t','x','hi'])]\n"],
  ])('K1 denied (a code line a marker set would have skipped): %s', (_l, interp, name, body) => {
    expect(dd(`${interp} ${f(name, body)}`)).toBe(true)
  })
  it.each([
    ['shell # comment', 'bash', 'ok-c.sh', "#!/bin/bash\n# An agent's tmux session does not see this variable\necho hi\n"],
    ['python # comment', 'python3', 'ok-c.py', '# the tmux send path is closed\nprint(1)\n'],
    ['JS // comment', 'node', 'ok-c.js', '// tmux send is closed\nconsole.log(1)\n'],
    ['JS one-line block comment', 'node', 'ok-b.js', '/* tmux send is closed */\nconsole.log(1)\n'],
  ])('K1 allowed (a whole-line comment of that language): %s', (_l, interp, name, body) => {
    expect(dd(`${interp} ${f(name, body)}`)).toBe(false)
  })

  it.each([
    'tmux -c ./drv.sh ls',
    'tmux -c id has-session',
    "printf 'send -t x hi\\n' | tmux -C ls",
    'tmux -f /tmp/x.conf ls',
    'tmux -uCC ls',
    'tmux -2c ls',
  ])("K2 denied: tmux's own %s is not a read form", (command) => {
    expect(dd(command)).toBe(true)
  })
  it('K2: -L / -S / -T still take a value and the read stays silent', () => {
    expect(dd('tmux -L work ls')).toBe(false)
    expect(dd('tmux -S /tmp/tmux-1000/default list-panes -a')).toBe(false)
    expect(dd('tmux -T RGB has-session -t x')).toBe(false)
  })

  it.each([
    "tm''ux send -t x hi",
    '"tm"ux send -t x hi',
    't""mux send -t x hi',
    "t'm'u'x' send -t x hi",
  ])('quote concatenation is one word to bash: %s', (command) => {
    expect(dd(command)).toBe(true)
  })

  it.each([
    ['if tmux has-session', 'if tmux has-session -t hex 2>/dev/null; then echo up; fi'],
    ['pgrep -a tmux', 'pgrep -a tmux'],
    ['a substitution of a read', "S=$(tmux display-message -p '#S'); echo $S"],
    ['command -v tmux', 'command -v tmux'],
    ['which tmux', 'which tmux'],
    ['a while loop on a read', 'while tmux has-session -t x 2>/dev/null; do sleep 1; done'],
  ])('K3 read forms inside scripts stay silent: %s (as a command and inside a file)', (_l, command) => {
    expect(dd(command)).toBe(false)
    expect(dd(`bash ${f(`k3-${_l.replace(/\W+/g, '-')}.sh`, `#!/bin/bash\n${command}\n`)}`)).toBe(false)
  })
})

describe('round 4: only a file of the INSTALL repo (main checkout or linked worktree), byte-identical to its own HEAD blob, is waived from the tmux scan', () => {
  const repo = mkdtempSync(join(tmpdir(), 'selfpace-git-'))
  const foreign = mkdtempSync(join(tmpdir(), 'selfpace-foreign-'))
  const wt = join(tmpdir(), `selfpace-wt-${process.pid}`)
  afterAll(() => {
    rmSync(repo, { recursive: true, force: true })
    rmSync(foreign, { recursive: true, force: true })
    rmSync(wt, { recursive: true, force: true })
  })
  const gitIn = (root: string) => (...args: string[]) => spawnSync('git', ['-C', root, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf-8' })
  const git = gitIn(repo)
  const SEND_SH = '#!/bin/bash\ntmux send -t x hi\n'
  // the install is `repo`
  const run = (command: string) => gateDecision('Bash', { command }, { installRoot: repo }).deny === true
  it('waives a file byte-identical to the blob in HEAD (the fleet\'s own daemon scripts); an edited or untracked one is scanned', () => {
    expect(git('init', '-q').status).toBe(0)
    const tracked = join(repo, 'daemon.sh')
    writeFileSync(tracked, SEND_SH)
    expect(run(`bash ${tracked}`)).toBe(true) // not committed yet
    expect(git('add', 'daemon.sh').status).toBe(0)
    expect(git('commit', '-q', '-m', 'add daemon').status).toBe(0)
    expect(run(`bash ${tracked}`)).toBe(false) // the HEAD blob
    writeFileSync(tracked, SEND_SH + 'echo changed\n')
    expect(run(`bash ${tracked}`)).toBe(true) // edited since HEAD
    expect(git('commit', '-q', '-a', '-m', 'edit').status).toBe(0)
    expect(run(`bash ${tracked}`)).toBe(false) // committed again
    const loose = join(repo, 'driver.sh')
    writeFileSync(loose, SEND_SH)
    expect(run(`bash ${loose}`)).toBe(true) // untracked: the agent's own driver
    expect(run(`cat > ${tracked} <<'EOF'\n${SEND_SH}EOF\nbash ${tracked}`)).toBe(true) // the text this command writes is scanned on its own, the waiver is for the disk file
  })
  it('a LINKED WORKTREE of the install gets the same rule against its OWN HEAD (HEX 4015: a review worktree runs the suites it reviews)', () => {
    expect(git('worktree', 'add', '-q', '--detach', wt, 'HEAD').status).toBe(0)
    const wtFile = join(wt, 'daemon.sh')
    expect(run(`bash ${wtFile}`)).toBe(false) // clean: the blob of the worktree's HEAD
    writeFileSync(wtFile, SEND_SH + 'echo edited in the worktree\n')
    expect(run(`bash ${wtFile}`)).toBe(true) // edited since the worktree's HEAD: scanned
    const loose = join(wt, 'wt-driver.sh')
    writeFileSync(loose, SEND_SH)
    expect(run(`bash ${loose}`)).toBe(true) // untracked in the worktree: scanned
    expect(spawnSync('git', ['-C', wt, 'checkout', '-q', '--', 'daemon.sh']).status).toBe(0)
    // KNOWN LIMIT, pinned: the agent may commit a driver in its OWN worktree (prod-tree-guard covers only the main checkout);
    // a standing limit: card deecccda closes only the HEAD-moving route, a commit in a worktree is ordinary work
    expect(spawnSync('git', ['-C', wt, 'add', 'wt-driver.sh']).status).toBe(0)
    expect(gitIn(wt)('commit', '-q', '-m', 'driver in the worktree').status).toBe(0)
    expect(run(`bash ${loose}`)).toBe(false)
  })
  it('a file in ANOTHER git repo is never waived, committed or not (the agent\'s own git init)', () => {
    const f = gitIn(foreign)
    expect(f('init', '-q').status).toBe(0)
    const driver = join(foreign, 'drv.sh')
    writeFileSync(driver, SEND_SH)
    expect(f('add', 'drv.sh').status).toBe(0)
    expect(f('commit', '-q', '-m', 'driver').status).toBe(0)
    expect(run(`bash ${driver}`)).toBe(true) // committed in its own repo: still the agent's own driver
    expect(gateDecision('Bash', { command: `bash ${driver}` }, {}).deny).toBe(true) // and against the real install
  })
  it('KNOWN LIMIT, pinned: a driver that is the install checkout\'s HEAD blob passes, however HEAD got there (prod-tree-guard stops a direct commit, not a fast-forward)', () => {
    const own = join(repo, 'agent-driver.sh')
    writeFileSync(own, SEND_SH)
    expect(git('add', 'agent-driver.sh').status).toBe(0)
    expect(git('commit', '-q', '-m', 'driver').status).toBe(0)
    expect(run(`bash ${own}`)).toBe(false)
  })
})

describe('round 4: a heredoc is not shell code when the shell runs a script FILE; command -v runs nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'selfpace-r4-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  const msg = join(dir, 'agent-msg.sh')
  writeFileSync(msg, '#!/bin/bash\ncat\n')
  const verdict = (command: string) => gateDecision('Bash', { command }, {})
  it('the fleet\'s message recipe: a body that QUOTES a command is that script\'s stdin, not a run (Sam\'s K10)', () => {
    expect(verdict(`bash ${msg} sam hex - <<'EOF'\nrun it as: x | bash nofile.sh arg -\nEOF`).deny).toBe(false)
    expect(verdict(`bash ${msg} sam hex - <<'EOF'\nthe regex agent-msg.sh .* - matched\nEOF`).deny).toBe(false)
  })
  it('a shell that reads its PROGRAM from the heredoc still has the body read as code', () => {
    for (const head of ['bash', 'bash -s', 'bash -', 'sh -s arg', 'bash -x', 'bash -o pipefail']) {
      expect(verdict(`${head} <<'EOF'\nbash ${join(dir, 'missing.sh')}\nEOF`).deny).toBe(true)
    }
  })
  it('`sh -s arg` takes its program from stdin: `arg` is its $1, not a script file', () => {
    expect(verdict(`sh -s arg <<'EOF'\necho hi\nEOF`).deny).toBe(false)
    expect(verdict(`bash -xs a b <<'EOF'\necho hi\nEOF`).deny).toBe(false)
  })
  it('and a script FILE named after the heredoc owner does not hide a second command that runs one', () => {
    expect(verdict(`bash ${msg} sam hex - <<'EOF'\nhi\nEOF\npython3 ${join(dir, 'missing.py')}`).deny).toBe(true)
  })
  it('command -v / -V names programs and runs none; a bare command still runs its program', () => {
    expect(verdict('command -v node pytest').deny).toBe(false)
    expect(verdict('command -V node pytest').deny).toBe(false)
    expect(verdict('X=1 command -p -v node pytest').deny).toBe(false)
    expect(verdict(`command node ${join(dir, 'missing.js')}`).deny).toBe(true)
    expect(verdict(`command -v node $(python3 ${join(dir, 'missing.py')})`).deny).toBe(true) // a substitution may run one
    expect(verdict(`command -v node; python3 ${join(dir, 'missing.py')}`).deny).toBe(true) // the second command is judged
  })
})

describe('round 3: what is shell text and what is another language\'s code', () => {
  it('a python / node heredoc body is code: `node = ...` or prose that starts with an interpreter name is not a run', () => {
    expect(denies("python3 - <<'PY'\nnode = make_node()\nbash is a shell, not a script path\nPY")).toBe(false)
    expect(denies("node - <<'JS'\nconst sh = 1\nJS")).toBe(false)
  })
  it('a SHELL heredoc body is shell text: its lines are commands and are judged', () => {
    expect(denies("bash <<'EOF'\npython3 \"$X/y.py\"\nEOF")).toBe(true)
    expect(denies("bash <<'EOF'\necho hi\nEOF")).toBe(false)
  })
  it('an assignment or a call after an interpreter name is not a script path', () => {
    expect(denies('node = 5')).toBe(false)
    expect(denies('sh (x)')).toBe(false)
  })
})
