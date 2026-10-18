/**
 * The Sam-green gate (30-sam-green-gate) is a member of pre-push.required: deleting it or swapping
 * its bytes for `exit 0` blocks the push instead of silently running one check fewer (HEX 3474).
 *
 * Real repositories, the real installers (git-guard writes the dispatcher, sam-green writes the
 * member and registers it) and real `git push`. The installers only ever run against a TEMP copy of
 * the scripts: run against the real checkout they would write into the shared .git of every worktree.
 * The pushes run WITHOUT the Claude Code environment markers, so the Sam-green gate itself takes its
 * "not an agent session" path and the only thing under test is the dispatcher's manifest check.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, cpSync, readFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO = process.cwd();
const AGENT_MARKERS = ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_SESSION_ID', 'CLAUDE_CODE_EXECPATH'];

function humanEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const k of AGENT_MARKERS) delete env[k];
  return env;
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', env: humanEnv() });
}

let tmp: string;
let work: string;
let remote: string;
let member: string;
let n = 0;

const out = (r: { stdout: string; stderr: string }) => `${r.stdout}${r.stderr}`;

function pushBranch(): ReturnType<typeof spawnSync> {
  const branch = `b-${n++}`;
  git(work, ['checkout', '-q', '-b', branch, 'base']);
  writeFileSync(join(work, `f-${branch}.txt`), 'clean\n');
  git(work, ['add', '-A']);
  git(work, ['commit', '-q', '-m', 'clean change']);
  return spawnSync('git', ['push', 'origin', branch], { cwd: work, encoding: 'utf8', env: humanEnv() });
}

const install = (script: string) =>
  spawnSync('bash', [join(work, 'scripts', script)], { cwd: work, encoding: 'utf8', env: humanEnv() });

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'pp-manifest-'));
  work = join(tmp, 'work');
  remote = join(tmp, 'remote.git');
  mkdirSync(work, { recursive: true });
  git(work, ['init', '-q', '-b', 'main']);
  git(work, ['config', 'user.email', 'dev@example.com']);
  git(work, ['config', 'user.name', 'Dev']);
  git(work, ['config', 'commit.gpgsign', 'false']);
  mkdirSync(join(work, 'scripts', 'git-hooks'), { recursive: true });
  mkdirSync(join(work, 'store'), { recursive: true });
  for (const f of [
    'install-git-guard-hook.sh', 'install-sam-green-gate-hook.sh', join('git-hooks', 'pre-push-sam-green.py'),
  ]) cpSync(join(REPO, 'scripts', f), join(work, 'scripts', f));
  writeFileSync(join(work, 'README.txt'), 'base\n');
  git(work, ['add', '-A']);
  git(work, ['commit', '-q', '-m', 'base']);
  git(work, ['branch', 'base']);
  git(tmp, ['init', '-q', '--bare', remote]);
  git(work, ['remote', 'add', 'origin', remote]);
  expect(install('install-git-guard-hook.sh').status).toBe(0);
  expect(install('install-sam-green-gate-hook.sh').status).toBe(0);
  member = join(work, '.git', 'hooks', 'pre-push.d', '30-sam-green-gate');
});

afterAll(() => { rmSync(tmp, { recursive: true, force: true }); });

describe('30-sam-green-gate in pre-push.required', () => {
  it('the installer records the member with the sha256 of the bytes it wrote, next to the git-guard member', () => {
    const lines = readFileSync(join(work, '.git', 'hooks', 'pre-push.required'), 'utf8').trim().split('\n');
    const want = execFileSync('sha256sum', [member], { encoding: 'utf8' }).split(' ')[0];
    expect(lines).toContain(`30-sam-green-gate ${want}`);
    expect(lines.some((l) => /^10-no-force-push-protected [0-9a-f]{64}$/.test(l))).toBe(true);
  });

  it('NEGATIVE CONTROL: with the member intact a clean push goes through', () => {
    const r = pushBranch();
    expect(r.status).toBe(0);
  });

  it('a member swapped for `exit 0` blocks the push (it is as off as one that is gone)', () => {
    const saved = readFileSync(member);
    writeFileSync(member, '#!/bin/sh\nexit 0\n');
    chmodSync(member, 0o755);
    try {
      const r = pushBranch();
      expect(r.status).not.toBe(0);
      expect(out(r as never)).toMatch(/required member 30-sam-green-gate does not match its recorded hash/);
    } finally {
      writeFileSync(member, saved);
      chmodSync(member, 0o755);
    }
  });

  it('a deleted member blocks the push', () => {
    const saved = readFileSync(member);
    rmSync(member);
    try {
      const r = pushBranch();
      expect(r.status).not.toBe(0);
      expect(out(r as never)).toMatch(/required member 30-sam-green-gate is missing -- BLOCKING/);
    } finally {
      writeFileSync(member, saved);
      chmodSync(member, 0o755);
    }
  });

  it('reinstalling re-records the hash, and does not duplicate the line', () => {
    writeFileSync(member, '#!/bin/sh\nexit 0\n');
    expect(install('install-sam-green-gate-hook.sh').status).toBe(0);
    const text = readFileSync(join(work, '.git', 'hooks', 'pre-push.required'), 'utf8');
    expect(text.match(/^30-sam-green-gate /gm)).toHaveLength(1);
    expect(pushBranch().status).toBe(0);
  });
});
