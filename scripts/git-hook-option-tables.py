#!/usr/bin/env python3
"""Print the option tables of the git subcommands that RUN client hooks, read from the installed git itself.

destructive-gate.py (card dafb69db) judges `git commit|merge|am|rebase|push|pull|cherry-pick|revert` by an ALLOWLIST of
options: an option it does not know is a deny, because "I cannot prove this keeps the hooks running" must not mean "it
was fine" (the owner's standing rule 11, inverted proof). The tables are baked into the gate; this script regenerates them.
scripts/__tests__/git-hook-switch-tables.test.py fails when the installed git knows an option the baked table does not,
so a git upgrade that adds an option (a new way to skip a hook included) is reviewed instead of passing silently.

  python3 scripts/git-hook-option-tables.py            # human-readable Python literal on stdout
  python3 scripts/git-hook-option-tables.py --json     # the same as JSON (used by the test)

Where the data comes from, per subcommand:
  long options  : `git <sub> --git-completion-helper-all` (the -all form lists the hidden ones too, e.g. commit --allow-empty) (a trailing `=` means the option takes a value)
  short options : the `-x` lines of `git <sub> -h`
  value rule    : a value in the NEXT word is assumed ONLY when git's usage text shows a required argument
                  (`--name <arg>`, `-x <arg>`); an optional attached value (`-u[<mode>]`, `--gpg-sign[=<key>]`) is never
                  assumed to consume the next word. Over-assuming would hide a following `-n` inside a "value".
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HOOKED = ('commit', 'merge', 'am', 'rebase', 'push', 'pull', 'cherry-pick', 'revert')


def _git(args, cwd):
    r = subprocess.run(['git'] + args, cwd=cwd, capture_output=True, text=True,
                       env=dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null'))
    return r.stdout + r.stderr


def tables():
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(['git', 'init', '-q', d], check=True, capture_output=True)
        out = {'git_version': _git(['--version'], d).strip(), 'subs': {}}
        for sub in HOOKED:
            helper = _git([sub, '--git-completion-helper-all'], d).split()
            usage = _git([sub, '-h'], d)
            long = {}
            for w in helper:
                if not w.startswith('--'):
                    continue
                name = w[2:].rstrip('=')
                if not name:
                    continue
                long[name] = 'value' if w.endswith('=') else None
            # refine 'value' with the usage text: required (`--name <arg>`) vs optional (`--name[=<arg>]`)
            for line in usage.splitlines():
                m = re.match(r'^\s+(?:-(\w)(?:\[[^\]]*\])?,\s+)?--(?:\[no-\])?([\w-]+)(\[=<[^>]*>\]|=<[^>]*>|\s+<[^>]*>)?', line)
                if m:
                    name, arg = m.group(2), m.group(3) or ''
                    for n in (name, 'no-' + name):
                        if n in long and long[n] == 'value':
                            long[n] = 'optional' if arg.startswith('[') else ('required' if arg else 'optional')
            shorts = {}
            for line in usage.splitlines():
                m = re.match(r'^\s+-(\w)(\[<[^>]*>\])?(?:,|\s|$)(\s*<[^>]*>)?', line)
                if m:
                    shorts[m.group(1)] = 'optional' if m.group(2) else ('required' if m.group(3) else None)
                m2 = re.match(r'^\s+-\w,\s+--(?:\[no-\])?([\w-]+)(\[=<[^>]*>\]|=<[^>]*>|\s+<[^>]*>)?', line)
                if m2 and m:
                    arg = m2.group(2) or ''
                    shorts[m.group(1)] = 'optional' if arg.startswith('[') else ('required' if arg else None)
            out['subs'][sub] = {'long': dict(sorted(long.items())), 'short': dict(sorted(shorts.items()))}
        return out


if __name__ == '__main__':
    t = tables()
    if '--json' in sys.argv:
        print(json.dumps(t, indent=1, sort_keys=True))
    else:
        print('# %s' % t['git_version'])
        for sub, d in t['subs'].items():
            print('%r: {' % sub)
            print("    'long': %r," % d['long'])
            print("    'short': %r," % d['short'])
            print('},')
