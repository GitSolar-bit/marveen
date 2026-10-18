#!/usr/bin/env python3
"""COMMENTMASK1013: a `#` comment line in front of a curl must not silence the Bash arm of the copy gate.

Measured by Sam (msg 3642) on the LIVE gate: `_mask_subshell_markers` turns a newline outside quotes into `;`, and the
`shlex` that runs after it has commenters='#', so a comment swallowed everything up to the END of the command:
`_segments_tokens('# post\\ncurl -X POST https://x/feed/posts -d hi') == []`. Every channel that is recognised from a
segment (the community feed, /api/messages, the kanban routes, sendmail) went quiet when ANY line before the curl held a
comment. shlex also read a `#` in the middle of a word as a comment (`curl https://x/y#z -d hi` lost its `-d hi`).

Contract pinned here:
  - for each base command (blocked or clean) the verdict is the SAME with a comment line in front, a trailing comment on
    an earlier line, several comment lines, and a comment between two commands;
  - a comment on the curl's OWN line (Sam's C6) never changed anything, and stays unchanged;
  - `#` only starts a comment at the start of a word (bash): `$#`, `${#x}`, `y#z` and a `#` inside quotes are not comments;
  - a comment does not HIDE a send (sendmail after a comment is a send) and a command named only in a comment is not one.

Run: python3 <thisfile>   Exit 0 = all pass. GATE=<path> runs it against another copy of the gate.
"""
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.environ.get("GATE") or os.path.join(os.path.dirname(HERE), "hooks", "outgoing-copy-gate.py")

CY_E = "е"  # CYRILLIC SMALL LETTER IE
MIO = "https://api.marveen.io"
MSG = "http://localhost:3420/api/messages"
HDR = '-H "Content-Type: application/json"'

UNACCENTED = "Szia, ez egy teszt uzenet, ekezet nelkul irva, de magyar szoveg."
HOMOGLYPH = "Szia, ez egy k" + CY_E + "rdés a keresésről."
CLEAN = "Szia, ez egy rendes, ékezetes mondat."


def run_gate(cmd: str) -> int:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    return subprocess.run([sys.executable, GATE], input=payload.encode(), capture_output=True).returncode


def feed(content):
    return f"curl -s -X POST {MIO}/feed/posts -d '{json.dumps({'title': 'x', 'content': content}, ensure_ascii=False)}'"


def msg_heredoc(content):
    return (f"curl -s -X POST {MSG} {HDR} --data-binary @- <<'JSON'\n"
            + json.dumps({"from": "igor", "to": "hex", "content": content}, ensure_ascii=False) + "\nJSON")


BASES = [
    ("feed, unaccented text", feed(UNACCENTED), 2),
    ("feed, Cyrillic lookalike in a Latin word", feed(HOMOGLYPH), 2),
    ("feed, clean accented text", feed(CLEAN), 0),
    ("/api/messages, own heredoc, Cyrillic lookalike", msg_heredoc(HOMOGLYPH), 2),
    ("/api/messages, own heredoc, clean", msg_heredoc(CLEAN), 0),
]
FRONTS = [
    ("a comment line in front", "# post\n{c}"),
    ("a trailing comment on an earlier line", "cd /tmp # go\n{c}"),
    ("several comment lines and a blank one", "# a\n# b\n\n# c\n{c}"),
    ("a comment between two commands", "echo start\n# now the post\n{c}"),
    ("a comment with quotes and a semicolon in it", "# it's the post; \"really\"\n{c}"),
    ("an indented comment", "   # post\n{c}"),
    ("a comment line with an apostrophe, NOT on the first line (Sam 3655 P2)", "echo a\n# it's the post\n{c}"),
    ("a comment line with an unbalanced double quote, not on the first line (P3)", "echo a\n# say \"hi\n{c}"),
    ("two comment lines, the second with an apostrophe (P4)", "# a\n# don't\n{c}"),
    ("a comment line holding a double-quoted phrase AND an apostrophe, far down the command (Sam's Zola shape)",
     "cd /tmp\nT=1\necho a\necho b\necho c\n# header: remove \"ellenorzes alatt\" now that Sam's last round is done\n{c}"),
    ("a comment right after a `)` (P9)", "(true)# it's\n{c}"),
    ("a comment right after a `)` and a newline", "(true)\n# it's\n{c}"),
    ("a comment right after a `;` (no space)", "echo start;# post\n{c}"),
    ("a comment right after a `&&`", "true &&# post\n{c}"),
]

cases = []  # (name, cmd, want)
for bname, base, want in BASES:
    cases.append((f"{bname}: plain", base, want))
    for fname, front in FRONTS:
        cases.append((f"{bname}: {fname}", front.format(c=base), want))
# C6: a comment on the curl's OWN line never changed anything
cases.append(("C6: feed, trailing comment on the curl's own line, blocked", feed(HOMOGLYPH) + " # post", 2))
cases.append(("P5: a comment line with an apostrophe AFTER the curl too", "echo a\n# it's the post\n" + feed(HOMOGLYPH) + "\n# it's done", 2))
cases.append(("P5 clean twin", "echo a\n# it's the post\n" + feed(CLEAN) + "\n# it's done", 0))
cases.append(("C6: /api/messages heredoc with a comment on the curl line, blocked",
              msg_heredoc(HOMOGLYPH).replace("--data-binary @- <<'JSON'", "--data-binary @- <<'JSON' # post", 1), 2))
cases.append(("C6: clean one with a trailing comment passes", feed(CLEAN) + " # post", 0))
# `#` is a comment only at the start of a word
cases.append(("a `#` inside quotes is text: echo \"# x\"; dirty feed still BLOCKS", 'echo "# not a comment"; ' + feed(HOMOGLYPH), 2))
# Sam 3659: a `#` right after a backslash pair is part of the word (bash: `a\\ #b` is ONE word `a #b`). The cut used to look at the raw
# previous character (a blank, `;`, `)`, `>`, a tab) and swallowed the rest of the line, so the dirty curl went out unchecked.
for ename, esc in (("E1 escaped blank", "a\\ #b"), ("E3 escaped `;`", "a\\;#b"), ("E4 escaped `)`", "a\\)#b"),
                   ("E5 escaped `>`", "a\\>#b"), ("E6 escaped tab", "a\\\t#b")):
    for bname, base, want in ((" dirty feed", feed(HOMOGLYPH), 2), (" clean feed", feed(CLEAN), 0)):
        cmd = base.replace("curl -s -X POST", "curl -s -X POST -H X-T:" + esc, 1)
        cases.append((f"{ename}: the `#` is mid-word, the rest of the command is read,{bname}", cmd, want))
cases.append(("an escaped backslash and then a REAL blank before the `#`: that one IS a comment, the next line is read",
              "echo a\\\\ # it's gone\n" + feed(HOMOGLYPH), 2))
cases.append(("K1 (named limit): after a backslash-newline the `#` starts a bash comment (the body is not sent), here it is not cut: the dirty body is still read and BLOCKED, the safe way",
              f"curl -s -X POST {MIO}/feed/posts \\\n#x -d '{json.dumps({'title': 'x', 'content': HOMOGLYPH}, ensure_ascii=False)}'", 2))
cases.append(("`$#` and `${#x}` before the curl are not comments", 'echo $# ${#PATH}; ' + feed(HOMOGLYPH), 2))
cases.append(("a `#` in the middle of a word (an unquoted header value) does not eat the rest of the command",
              f"curl -s -X POST -H X-Tag:a#b {MIO}/feed/posts -d '{json.dumps({'title': 'x', 'content': HOMOGLYPH}, ensure_ascii=False)}'", 2))
cases.append(("an escaped \\# is a letter, not a comment", "echo a\\#b; " + feed(HOMOGLYPH), 2))

failed = []
for name, cmd, want in cases:
    got = run_gate(cmd)
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: exit={got} want={want}")
    if not ok:
        failed.append(name)

# segmentation and send recognition, straight on the gate's functions
spec = importlib.util.spec_from_file_location("gate_under_test", GATE)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
SEG = [
    ("segments: a comment line in front leaves the curl segment",
     lambda: g._segments_tokens("# post\ncurl -X POST https://x/feed/posts -d hi"),
     [["curl", "-X", "POST", "https://x/feed/posts", "-d", "hi"]]),
    ("segments: a trailing comment is cut, the next line stays",
     lambda: g._segments_tokens("cd /tmp # go\ncurl -d hi https://x"),
     [["cd", "/tmp"], ["curl", "-d", "hi", "https://x"]]),
    ("segments: y#z stays one token", lambda: g._segments_tokens("curl https://x/y#z -d hi"),
     [["curl", "https://x/y#z", "-d", "hi"]]),
    ("segments: $# and ${#x} stay tokens", lambda: g._segments_tokens("echo ${#x} $# ; curl x"),
     [["echo", "${#x}", "$#"], ["curl", "x"]]),
    ("segments: a # inside quotes stays text", lambda: g._segments_tokens('echo "a # b" ; curl x'),
     [["echo", "a # b"], ["curl", "x"]]),
    ("segments: a comment after a newline, a `)` and `>` is cut (no leftover tokens, no parse error)",
     lambda: g._segments_tokens("echo a\n# it's x\n(true)# y\necho b >#f\ncurl z"),
     [["echo", "a"], ["true"], ["echo", "b", ">"], ["curl", "z"]]),
    ("segments: a comment right after a `<` is cut",
     lambda: g._segments_tokens("echo a <#f\ncurl z"), [["echo", "a", "<"], ["curl", "z"]]),
    ("segments: an escaped blank keeps the `#` in the word",
     lambda: g._segments_tokens("curl a\\ #b -d hi"), [["curl", "a #b", "-d", "hi"]]),
    ("segments: a comment after a TAB with an apostrophe is cut",
     lambda: g._segments_tokens("echo a\t# it's x\ncurl z"), [["echo", "a"], ["curl", "z"]]),
    ("segments: a comment right after a `|` with an apostrophe is cut",
     lambda: g._segments_tokens("echo a |# it's x\ncat"), [["echo", "a"], ["cat"]]),
    ("segments: a comment right after a `(` with an apostrophe is cut",
     lambda: g._segments_tokens("(# it's x\ntrue)\ncurl z"), [["true"], ["curl", "z"]]),
    ("segments: a comment right after ; or && is cut (no `#` token left over)",
     lambda: g._segments_tokens("echo a;# note\ntrue &&# more\ncurl x"),
     [["echo", "a"], ["true"], ["curl", "x"]]),
    ("send: sendmail on the line after a comment IS a send", lambda: g.is_send_invocation("# note\nsendmail -t"), True),
    ("send: sendmail named only in a comment is NOT a send", lambda: g.is_send_invocation("echo hi # sendmail -t"), False),
]
for name, fn, want in SEG:
    try:
        got = fn()
    except Exception as exc:  # a parse error is a failure of the case, not a crash of the file
        got = f"{type(exc).__name__}: {exc}"
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {got!r}")
    if not ok:
        failed.append(name)

total = len(cases) + len(SEG)
if failed:
    print(f"\n{len(failed)} of {total} FAILED: {failed}")
    sys.exit(1)
print(f"\nAll {total} comment-mask tests passed.")
