#!/usr/bin/env python3
"""Refuse text that carries Cyrillic or Greek letters inside Latin words.

Reads stdin, writes it back to stdout if clean. Exit code 3 and a report on
stderr if not. With --tisztit it replaces the known homoglyphs first and then
checks again, so the cleaning is never taken on trust.

WHY THIS EXISTS. Measured 2026-09-22: one agent sent a report with three
Cyrillic letters inside a Hungarian word, warned the recipient in the next
message, and the recipient quoted the contaminated word straight back. The
letters cannot be seen, and they break every later search for that word -- the
text looks right and matches nothing.

WHY IT IS HERE AND NOT IN ONE AGENT'S TOOLBOX (MSGGATE924). Two agents had
built this guard for themselves, independently, because both had been bitten;
a third had no guard at all, and nothing in the fleet told them to. Meanwhile
the route every CLAUDE.md prescribes -- scripts/agent-msg.sh -- had none. A
protection everyone has to remember to reach for is not a protection.
"""
import sys, unicodedata

CSERE = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
         "у": "y", "х": "x", "т": "t", "к": "k", "в": "v",
         "м": "m", "н": "n", "і": "i", "Ѕ": "S", "А": "A",
         "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T"}


def rossz(t):
    return [(i, c) for i, c in enumerate(t)
            if ord(c) > 127 and ("CYRILLIC" in unicodedata.name(c, "")
                                 or "GREEK" in unicodedata.name(c, ""))]


def main():
    t = sys.stdin.read()
    if "--tisztit" in sys.argv:
        t = "".join(CSERE.get(c, c) for c in t)
    r = rossz(t)
    if r:
        for i, c in r[:10]:
            sys.stderr.write(f"  {hex(ord(c))} {unicodedata.name(c, '?')} "
                             f"-> {t[max(0, i - 25):i + 10]!r}\n")
        sys.stderr.write(f"NEM KULDOM EL: {len(r)} nem-latin betu a szovegben.\n")
        # The first reflex must NOT be the override. Measured twice on
        # 2026-09-24: both refusals were correct, and both were triggered by a
        # correction QUOTING the contaminated word it was reporting. The fix is
        # to name the word instead of copying it -- TISZTIT=1 is for the case
        # where the text itself is the payload and has to go out cleaned.
        sys.stderr.write(
            "  Mit tegyel: a szennyezett alakot NE masold at (nevezd meg,\n"
            "  idezes nelkul), vagy ird ujra a szot. A TISZTIT=1 nem elso\n"
            "  valasz: az a kaput nem kapcsolja ki, de a dontest rad hagyja.\n")
        return 3
    sys.stdout.write(t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
