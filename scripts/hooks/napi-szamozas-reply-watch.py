#!/usr/bin/env python3
"""PreToolUse watcher on the channel reply tool: the day's continuous item numbering (card 572dbd49).

Laci's rule (2026-09-23, 2026-09-24, restated 2026-10-11, Telegram 4012): in a message to him with
several items or a decision to make, the numbering starts at 1 on the day's first such message and
runs on until the end of the day; it does not start over per message, and an item keeps its number
all day. The counter lives in store/napi-szamozas.json (scripts/napi-szamozas.py uj/lista/zar).
The rule lived in CLAUDE.md and a skill, and a message that restarts at 1 still went out (measured
2026-09-30: items 54 and 55 are the only run that kept the numbers).

WHAT IT DOES. When the counter file is dated TODAY and its "kovetkezo" (next number) is above 1, and
the outgoing text has a numbered list that starts with 1 (a line "1." and a later line "2."), it
tells the model so, in the PreToolUse `additionalContext`. It WARNS and never blocks: no
permissionDecision is emitted, so the normal permission flow is untouched, and the message goes out
either way.

WHAT IT CANNOT KNOW (and the warning says so, because a warning that is wrong half the time gets
ignored): a list that restates TODAY'S items by their own numbers legitimately starts at 1 while item
1 is still open, and a list of steps is not a list of items. The text does not tell them apart from a
restart, so the warning names the counter's state and leaves the call to the sender.
It is silent when the file is missing, unreadable, from another day, or "kovetkezo" is 1 (the first
list of the day starts at 1, rightly).

NOT DONE. A single "1." line is not a list. Numbers behind other markers ("#1", "a)", "I.") are not
read. The text is never quoted back: additionalContext is injected as trusted framing text, and
echoing an outgoing message into it would put arbitrary text in the harness's own voice.

INSTRUMENT. Each warning appends one line (time, counter, numbers found; NO message text) to
store/napi-szamozas-figyelmeztetes.log, so how often it fires, and whether it fires at all, is
measurable without reading anyone's messages. A list from 1 sent while the counter file is not
today's (card 3669ee68) writes the same kind of line, "allapot-nem-mai datum=<the file's date>", and
no warning: that was the measured failure mode (nobody refreshed the counter today), and a watcher
that stays mute there cannot be told apart from one that saw nothing. A missing or unreadable
counter file writes nothing (there is no state to describe). The weekly check (Sam, card 548bb2a4) compares that
log with the Telegram replies.

CONTRACT. Exit 0 on every path, including a malformed payload. A guard that raises blocks the agent's
tool call; this one is only an aid. A failure is written to store/hook-errors.log and the hook stays
silent. Wiring (settings.json, PreToolUse, matcher mcp__plugin_telegram_telegram__reply) is the main
agent's step and is NOT part of this file.

Env (tests): NAPI_SZAMOZAS_STATE, NAPI_SZAMOZAS_TODAY (YYYY-MM-DD), NAPI_SZAMOZAS_LOG.
"""
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

INSTALL = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
STATE = os.environ.get("NAPI_SZAMOZAS_STATE") or os.path.join(INSTALL, "store", "napi-szamozas.json")
LOG = os.environ.get("NAPI_SZAMOZAS_LOG") or os.path.join(INSTALL, "store", "napi-szamozas-figyelmeztetes.log")

# "1." "1)" "(1)" "*1.*" "1\." (MarkdownV2 escapes the dot) "📌 1." "- 1." and the keycap "1️⃣".
_NUM_LINE = re.compile(
    r"^[ \t]*(?:[^\w\s]{0,6}[ \t]*)?\(?(\d{1,3})\\?[.)][^\w\s]{0,4}[ \t]+\S"
    r"|^[ \t]*(\d{1,3})️?⃣"
)


def numbered_items(text):
    """The numbers of the numbered lines, in order of appearance."""
    out = []
    for line in text.splitlines():
        m = _NUM_LINE.match(line)
        if m:
            out.append(int(m.group(1) or m.group(2)))
    return out


def starts_a_list_at_one(items):
    """A list that starts with 1: the first numbered line is 1 and a 2 follows somewhere after it."""
    return bool(items) and items[0] == 1 and 2 in items[1:]


def today():
    return os.environ.get("NAPI_SZAMOZAS_TODAY") or datetime.date.today().isoformat()


def load_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _log(fields, items):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write("%s %s szamok=%s\n" % (
                datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"), fields,
                ",".join(str(i) for i in items[:20])))
    except OSError:
        pass


def log_line(next_no, items):
    _log("kovetkezo=%s" % next_no, items)


def log_stale(state_date, items):
    """A list from 1 went out while the counter file is NOT today's (card 3669ee68). No warning: with no
    counter for today the list may well be the day's first. The line is the instrument: the failure mode
    that was measured (the counter not refreshed today) would otherwise leave the watcher mute and
    indistinguishable from "nothing happened". The file's date is data, so only a plain date is written."""
    d = state_date if isinstance(state_date, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", state_date) else "?"
    _log("allapot-nem-mai datum=%s" % d, items)


def warning(next_no, open_nums):
    opened = (" Nyitott tétel: %s." % ", ".join(str(n) for n in open_nums)) if open_nums else ""
    return (
        "NAPI SZÁMOZÁS FIGYELMEZTETÉS (nem blokkol, az üzenet kimegy): a mai számláló következő száma %d "
        "(kiosztva: 1 és %d között), de ennek az üzenetnek a számozott listája 1-gyel indul.%s "
        "Laci szabálya (2026-09-24, megerősítve 2026-10-11, Telegram 4012): a nap 1-től indul, a nap végéig "
        "nő, üzenetenként NEM kezdődik újra, és egy tétel száma a nap végéig nem változik. "
        "Ha ez ÚJ tételek listája, a számuk a számlálóból jön: python3 scripts/napi-szamozas.py uj \"<cím>\" "
        "(a következő szám %d). Ha a mai tételek újra-felsorolása a SAJÁT számukkal, vagy nem tétel-lista "
        "(lépések), akkor tévedés a figyelmeztetés, és változtatás nélkül küldhető."
        % (next_no, next_no - 1, opened, next_no)
    )


def main():
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return
    if not isinstance(payload, dict):
        return
    if not str(payload.get("tool_name") or "").endswith("__reply"):
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return
    text = tool_input.get("text")
    if not isinstance(text, str) or not text:
        return

    state = load_state()
    if state is None:
        return
    if state.get("datum") != today():
        items = numbered_items(text)
        if starts_a_list_at_one(items):
            log_stale(state.get("datum"), items)
        return
    next_no = state.get("kovetkezo")
    if not isinstance(next_no, int) or isinstance(next_no, bool) or next_no <= 1:
        return

    items = numbered_items(text)
    if not starts_a_list_at_one(items):
        return

    open_nums = []
    for t in state.get("tetelek") or []:
        if isinstance(t, dict) and t.get("nyitva") is True and isinstance(t.get("szam"), int):
            open_nums.append(t["szam"])
    log_line(next_no, items)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                              "additionalContext": warning(next_no, open_nums)}},
                     ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # a guard that raises blocks the tool call; this one is only an aid
        try:
            import hook_errlog
            hook_errlog.report("napi-szamozas-reply-watch", "unexpected failure", e)
        except Exception:
            pass
    sys.exit(0)
