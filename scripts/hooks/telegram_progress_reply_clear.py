#!/usr/bin/env python3
"""
PostToolUse hook — clears the "✍️ Dolgozom rajta…" placeholder as soon as the
agent actually SENDS a reply, instead of waiting for the turn to end (Stop).

Why: a single long turn can pull a bigger task forward and emit several replies
before it finishes. With Stop-only cleanup the placeholder visibly lingers for
the whole (possibly very long) turn even though the user already got an answer.
Clearing on the reply tool makes the placeholder disappear exactly when the
answer appears — matching the user's mental model.

Fires after the Telegram `reply` tool. Deletes any pending placeholder(s) for
the replied chat_id in this session. The Stop hook + watchdog remain as
backstops for turns that end without a reply, or true crashes.

It also fires after the Telegram `react` tool, but ONLY for an inbound that is a
pure acknowledgement ("ok", "118 ok"): a reaction is the whole answer to those
(the owner sees it under the message), so the placeholder goes away at once. A
reaction on a question or a decision is NOT an answer -- the entry stays and the
mandatory reply with it. The inbound is identified by the reacted message_id
against the entry's src_mid, and "ack" is the flag telegram_progress.py wrote.

Silent on stdout. Honors TELEGRAM_STATE_DIR (per-agent token) like the others.
"""
import sys, os, json, urllib.request


def state_dir():
    # #915: env override, then install-scoped once migrated, then legacy shared.
    d = os.environ.get("TELEGRAM_STATE_DIR")
    if d:
        return d
    _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _inst = os.path.join(_root, ".claude", "channels", "telegram")
    if os.path.isfile(os.path.join(_inst, ".env")):
        return _inst
    return os.path.expanduser("~/.claude/channels/telegram")


def token(sd):
    try:
        for line in open(os.path.join(sd, ".env"), encoding="utf-8"):
            line = line.strip()
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                return line.split("=", 1)[1].strip()
    except Exception:
        return None
    return None


def api(tok, method, payload):
    # Base is overridable (TELEGRAM_API_BASE) so tests can point it at a local
    # stub, like the sibling hooks; defaults to the real Bot API.
    base = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
    url = f"{base}/bot{tok}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read().decode())


def main():
    try:
        ev = json.loads(sys.stdin.read())
    except Exception:
        return
    tool = ev.get("tool_name") or ev.get("toolName") or ""
    is_reply = "telegram" in tool and "reply" in tool
    is_react = "telegram" in tool and tool.endswith("__react")
    if not (is_reply or is_react):
        return
    ti = ev.get("tool_input") or ev.get("toolInput") or {}
    chat_id = ti.get("chat_id")
    if chat_id is None:
        return
    react_target = str(ti.get("message_id")) if is_react and ti.get("message_id") is not None else None
    if is_react and react_target is None:
        return
    chat_id = str(chat_id)
    sid = ev.get("session_id") or "default"
    sd = state_dir()
    path = os.path.join(sd, "progress", f"{sid}.json")
    try:
        pend = json.load(open(path))
    except Exception:
        return
    keep, drop = [], []
    for p in pend:
        if is_react:
            # Only a reaction on the very message an ACK-type entry was opened
            # for is an answer. Everything else keeps its placeholder.
            hit = (str(p.get("chat_id")) == chat_id
                   and p.get("ack") is True
                   and str(p.get("src_mid")) == react_target)
        else:
            hit = str(p.get("chat_id")) == chat_id
        (drop if hit else keep).append(p)
    if not drop:
        return
    tok = token(sd)
    if tok:
        for p in drop:
            try:
                api(tok, "deleteMessage", {"chat_id": p["chat_id"], "message_id": p["message_id"]})
            except Exception:
                pass
    try:
        if keep:
            json.dump(keep, open(path, "w"))
        else:
            os.remove(path)
    except Exception:
        pass


if __name__ == "__main__":
    main()
