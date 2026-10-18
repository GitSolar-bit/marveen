"""Shared "is this inbound a pure acknowledgement?" predicate for the Telegram
hooks (telegram-reply-guard.py, telegram_progress.py, telegram_progress_clear.py,
telegram_progress_reply_clear.py). ONE definition, imported by all of them, so
the guard and the placeholder cleanup can never disagree about what needs an
answer.

A pure acknowledgement ("ok", "koszi", a thumbs-up) owes no reply: the standing
rule is that a bare ack is answered, at most, with a reaction. An ack is
UNNUMBERED and has no question mark; see the notes above is_ack().
"""

# Pure acknowledgements that do NOT require a reply (standing rule #9). Kept
# deliberately conservative so a short real question is never swallowed. This
# list must NOT grow to cover decisions: "igen" / "mehet" answer a question the
# agent asked and are owed a substantive reply.
_ACK_WORDS = (
    "ok", "oke", "okk", "okés", "okes", "rendben", "rdb", "köszi", "koszi",
    "kösz", "kosz", "köszönöm", "koszonom", "thx", "thanks", "ty", "thank you",
    "szuper", "super", "remek", "tökéletes", "tokeletes", "jó", "jo", "oksa",
)
_EMOJI_ACK = ("👍", "🙏", "👌", "❤️", "👏", "🎉", "✅", "🆗", "+1")

# A NUMBERED short reply ("118 ok", "86. ok", "104: ok") is deliberately NOT an
# ack. The owner numbers every reply after the daily item numbering, and the same
# text answers two different things: "86. ok" was a bare acknowledgement one day
# and, on another, the DECISION that started an assignment (measured 2026-09-30).
# The text cannot tell them apart, so a number in front means a real reply is
# owed: the number is not stripped, and "118" is not in the word list.
#
# A question mark ANYWHERE means a question, never an ack ("jó?", "ok?", "118 jo?"):
# stripping the "?" as punctuation used to let those through as acks.
_QUESTION_MARKS = ("?", "\uff1f")  # ASCII and fullwidth


def is_ack(text):
    raw = (text or "").strip()
    if any(q in raw for q in _QUESTION_MARKS):
        return False
    if not raw:
        # An empty/attachment-only inbound (e.g. a bare photo) is not a question
        # this guard should block on; the agent handles media on its own terms.
        return True
    # Strip emoji-ack glyphs and punctuation, then require EVERY remaining word to
    # be an acknowledgement word. This catches "koszi", "ok koszi", a lone
    # thumbs-up, etc., while still treating "ok de miert?" (a real question) as
    # non-ack.
    t = raw.lower()
    for e in _EMOJI_ACK:
        t = t.replace(e, " ")
    for ch in ".!…,":
        t = t.replace(ch, " ")
    tokens = t.split()
    if not tokens:
        return True  # emoji-only acknowledgement
    return all(tok in _ACK_WORDS for tok in tokens)
