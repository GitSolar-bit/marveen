#!/usr/bin/env python3
"""Test the daily-numbering reply watcher (scripts/hooks/napi-szamozas-reply-watch.py), card 572dbd49.

Drives the hook as a subprocess with its three env overrides (state file, "today", log), so the real
store/napi-szamozas.json and the real log are never touched. Run:
  python3 scripts/__tests__/napi-szamozas-reply-watch.test.py
Exit 0 = all pass; non-zero = a failure (message on stderr).

What this guards above all: the warning is WARN-ONLY (no permissionDecision, exit 0 on every
path, however broken the input), it fires on the shapes the Telegram reply text really takes
(plain, MarkdownV2-escaped, bold, keycap emoji), and it stays silent on the cases where a list
starting at 1 is right (first list of the day, a new day, a list that does not start at 1).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(os.path.dirname(HERE), "hooks", "napi-szamozas-reply-watch.py")
REPLY = "mcp__plugin_telegram_telegram__reply"
TODAY = "2026-10-11"

LIST_FROM_ONE = "Három tétel:\n1. Első\n2. Második\n3. Harmadik"


class Watch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "napi-szamozas.json")
        self.log = os.path.join(self.tmp.name, "sub", "figyelmeztetes.log")
        self.write_state(datum=TODAY, kovetkezo=4)

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, **d):
        d.setdefault("tetelek", [
            {"szam": 1, "cim": "a", "nyitva": False},
            {"szam": 2, "cim": "b", "nyitva": True},
            {"szam": 3, "cim": "c", "nyitva": True},
        ])
        with open(self.state, "w", encoding="utf-8") as fh:
            json.dump(d, fh)

    def run_hook(self, stdin, tool=REPLY, text=None, today=TODAY, raw=None):
        env = dict(os.environ, NAPI_SZAMOZAS_STATE=self.state, NAPI_SZAMOZAS_TODAY=today,
                   NAPI_SZAMOZAS_LOG=self.log, HOOK_ERRLOG_PATH=os.path.join(self.tmp.name, "hook-errors.log"))
        if raw is None:
            raw = json.dumps({"tool_name": tool, "tool_input": {"chat_id": "1", "text": stdin if text is None else text}})
        p = subprocess.run([sys.executable, HOOK], input=raw, capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, "the hook must exit 0 on every path: %s" % p.stderr)
        return p

    def warned(self, p):
        return bool(p.stdout.strip())

    # ---- fires -----------------------------------------------------------------------------

    def test_a_list_from_one_with_a_counter_above_one_warns(self):
        p = self.run_hook(LIST_FROM_ONE)
        self.assertTrue(self.warned(p), "should warn")
        out = json.loads(p.stdout)["hookSpecificOutput"]
        self.assertEqual(out["hookEventName"], "PreToolUse")
        ctx = out["additionalContext"]
        self.assertIn("következő száma 4", ctx)
        self.assertIn("Nyitott tétel: 2, 3", ctx)
        self.assertIn("napi-szamozas.py uj", ctx)

    def test_it_never_blocks_or_decides_permission(self):
        out = json.loads(self.run_hook(LIST_FROM_ONE).stdout)
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertNotIn("decision", out)
        self.assertNotIn("updatedInput", out["hookSpecificOutput"])

    def test_the_shapes_a_telegram_text_really_takes(self):
        shapes = {
            "paren": "(1) a\n(2) b",
            "bracket": "1) a\n2) b",
            "markdownv2 escaped dot": "1\\. a\n2\\. b",
            "bold": "*1\\.* a\n*2\\.* b",
            "emoji prefix": "📌 1. a\n📌 2. b",
            "dash prefix": "- 1. a\n- 2. b",
            "keycap": "1️⃣ a\n2️⃣ b",
            "indented": "  1. a\n  2. b",
            "with prose between": "Bevezető\n1. a\nmagyarázat\n2. b",
        }
        for name, text in shapes.items():
            self.assertTrue(self.warned(self.run_hook(text)), "should warn for: %s" % name)

    # ---- silent ----------------------------------------------------------------------------

    def test_the_first_list_of_the_day_is_right_to_start_at_one(self):
        self.write_state(datum=TODAY, kovetkezo=1, tetelek=[])
        self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE)))

    def test_a_state_file_from_another_day_is_silent(self):
        self.write_state(datum="2026-10-10", kovetkezo=9)
        self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE)))

    def read_log(self):
        try:
            with open(self.log, encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    # ---- card 3669ee68: the stale-state line --------------------------------------------------

    def test_a_list_from_one_with_yesterdays_counter_is_silent_but_logged(self):
        self.write_state(datum="2026-10-10", kovetkezo=9)
        p = self.run_hook(LIST_FROM_ONE)
        self.assertFalse(self.warned(p), "no warning: with no counter for today the list may be the day's first")
        logged = self.read_log()
        self.assertIn("allapot-nem-mai datum=2026-10-10 szamok=1,2,3", logged)
        self.assertEqual(len(logged.splitlines()), 1)

    def test_the_stale_line_never_carries_message_text_or_a_foreign_date_string(self):
        secret = "TITOKSZOVEG-77c1"
        self.write_state(datum="2026-10-10 %s" % secret, kovetkezo=9)
        self.run_hook("1. %s\n2. más" % secret)
        logged = self.read_log()
        self.assertNotIn(secret, logged)
        self.assertIn("allapot-nem-mai datum=?", logged)

    def test_the_stale_line_needs_a_list_from_one(self):
        self.write_state(datum="2026-10-10", kovetkezo=9)
        for text in ("Nincs lista", "4. Negyedik\n5. Ötödik", "Csak egy:\n1. Egyetlen"):
            self.run_hook(text)
        self.assertEqual(self.read_log(), "")

    def test_a_missing_or_broken_state_writes_no_stale_line(self):
        os.remove(self.state)
        self.run_hook(LIST_FROM_ONE)
        with open(self.state, "w") as fh:
            fh.write("not json")
        self.run_hook(LIST_FROM_ONE)
        self.assertEqual(self.read_log(), "")

    def test_todays_state_never_writes_the_stale_line(self):
        self.run_hook(LIST_FROM_ONE)  # warns
        self.write_state(datum=TODAY, kovetkezo=1, tetelek=[])
        self.run_hook(LIST_FROM_ONE)  # first list of the day, silent
        self.assertNotIn("allapot-nem-mai", self.read_log())

    def test_a_list_that_continues_the_numbering_is_silent(self):
        self.assertFalse(self.warned(self.run_hook("4. Negyedik\n5. Ötödik")))

    def test_a_single_one_is_not_a_list(self):
        self.assertFalse(self.warned(self.run_hook("Csak egy:\n1. Egyetlen")))

    def test_no_numbers_and_prose_with_digits_are_silent(self):
        for text in ("Szia, kész van.", "A 2026-10-11-i futás 1 hibát adott, 2 figyelmeztetést.",
                     "Verzió 1.2.3 és 2.0 között", "11. hónap 1. napja\n2. kerület"):
            self.assertFalse(self.warned(self.run_hook(text)), "should stay silent for: %r" % text)

    def test_the_wrong_tool_is_silent(self):
        self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE, tool="mcp__plugin_telegram_telegram__edit_message")))
        self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE, tool="Bash")))

    # ---- never raises ----------------------------------------------------------------------

    def test_a_broken_state_file_is_silent_not_an_error(self):
        for body in ("", "not json", "[]", '{"datum": 1}', '{"datum":"%s","kovetkezo":"4"}' % TODAY,
                     '{"datum":"%s","kovetkezo":true}' % TODAY):
            with open(self.state, "w") as fh:
                fh.write(body)
            self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE)), "state %r" % body)

    def test_a_missing_state_file_is_silent(self):
        os.remove(self.state)
        self.assertFalse(self.warned(self.run_hook(LIST_FROM_ONE)))

    def test_malformed_payloads_exit_zero_and_stay_silent(self):
        for raw in ("", "not json", "[]", "null", '{"tool_name": 5}', '{"tool_name":"%s"}' % REPLY,
                    '{"tool_name":"%s","tool_input":"x"}' % REPLY,
                    '{"tool_name":"%s","tool_input":{"text": 7}}' % REPLY,
                    '{"tool_name":"%s","tool_input":{"text": ""}}' % REPLY):
            self.assertFalse(self.warned(self.run_hook("", raw=raw)), "payload %r" % raw)

    # ---- hygiene ---------------------------------------------------------------------------

    def test_the_message_text_is_never_echoed_into_the_context_or_the_log(self):
        secret = "TITOKSZOVEG-9f3a"
        p = self.run_hook("1. %s\n2. más" % secret)
        self.assertTrue(self.warned(p))
        self.assertNotIn(secret, p.stdout)
        with open(self.log, encoding="utf-8") as fh:
            logged = fh.read()
        self.assertNotIn(secret, logged)
        self.assertIn("kovetkezo=4 szamok=1,2", logged)

    def test_a_silent_run_writes_no_log_line(self):
        self.run_hook("Nincs lista")
        self.assertFalse(os.path.exists(self.log))

    def test_an_unwritable_log_does_not_stop_the_warning(self):
        os.makedirs(self.log)  # a directory where the file should be
        self.assertTrue(self.warned(self.run_hook(LIST_FROM_ONE)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
