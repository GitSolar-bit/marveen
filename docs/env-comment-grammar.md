# Trailing comments in `.env` values

Card 6600f89b (HEX 3549). `KEY=abc # note` used to read as the value `abc # note`. The rule now:

- Outside quotes, a `#` that has a space or a tab **before** it starts a comment. The comment and the
  whitespace in front of it are dropped: `KEY=abc # note` is `abc`, `KEY= # note` is empty.
- A `#` without a space before it stays part of the value: `KEY=a#b`, `KEY=#abc`,
  `KEY=http://x/#frag`.
- A value quoted as a whole is untouched: `KEY="a #b"` is `a #b`. A quote that closes
  ends the quoted part, so a quoted value followed by a comment is `a`, also when the comment itself ends
  with the same quote (`KEY="a" # note`, `KEY="a" # see "docs"`).
- There are no escapes: a backslash does not protect a quote or a `#` (`KEY="a\"b" # c` keeps its comment,
  because the second quote closes the first). Do not rely on a quote inside a quoted value.
- A quote that never closes switches the rule off for that value (`KEY=it's # x` stays whole), and a
  `#` inside a quote in the middle of a value is not a comment (`KEY=a "b # c" d`).
- Whole-line comments (`# KEY=1`) are skipped as before.

## Where it applies

Three readers carry the rule and are pinned together by tests (`src/__tests__/env-comment-grammar.test.ts`,
`src/__tests__/persona-guard-env-parity.test.ts`):

| Reader | File |
|---|---|
| the product (TypeScript) | `src/env-parse.ts`, `stripTrailingComment` |
| the persona-change hook (Python) | `scripts/hooks/persona-change-notify.py`, `_strip_trailing_comment` |
| the installer's `SYSTEM_SENDER_IDS` reader (awk) | `scripts/install-prod-tree-guard-hook.sh` |

## Named limit: every other reader

Only the three readers above know the rule. EVERY other reader of a `.env` keeps the comment as part of the
value, and a `.env` line that carries a trailing comment is therefore read differently by the app and by them:

- the shell scripts that cut a value with `grep -E '^KEY=' .env | cut -d= -f2-` (for example `auth.sh`,
  `host-restart-watchdog.sh`, `disk-space-guard.sh`, `channel-keepalive-probe.sh`, `channel-watchdog.sh`,
  `watchdog.sh`, `doctor.sh`, `stop.sh`);
- the Python and Node readers with their own grammar, among them security hooks: `scripts/hooks/destructive-gate.py`
  and `scripts/hooks/ledger_lib.py` (`line.startswith('MAIN_AGENT_ID=')`), `scripts/hooks/egress-gate.mjs`
  (`/^WEB_PORT=(.*)$/m`), `scripts/email-send-gate.mjs` (`split('=').slice(1).join('=')`), and further
  `scripts/hooks/provenance-gate.py`, `email-approval-gate.py`, `scripts/lib/owner_chat.py`,
  `scripts/git-hooks/pre-push-sam-green.py` (named from a search, their grammar is not measured).

So `WEB_PORT=3420 # dashboard` or `MAIN_AGENT_ID=hex # main` reads as `3420` / `hex` in the app and as the
whole text with the comment in those scripts. **For every reader: if a value needs a comment, put the comment
on its own line above it.** Measured on the live install on 2026-10-13 (key names only, no values read):
14 keys, none has a `#`, so there is no live effect today.

## The writer (named limit)

`updateEnvFile` (`src/env.ts`) writes values UNQUOTED, because `channels.sh` does not strip quotes. A value
that contains a space followed by `#` is therefore cut when the app reads it back. Its only caller is the fleet
import (`src/web/fleet-transfer.ts`), which mirrors `MAIN_AGENT_ID`, `BOT_NAME`, `BRAND_NAME`, `OWNER_NAME` and
`CHANNEL_PROVIDER`. The id and the provider cannot contain a space; the three names are free text, so a
`BRAND_NAME` such as `Team #1` would come back as `Team`. Quoting it would fix the app and leak the quotes into
`channels.sh`, so the writer is left as it is and the case is named here instead. Nothing in the live install
has this shape.

Safe ways to write such a value by hand: no space (or tab) before the `#` (`BRAND_NAME=Team#1` is read whole
everywhere), or quote it yourself (`BRAND_NAME="Team #1"`, read whole by the app and the three readers above;
the shell readers keep the quotes).
