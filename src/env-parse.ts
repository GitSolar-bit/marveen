// The .env line grammar, zero-import so a small launcher helper
// (scripts/fleet-venv-prefix.mjs via dist/fleet-venv.js) can share it with
// env.ts without pulling the rest of the app in. Comments and blank lines are
// skipped, a trailing comment (" #" outside quotes) is cut, the value is trimmed,
// and ONE pair of matching surrounding quotes ("..." or '...') is stripped.
//
// The trailing-comment rule (card 6600f89b, HEX 3549): outside quotes a `#` that has a space or tab
// BEFORE it starts a comment, and the comment and the whitespace in front of it are dropped
// (`KEY=abc # note` -> `abc`, `KEY= # note` -> empty). A `#` without a space before it stays
// (`KEY=a#b`, `KEY=#abc`). A `#` inside quotes is not a comment, so `KEY="a #b"` keeps it; a quote that
// closes before the end ends the quoted part (`KEY="a" # see "docs"` is `a`); a quote that never closes
// switches the rule off for the rest of the value (`KEY=it's # x` stays whole). There are no escapes: a backslash does not protect a quote or a `#`
// (`KEY="a\"b" # c` keeps its comment). The same rule is copied, and pinned by a parity test, in the
// persona-change hook (scripts/hooks/persona-change-notify.py) and in the installer reader
// (scripts/install-prod-tree-guard-hook.sh). The shell readers that cut a value with `cut -d= -f2-`
// (auth.sh, host-restart-watchdog.sh, disk-space-guard.sh, channel-keepalive-probe.sh, ...) do NOT
// know it: they keep the comment as part of the value, so a value that carries one is read differently
// there. That is a named limit (docs/env-comment-grammar.md).
export function stripTrailingComment(raw: string): string {
  let q: string | null = null
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]
    if (q) { if (c === q) q = null; continue }
    if (c === '"' || c === "'") { q = c; continue }
    if (c === '#' && i > 0 && (raw[i - 1] === ' ' || raw[i - 1] === '\t')) return raw.slice(0, i)
  }
  return raw
}
export function parseEnvContent(content: string, keys?: string[]): Record<string, string> {
  const result: Record<string, string> = {}
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eqIdx = trimmed.indexOf('=')
    if (eqIdx === -1) continue
    const key = trimmed.slice(0, eqIdx).trim()
    let value = stripTrailingComment(trimmed.slice(eqIdx + 1)).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    if (keys && !keys.includes(key)) continue
    result[key] = value
  }
  return result
}
