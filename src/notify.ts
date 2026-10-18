import { CHANNEL_PROVIDER, CHANNEL_TOKEN, CHANNEL_CHAT_ID, ALERT_CHAT_ID } from './config.js'
import { normalizeChatId, resolveAlertOwnerChat } from './owner-chat.js'
import { getProvider } from './channel-provider.js'
import { logger } from './logger.js'
import { markIfTestRun } from './test-run-marker.js'
import type { sendSlackNotification as SendSlack } from './slack-notify.js'

// SLACKATALLAS1006: the Slack side of this funnel. 'owner' = owner-facing
// content, 'alert' = operational alerts (falls back to the owner target).
// Read per send, so a Settings change applies without a restart. Loaded
// lazily: this module is imported almost everywhere, and a load failure of
// the settings layer must degrade to "no Slack target" (the Telegram path),
// never take every notification down with it.
type SettingFn = (key: string) => string
async function loadSetting(): Promise<SettingFn> {
  try {
    const { getEffectiveSettingValue } = await import('./settings-store.js')
    return (key) => { try { return String(getEffectiveSettingValue(key) ?? '').trim() } catch { return '' } }
  } catch {
    return () => ''
  }
}
export async function slackTargetFor(kind: 'owner' | 'alert', setting?: SettingFn): Promise<string> {
  const get = setting ?? await loadSetting()
  const owner = get('NOTIFY_SLACK_TARGET')
  return kind === 'alert' ? (get('NOTIFY_SLACK_ALERT_TARGET') || owner) : owner
}

/**
 * Slack first (when a target is set), then Telegram unless NOTIFY_TELEGRAM=0.
 * A failed Slack send falls back to Telegram, so nothing is lost while the
 * Slack path is new -- unless NOTIFY_TELEGRAM_FALLBACK=0: then Telegram never
 * gets the message, and the miss is an error line instead (an owner who moved
 * to Slack does not want alerts on the channel they left). Exported for tests.
 */
export async function deliverWithSlack(
  kind: 'owner' | 'alert',
  text: string,
  telegram: () => Promise<void>,
  send?: typeof SendSlack,
): Promise<void> {
  const setting = await loadSetting()
  const noFallback = setting('NOTIFY_TELEGRAM_FALLBACK') === '0'
  const target = await slackTargetFor(kind, setting)
  if (!target) {
    if (noFallback) {
      logger.error({ kind }, 'Ertesites ELVESZETT: nincs Slack-cel, a Telegram-tartalek ki van kapcsolva (NOTIFY_TELEGRAM_FALLBACK=0)')
      return
    }
    return telegram()
  }
  let sendFn: typeof SendSlack
  try {
    sendFn = send ?? (await import('./slack-notify.js')).sendSlackNotification
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    // A half-finished build must not cost the notification: Telegram instead,
    // unless the owner switched the Telegram fallback off.
    if (noFallback) {
      logger.error({ err: msg }, 'Ertesites ELVESZETT: a Slack modul nem toltheto be, a Telegram-tartalek ki van kapcsolva (NOTIFY_TELEGRAM_FALLBACK=0)')
      return
    }
    logger.warn({ err: msg }, 'Slack modul nem toltheto be; Telegram tartalek')
    return telegram()
  }
  const r = await sendFn(target, markIfTestRun(text), { ownerUserId: setting('SLACK_OWNER_USER_ID') })
  if (!r.ok && noFallback) {
    logger.error({ target, error: r.error }, 'Ertesites ELVESZETT: a Slack-kuldes bukott, a Telegram-tartalek ki van kapcsolva (NOTIFY_TELEGRAM_FALLBACK=0)')
    return
  }
  if (!r.ok) logger.warn({ target, error: r.error }, 'Slack ertesites nem ment ki; Telegram tartalek')
  if (r.ok) logger.info({ target, kind }, 'Slack ertesites elkuldve')
  if (!r.ok || setting('NOTIFY_TELEGRAM') !== '0') await telegram()
}

// True when operational alerts go to a chat other than the owner's. Callers
// must then leave owner/partner conversation content (e.g. a preview of a
// parked input line) out of the alert text.
export function alertIsRedirected(): boolean {
  return normalizeChatId(ALERT_CHAT_ID) !== null
}

// Operational alert (watchdogs, restarts, stuck sessions). Goes to
// ALERT_CHAT_ID when it is set, otherwise to the owner chat.
export async function notifyChannel(text: string): Promise<void> {
  return deliverWithSlack('alert', text, () => {
    const alertChat = normalizeChatId(ALERT_CHAT_ID)
    // an operational alert: its first words may go to the log (which alert was lost or sent)
    if (alertChat) return sendToChat(alertChat, text, true)
    return telegramOwner(text, true)
  })
}

// Card 3ed09d25 (71263d15): a message with no resolvable owner chat is not dropped in
// silence. The log line fires every time; the main agent's inbox hears about it once
// per window, through a sink the dashboard registers at start. notify.ts does not
// reach into the database itself: processes that never open it import this module
// too, and there the log line is the signal. Which chat counts as the owner is the
// alert rule below (resolveAlertOwnerChat); this only makes its refusal heard.
type OwnerChatMissingSink = (text: string) => void
let ownerChatMissingSink: OwnerChatMissingSink | null = null
let lastOwnerChatMissingSignalAt = 0
const OWNER_CHAT_MISSING_SIGNAL_MS = 60 * 60 * 1000

export function setOwnerChatMissingSink(sink: OwnerChatMissingSink | null): void {
  ownerChatMissingSink = sink
  lastOwnerChatMissingSignalAt = 0
}

function signalOwnerChatMissing(text: string, reason: string): void {
  const now = Date.now()
  if (!ownerChatMissingSink || now - lastOwnerChatMissingSignalAt < OWNER_CHAT_MISSING_SIGNAL_MS) return
  lastOwnerChatMissingSignalAt = now
  const preview = text.length > 200 ? `${text.slice(0, 200)} [... +${text.length - 200} karakter]` : text
  try {
    ownerChatMissingSink(
      `[notify-undelivered] Egy riasztás nem ment ki: a tulajdonosi chat nem oldható fel (${reason}). ` +
      'Óránként legfeljebb egy ilyen jelzés jön, a többi csak a naplóba kerül. ' +
      `A kihagyott riasztás eleje: ${preview}`,
    )
  } catch (err) {
    logger.warn({ err }, 'owner-chat-missing signal could not be delivered')
  }
}

// Owner-facing content (heartbeat digest, security events): always the owner
// chat, never rerouted by ALERT_CHAT_ID.
export async function notifyOwner(text: string): Promise<void> {
  return deliverWithSlack('owner', text, () => telegramOwner(text))
}

async function telegramOwner(text: string, logPreview = false): Promise<void> {
  // CHATID0 -- resolveAlertOwnerChat, not a truthiness test on the raw .env
  // value. The installer writes ALLOWED_CHAT_ID=0 as its placeholder, and "0"
  // is neither empty nor falsy, so a plain truthiness/normalizeChatId-only
  // guard used to PASS on exactly the installs that had no owner chat: the
  // send went out with chat_id=0, the Bot API answered 400, and the two
  // nested catches below discarded it. Result on such an install: every alert
  // in the fleet is silently dropped, and the "kihagyva" warning that exists
  // to say so never fired.
  //
  // The access.json fallback here is the ALERT rule, not the digest one: only
  // a single paired DM entry counts as the owner, never a group or channel,
  // and with several entries the alert is not sent (a guess would reach a
  // stranger). The reason is logged, so a skipped alert is visible.
  const owner = resolveAlertOwnerChat(undefined, CHANNEL_CHAT_ID, CHANNEL_PROVIDER)
  if (!CHANNEL_TOKEN || !owner.chatId) {
    const reason = !CHANNEL_TOKEN ? 'nincs token' : `nincs tulajdonos-chat (${owner.reason})`
    logger.warn(`Channel ertesites kihagyva: ${reason}`)
    // No token means no channel on this install: the log line is enough. A token
    // with no owner chat is the 2026-09-16 shape, and that one must reach someone.
    if (CHANNEL_TOKEN) signalOwnerChatMissing(text, owner.reason ?? 'ismeretlen ok')
    return
  }
  return sendToChat(owner.chatId, text, logPreview)
}

// What may reach the log from a message or an error (Sam 3550): a bot-token shape (no leading word boundary: the
// provider's own URL carries it as `bot<digits>:<secret>`) and any long run of digits
// (a chat id, a user id) are masked, and so are the configured token and chat id themselves. A provider's
// error text is not under our control, and an alert's words are not either.
export function scrubForLog(text: string, chatId: string): string {
  let t = String(text)
  for (const secret of [CHANNEL_TOKEN, chatId]) {
    if (secret && secret.length >= 4) t = t.split(secret).join('<redacted>')
  }
  return t.replace(/\d{6,}:[A-Za-z0-9_-]{20,}/g, '<token>').replace(/\d{7,}/g, '<id>')
}

async function sendToChat(chatId: string, text: string, logPreview = false): Promise<void> {
  if (!CHANNEL_TOKEN) {
    logger.warn('Channel ertesites kihagyva: nincs token')
    return
  }

  // Marked here at the funnel, NOT at call sites -- a new caller must not be
  // able to leak an unmarked message from a test run.
  const outbound = markIfTestRun(text)
  const provider = getProvider(CHANNEL_PROVIDER)
  const formatted = provider.formatMessage(outbound)
  const chunks = provider.splitMessage(formatted)

  // ALERTVAK923 (card c1445b93): the outcome is logged, success and failure alike. Until now a chunk that
  // failed twice was dropped without a trace, and a delivered alert left none either, so "did it go out?"
  // could only be answered by the owner's eyes. One line per send, never the text itself beyond a short
  // preview, never the chat id or the token.
  let failed = 0
  let plainFallback = 0
  let lastErr = ''
  for (const chunk of chunks) {
    try {
      const parseMode = CHANNEL_PROVIDER === 'telegram' ? 'HTML' : undefined
      await provider.sendMessage(CHANNEL_TOKEN, chatId, chunk, parseMode)
    } catch {
      try {
        await provider.sendMessage(CHANNEL_TOKEN, chatId, outbound.slice(0, 4096))
        plainFallback++
      } catch (err) {
        failed++
        lastErr = err instanceof Error ? err.message : String(err)
      }
    }
  }
  // The first words of an OPERATIONAL alert say which alert it was; owner-facing content (heartbeat summaries,
  // security events) gets no preview at all, the dashboard.log is read by the whole fleet.
  // scrub FIRST, cut after (Sam 3566): a token that straddles the 80th character would otherwise lose its tail to the cut
  // and keep a head the masking no longer recognises
  const preview = logPreview ? scrubForLog(outbound.replace(/\s+/g, ' '), chatId).slice(0, 80) : undefined
  if (failed > 0) {
    logger.error({ provider: CHANNEL_PROVIDER, chunks: chunks.length, failed, err: scrubForLog(lastErr, chatId), preview }, 'Ertesites ELVESZETT: a csatorna-kuldes bukott mindket probara')
  } else if (plainFallback > 0 && chunks.length > 1) {
    // The plain-text fallback re-sends the HEAD of the whole message (outbound.slice(0, 4096)), not the chunk that
    // failed, so with several chunks the tail of the message is not known to have gone out (Sam 3550).
    logger.warn({ provider: CHANNEL_PROVIDER, chunks: chunks.length, plainFallback, preview }, 'Channel ertesites RESZBEN ment ki: egy darab csak sima szovegre esessel, a bukott darab farka nem biztos, hogy kiment')
  } else {
    logger.info({ provider: CHANNEL_PROVIDER, chunks: chunks.length, plainFallback, preview }, 'Channel ertesites elkuldve')
  }
}

// Backward-compatible alias
export const notifyTelegram = notifyChannel

// Security-event notification (break-glass password reset, security:reset).
// Unlike notifyChannel, a missing channel config is an EXPECTED state here
// (fresh installs, channel-less deployments), so it stays fully silent -- the
// recovery path must never depend on, or be noisy about, Telegram being wired.
export async function notifySecurityEvent(text: string): Promise<void> {
  // Silent when NEITHER channel is configured; a Slack-only install still gets it.
  const hasTelegram = !!CHANNEL_TOKEN && !!resolveAlertOwnerChat(undefined, CHANNEL_CHAT_ID, CHANNEL_PROVIDER).chatId
  if (!hasTelegram && !(await slackTargetFor('owner'))) return
  try {
    await notifyOwner(text)
  } catch {
    /* never let a notification failure break the recovery action itself */
  }
}
