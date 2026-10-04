import type { IConfigProvider, IHttpClient, ILogger, INotifier, ScanStats, ValidatedHit } from "@scanner/core";
import { collectBotTokens, parseRetryAfter, TelegramBotPool } from "./bot-pool.js";
import { hitChannelId } from "./channel.js";
import { formatHit, formatStats, safeHtmlTruncate } from "./templates.js";

const API = "https://api.telegram.org";
const MIN_EDIT_MS = 15_000;
const MAX_BACKOFF_MS = 300_000;

export class TelegramNotifier implements INotifier {
  private statsMessageId: number | null = null;
  private statsBotToken: string | null = null;
  private lastEdit = 0;
  private updating = false;
  private hitNo = 0;
  private pool: TelegramBotPool;
  /** Échecs réseau consécutifs — backoff exponentiel pour arrêter le spam de logs. */
  private fails = 0;
  private retryAt = 0;

  constructor(
    private readonly config: IConfigProvider,
    private readonly logger: ILogger,
    private readonly http: IHttpClient,
  ) {
    this.pool = new TelegramBotPool(collectBotTokens(this.cfg()));
  }

  async startScan(label: string): Promise<void> {
    this.hitNo = 0;
    this.lastEdit = 0;
    this.statsMessageId = null;
    this.statsBotToken = null;
    this.pool = new TelegramBotPool(collectBotTokens(this.cfg()));
    const text = formatStats({
      fileName: label,
      urlsProcessed: 0,
      hitsValid: 0,
      hitsInvalid: 0,
      hitsRaw: 0,
      byService: {},
      cpm: 0,
      startedAt: Date.now(),
    });
    const sent = await this.send(this.cfg().statsChannelId, text);
    this.statsMessageId = sent?.id ?? null;
    this.statsBotToken = sent?.token ?? null;
  }

  async updateProgress(stats: ScanStats): Promise<void> {
    if (this.updating || this.down()) return;
    const now = Date.now();
    if (now - this.lastEdit < MIN_EDIT_MS) return;
    this.updating = true;
    this.lastEdit = now;
    try {
      await this.syncStats(formatStats(stats), false);
    } finally {
      this.updating = false;
    }
  }

  async sendHit(hit: ValidatedHit): Promise<void> {
    await this.send(hitChannelId(hit, this.cfg()), formatHit(hit, ++this.hitNo));
  }

  async sendFinalStats(stats: ScanStats): Promise<void> {
    await this.syncStats(formatStats({ ...stats, done: true }), true);
  }

  /** Après le premier SCAN EN COURS, on édite ce message — on n'en renvoie un que s'il a disparu. */
  private async syncStats(text: string, force: boolean): Promise<void> {
    const chat = this.cfg().statsChannelId;
    if (this.statsMessageId && this.statsBotToken) {
      const r = await this.edit(chat, this.statsMessageId, text, this.statsBotToken);
      if (r === "ok") return;
      if (r === "gone") {
        // Message supprimé / introuvable côté Telegram → on en renvoie un neuf.
        this.statsMessageId = null;
        this.statsBotToken = null;
      } else if (!force) {
        return; // échec réseau → le backoff (retryAt) espacera la prochaine tentative
      }
    }
    const sent = await this.send(chat, text);
    this.statsMessageId = sent?.id ?? this.statsMessageId;
    this.statsBotToken = sent?.token ?? this.statsBotToken;
  }

  private cfg() {
    return this.config.get().telegram;
  }

  /** Vrai tant qu'on est en backoff après des échecs réseau consécutifs. */
  private down(): boolean {
    return Date.now() < this.retryAt;
  }

  private markDown(err: unknown): void {
    this.fails++;
    const wait = Math.min(MAX_BACKOFF_MS, MIN_EDIT_MS * 2 ** Math.min(this.fails, 5));
    this.retryAt = Date.now() + wait;
    this.logger.warn("TELEGRAM", `${this.errText(err)} — retry dans ${Math.round(wait / 1000)}s`);
  }

  private markUp(): void {
    this.fails = 0;
    this.retryAt = 0;
  }

  /** "fetch failed" masque la vraie cause (DNS/refus/TLS) — on la remonte. */
  private errText(err: unknown): string {
    const e = err as Error & { cause?: { code?: string; errno?: string; message?: string } };
    const parts = [e.cause?.code, e.cause?.errno, e.cause?.message, e.message]
      .filter((x): x is string => !!x && x !== "fetch failed");
    return parts.join(" | ") || "request failed";
  }

  private parseJson(text: string): Record<string, unknown> {
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  private async send(chatId: string, text: string): Promise<{ id: number; token: string } | null> {
    if (!this.pool.size() || !chatId) {
      this.logger.warn("TELEGRAM", "missing botTokens/channel — skip send");
      return null;
    }
    if (this.down()) return null;
    const attempts = Math.max(3, this.pool.size() * 2);
    for (let i = 0; i < attempts; i++) {
      const token = this.pool.nextReady();
      if (!token) break;
      try {
        const res = await this.http.post(`${API}/bot${token}/sendMessage`, {
          budget: "httpRequest",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: safeHtmlTruncate(text),
            parse_mode: "HTML",
            disable_web_page_preview: true,
          }),
        });
        if (res.status === 429) {
          const wait = parseRetryAfter(this.parseJson(res.text), 1 + i);
          this.pool.markCooling(token, wait);
          this.markUp(); // le réseau répond : on annule le backoff d'échecs réseau
          this.logger.warn("TELEGRAM", `429 bot #${this.pool.indexOf(token) + 1} — rotate (${wait}s)`);
          continue;
        }
        if (res.status < 200 || res.status >= 300) {
          this.logger.warn("TELEGRAM", `send HTTP ${res.status} bot #${this.pool.indexOf(token) + 1}`);
          continue;
        }
        const json = this.parseJson(res.text) as { result?: { message_id?: number } };
        const id = json.result?.message_id;
        this.markUp();
        if (id == null) return null;
        return { id, token };
      } catch (err) {
        // Erreur réseau : tous les bots passent par le même chemin → inutile de
        // retenter 6×. On marque le backoff et on sort.
        this.markDown(err);
        break;
      }
    }
    return null;
  }

  private async edit(chatId: string, messageId: number, text: string, token: string): Promise<"ok" | "retry" | "gone"> {
    try {
      const res = await this.http.post(`${API}/bot${token}/editMessageText`, {
        budget: "httpRequest",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          message_id: messageId,
          text: safeHtmlTruncate(text),
          parse_mode: "HTML",
          disable_web_page_preview: true,
        }),
      });
      if (res.status === 429) {
        this.pool.markCooling(token, parseRetryAfter(this.parseJson(res.text), 2));
        this.markUp(); // le réseau répond : on annule le backoff d'échecs réseau
        this.logger.warn("TELEGRAM", "edit 429 — keep same stats message");
        return "retry";
      }
      if (res.status >= 200 && res.status < 300) {
        this.markUp();
        return "ok";
      }
      const desc = (this.parseJson(res.text) as { description?: string }).description ?? "";
      if (res.status === 400 && /not modified/i.test(desc)) {
        this.markUp();
        return "ok";
      }
      if (res.status === 400 && /message to edit not found|message can't be edited|message is not modified/i.test(desc)) {
        this.logger.warn("TELEGRAM", "stats message introuvable — re-send");
        return "gone";
      }
      this.logger.warn("TELEGRAM", `edit HTTP ${res.status} ${desc.slice(0, 80)}`);
      return "retry";
    } catch (err) {
      this.markDown(err);
      return "retry";
    }
  }
}

export { formatHit, formatStats, safeHtmlTruncate };
export { collectBotTokens, TelegramBotPool } from "./bot-pool.js";
export { hitChannelId, isIaService } from "./channel.js";
