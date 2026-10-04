import { collectBotTokens, parseRetryAfter, TelegramBotPool } from "./bot-pool.js";
import { hitChannelId } from "./channel.js";
import { formatHit, formatStats, safeHtmlTruncate } from "./templates.js";
export class TelegramNotifier {
    config;
    logger;
    statsMessageId = null;
    statsBotToken = null;
    lastEdit = 0;
    updating = false;
    hitNo = 0;
    pool;
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.pool = new TelegramBotPool(collectBotTokens(this.cfg()));
    }
    async startScan(label) {
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
    async updateProgress(stats) {
        if (this.updating)
            return;
        const now = Date.now();
        if (now - this.lastEdit < 15_000)
            return;
        this.updating = true;
        this.lastEdit = now;
        try {
            await this.syncStats(formatStats(stats), false);
        }
        finally {
            this.updating = false;
        }
    }
    async sendHit(hit) {
        await this.send(hitChannelId(hit, this.cfg()), formatHit(hit, ++this.hitNo));
    }
    async sendFinalStats(stats) {
        await this.syncStats(formatStats({ ...stats, done: true }), true);
    }
    /** After the first SCAN EN COURS, only edit that message — never send a new one. */
    async syncStats(text, force) {
        const chat = this.cfg().statsChannelId;
        if (this.statsMessageId && this.statsBotToken) {
            await this.edit(chat, this.statsMessageId, text, this.statsBotToken);
            return;
        }
        if (!force && this.statsMessageId)
            return;
        const sent = await this.send(chat, text);
        this.statsMessageId = sent?.id ?? this.statsMessageId;
        this.statsBotToken = sent?.token ?? this.statsBotToken;
    }
    cfg() {
        return this.config.get().telegram;
    }
    async send(chatId, text) {
        if (!this.pool.size() || !chatId) {
            this.logger.warn("TELEGRAM", "missing botTokens/channel — skip send");
            return null;
        }
        const attempts = Math.max(3, this.pool.size() * 2);
        for (let i = 0; i < attempts; i++) {
            const token = this.pool.nextReady();
            if (!token)
                break;
            try {
                const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                        chat_id: chatId,
                        text: safeHtmlTruncate(text),
                        parse_mode: "HTML",
                        disable_web_page_preview: true,
                    }),
                });
                if (res.status === 429) {
                    const body = await res.json().catch(() => ({}));
                    const wait = parseRetryAfter(body, 1 + i);
                    this.pool.markCooling(token, wait);
                    this.logger.warn("TELEGRAM", `429 bot #${this.pool.indexOf(token) + 1} — rotate (${wait}s)`);
                    continue;
                }
                if (!res.ok) {
                    this.logger.warn("TELEGRAM", `send HTTP ${res.status} bot #${this.pool.indexOf(token) + 1}`);
                    continue;
                }
                const json = (await res.json());
                const id = json.result?.message_id;
                if (id == null)
                    return null;
                return { id, token };
            }
            catch (err) {
                this.logger.warn("TELEGRAM", `send failed ${err.message}`);
            }
        }
        return null;
    }
    async edit(chatId, messageId, text, token) {
        try {
            const res = await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
                method: "POST",
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
                const body = await res.json().catch(() => ({}));
                this.pool.markCooling(token, parseRetryAfter(body, 2));
                this.logger.warn("TELEGRAM", "edit 429 — keep same stats message");
                return false;
            }
            if (res.ok)
                return true;
            const body = (await res.json().catch(() => ({})));
            const desc = body.description ?? "";
            if (res.status === 400 && /not modified/i.test(desc))
                return true;
            this.logger.warn("TELEGRAM", `edit HTTP ${res.status} ${desc.slice(0, 80)}`);
            return false;
        }
        catch (err) {
            this.logger.warn("TELEGRAM", `edit failed ${err.message}`);
            return false;
        }
    }
}
export { formatHit, formatStats, safeHtmlTruncate };
export { collectBotTokens, TelegramBotPool } from "./bot-pool.js";
export { hitChannelId, isIaService } from "./channel.js";
