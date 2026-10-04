export function collectBotTokens(cfg) {
    const raw = [...(cfg.botTokens ?? [])];
    if (cfg.botToken)
        raw.unshift(cfg.botToken);
    const seen = new Set();
    const out = [];
    for (const t of raw) {
        const token = t.trim();
        if (!token)
            continue;
        if (seen.has(token))
            continue;
        seen.add(token);
        out.push(token);
    }
    return out;
}
export class TelegramBotPool {
    tokens;
    cursor = 0;
    coolingUntil = new Map();
    constructor(tokens) {
        this.tokens = tokens;
    }
    size() {
        return this.tokens.length;
    }
    indexOf(token) {
        return this.tokens.indexOf(token);
    }
    markCooling(token, retryAfterSec) {
        const ms = Math.max(1, retryAfterSec) * 1000;
        this.coolingUntil.set(token, Date.now() + ms);
    }
    nextReady(prefer) {
        if (!this.tokens.length)
            return null;
        const now = Date.now();
        const ready = this.tokens.filter((t) => now >= (this.coolingUntil.get(t) ?? 0));
        if (prefer && ready.includes(prefer))
            return prefer;
        if (!ready.length) {
            const t = this.tokens[this.cursor % this.tokens.length];
            this.cursor++;
            return t;
        }
        const t = ready[this.cursor % ready.length];
        this.cursor++;
        return t;
    }
}
export function parseRetryAfter(body, fallback = 1) {
    const n = body?.parameters?.retry_after;
    return typeof n === "number" && n > 0 ? n : fallback;
}
