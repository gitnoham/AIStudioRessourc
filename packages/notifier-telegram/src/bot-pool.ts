export function collectBotTokens(cfg: { botToken?: string; botTokens?: string[] }): string[] {
  const raw = [...(cfg.botTokens ?? [])];
  if (cfg.botToken) raw.unshift(cfg.botToken);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of raw) {
    const token = t.trim();
    if (!token) continue;
    if (seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}

export class TelegramBotPool {
  private cursor = 0;
  private readonly coolingUntil = new Map<string, number>();

  constructor(private readonly tokens: string[]) {}

  size(): number {
    return this.tokens.length;
  }

  indexOf(token: string): number {
    return this.tokens.indexOf(token);
  }

  markCooling(token: string, retryAfterSec: number): void {
    const ms = Math.max(1, retryAfterSec) * 1000;
    this.coolingUntil.set(token, Date.now() + ms);
  }

  nextReady(prefer?: string): string | null {
    if (!this.tokens.length) return null;
    const now = Date.now();
    const ready = this.tokens.filter((t) => now >= (this.coolingUntil.get(t) ?? 0));
    if (prefer && ready.includes(prefer)) return prefer;
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

export function parseRetryAfter(body: unknown, fallback = 1): number {
  const n = (body as { parameters?: { retry_after?: number } })?.parameters?.retry_after;
  return typeof n === "number" && n > 0 ? n : fallback;
}
