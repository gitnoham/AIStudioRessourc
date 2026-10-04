export declare function collectBotTokens(cfg: {
    botToken?: string;
    botTokens?: string[];
}): string[];
export declare class TelegramBotPool {
    private readonly tokens;
    private cursor;
    private readonly coolingUntil;
    constructor(tokens: string[]);
    size(): number;
    indexOf(token: string): number;
    markCooling(token: string, retryAfterSec: number): void;
    nextReady(prefer?: string): string | null;
}
export declare function parseRetryAfter(body: unknown, fallback?: number): number;
