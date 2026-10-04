import type { IConfigProvider, ILogger, INotifier, ScanStats, ValidatedHit } from "@scanner/core";
import { formatHit, formatStats, safeHtmlTruncate } from "./templates.js";
export declare class TelegramNotifier implements INotifier {
    private readonly config;
    private readonly logger;
    private statsMessageId;
    private statsBotToken;
    private lastEdit;
    private updating;
    private hitNo;
    private pool;
    constructor(config: IConfigProvider, logger: ILogger);
    startScan(label: string): Promise<void>;
    updateProgress(stats: ScanStats): Promise<void>;
    sendHit(hit: ValidatedHit): Promise<void>;
    sendFinalStats(stats: ScanStats): Promise<void>;
    /** After the first SCAN EN COURS, only edit that message — never send a new one. */
    private syncStats;
    private cfg;
    private send;
    private edit;
}
export { formatHit, formatStats, safeHtmlTruncate };
export { collectBotTokens, TelegramBotPool } from "./bot-pool.js";
export { hitChannelId, isIaService } from "./channel.js";
