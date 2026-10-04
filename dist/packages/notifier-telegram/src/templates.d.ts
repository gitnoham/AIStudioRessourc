import type { ScanStats, ValidatedHit } from "@scanner/core";
export declare function stamp(now?: Date): string;
export declare function formatHit(hit: ValidatedHit, n?: number, now?: Date): string;
export declare function formatStats(stats: ScanStats, now?: Date): string;
export declare function safeHtmlTruncate(msg: string, maxLen?: number): string;
