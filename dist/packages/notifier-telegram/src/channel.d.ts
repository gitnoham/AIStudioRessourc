import type { TelegramConfig, ValidatedHit } from "@scanner/core";
export declare function isIaService(service: string | undefined): boolean;
export declare function hitChannelId(hit: ValidatedHit, tg: TelegramConfig): string;
