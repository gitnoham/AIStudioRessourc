import type { PatternMatch, RawHit } from "@scanner/core";
export declare function parseZohoAssignments(text: string): Record<string, string>;
export declare function collectZohoEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string>;
export declare function formatZohoBlock(env: Record<string, string>): string;
export declare function isUsableZoho(env: Record<string, string>): boolean;
export declare function zohoFingerprint(env: Record<string, string>): string;
export declare function zohoDcHosts(env: Record<string, string>): {
    accounts: string;
    api: string;
    dc: string;
}[];
