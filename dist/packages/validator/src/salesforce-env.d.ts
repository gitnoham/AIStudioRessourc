import type { PatternMatch, RawHit } from "@scanner/core";
export declare function canonicalSfKey(raw: string): string;
export declare function parseSalesforceAssignments(text: string): Record<string, string>;
export declare function collectSalesforceEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string>;
export declare function formatSalesforceBlock(env: Record<string, string>): string;
export declare function isUsableSalesforce(env: Record<string, string>): boolean;
export declare function salesforceFingerprint(env: Record<string, string>): string;
