import type { PatternMatch, RawHit } from "@scanner/core";
export declare function parseAzureAssignments(text: string): Record<string, string>;
export declare function collectAzureEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string>;
export declare function formatAzureBlock(env: Record<string, string>): string;
export declare function isUsableAzure(env: Record<string, string>): boolean;
export declare function azureFingerprint(env: Record<string, string>): string;
