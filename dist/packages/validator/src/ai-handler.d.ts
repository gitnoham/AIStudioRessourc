import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
type AiSpec = {
    service: string;
    key: (raw: string, siblings: PatternMatch[]) => string | null;
    headers: (key: string, siblings: PatternMatch[]) => Record<string, string>;
    check: string;
    extras?: string[];
};
export declare class AiHandler implements ValidationHandler {
    private readonly http;
    private readonly spec;
    readonly service: string;
    constructor(http: IHttpClient, spec: AiSpec);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare function aiHandlers(http: IHttpClient): ValidationHandler[];
export {};
