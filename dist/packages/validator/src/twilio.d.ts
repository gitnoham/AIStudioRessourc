import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
export interface TwilioCreds {
    sid: string;
    token: string;
    apiKey: string;
    encoded: string;
}
export declare function collectTwilioCreds(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): TwilioCreds;
export declare function looksLikeTwilio(hit: RawHit, match: PatternMatch, creds: TwilioCreds): boolean;
export declare class TwilioHandler implements ValidationHandler {
    private readonly http;
    readonly service = "twilio";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
    private balanceAndNumbers;
}
