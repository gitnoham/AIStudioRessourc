import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
export interface AwsPerm {
    service: string;
    action: string;
    ok: boolean;
    details: string;
}
export declare function formatAwsPermLines(perms: AwsPerm[]): string;
export declare class AwsHandler implements ValidationHandler {
    private readonly http;
    readonly service = "aws";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
    private identify;
    private probe;
    private ses;
    private other;
    private iam;
}
