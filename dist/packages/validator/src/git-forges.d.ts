import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
export declare class GitLabHandler implements ValidationHandler {
    private readonly http;
    readonly service = "gitlab";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
    private probe;
}
export declare class BitbucketHandler implements ValidationHandler {
    private readonly http;
    readonly service = "bitbucket";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare class GitBucketHandler implements ValidationHandler {
    private readonly http;
    readonly service = "gitbucket";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
