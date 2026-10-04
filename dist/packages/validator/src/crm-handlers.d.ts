import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
export declare class SalesforceHandler implements ValidationHandler {
    private readonly http;
    readonly service = "salesforce";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
    private ok;
    private userinfo;
    private soapLogin;
    private oauthClient;
    private identity;
    private orgMeta;
}
export declare class AzureHandler implements ValidationHandler {
    private readonly http;
    readonly service = "azure";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare class ZohoHandler implements ValidationHandler {
    private readonly http;
    readonly service = "zoho";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare class MondayHandler implements ValidationHandler {
    private readonly http;
    readonly service = "monday";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class MailtrapHandler implements ValidationHandler {
    private readonly http;
    readonly service = "mailtrap";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class ElasticEmailHandler implements ValidationHandler {
    private readonly http;
    readonly service = "elasticemail";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
