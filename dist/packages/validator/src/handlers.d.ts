import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
export { AwsHandler } from "./aws-handler.js";
export { AzureHandler, ElasticEmailHandler, MailtrapHandler, MondayHandler, SalesforceHandler, ZohoHandler } from "./crm-handlers.js";
export declare class SendGridHandler implements ValidationHandler {
    private readonly http;
    readonly service = "sendgrid";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
    private senders;
}
export declare class StripeHandler implements ValidationHandler {
    private readonly http;
    readonly service = "stripe";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
    private permissions;
}
export declare class GitHubHandler implements ValidationHandler {
    private readonly http;
    readonly service = "github";
    constructor(http: IHttpClient);
    validate(hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
    private probe;
    private listRepos;
    private listReposRest;
    private listInstallRepos;
    private listReposGraphql;
    private viewer;
}
export declare class BrevoHandler implements ValidationHandler {
    private readonly http;
    readonly service = "brevo";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class MailgunHandler implements ValidationHandler {
    private readonly http;
    readonly service: string;
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class NewMailgunHandler extends MailgunHandler {
    readonly service = "newmailgun";
}
export declare class SmtpHandler implements ValidationHandler {
    private readonly authTimeoutMs;
    readonly service: string;
    constructor(service?: string, authTimeoutMs?: number);
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare class KlaviyoHandler implements ValidationHandler {
    private readonly http;
    readonly service = "klaviyo";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
    private collection;
}
export declare class MandrillHandler implements ValidationHandler {
    private readonly http;
    readonly service = "mandrill";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class PostmarkHandler implements ValidationHandler {
    private readonly http;
    readonly service = "postmark";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class SparkpostHandler implements ValidationHandler {
    private readonly http;
    readonly service = "sparkpost";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class ResendHandler implements ValidationHandler {
    private readonly http;
    readonly service = "resend";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class MailersendHandler implements ValidationHandler {
    private readonly http;
    readonly service = "mailersend";
    constructor(http: IHttpClient);
    validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult>;
}
export declare class HttpCheckHandler implements ValidationHandler {
    private readonly http;
    readonly service: string;
    private readonly spec;
    constructor(http: IHttpClient, service: string, spec: (key: string) => {
        url: string;
        headers?: Record<string, string>;
    } | null);
    validate(_hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export declare class RawHandler implements ValidationHandler {
    readonly service: string;
    constructor(service: string);
    validate(): Promise<ValidationResult>;
}
export declare function builtinHandlers(http: IHttpClient, smtpAuthMs?: number): ValidationHandler[];
