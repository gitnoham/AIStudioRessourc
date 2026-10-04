import type { PatternMatch, RawHit } from "@scanner/core";
export declare function isFullSendGridKey(value: string): boolean;
export declare function canonicalMailKey(raw: string): string;
export declare function parseMailAssignments(text: string): Record<string, string>;
export declare function collectMailEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string>;
export declare function formatMailBlock(env: Record<string, string>): string;
/** Same mailbox: host + username, password ignored (rotated .env.save vs .save.1). */
export declare function smtpAccountKey(env: Record<string, string>): string;
/** Hold AUTH-fail until sibling dumps AUTH, then skip if that mailbox is already valid. */
export declare function shouldHoldSmtpInvalid(opts: {
    alreadyValid: boolean;
    alreadyNotifiedAccount: boolean;
    otherPending: number;
    alreadyDeferred: boolean;
}): "skip" | "defer" | "emit";
export type SmtpApiRoute = "sendgrid" | "mailgun" | "brevo" | null;
export declare function smtpApiRoute(env: Record<string, string>): SmtpApiRoute;
export declare function smtpBrand(host: string): string;
export declare function isTutorialSmtpHit(hit: RawHit): boolean;
export declare function isUsableSmtp(env: Record<string, string>): boolean;
export declare function isStripeSecret(v: string): boolean;
export declare function credentialFingerprints(hit: RawHit): string[];
