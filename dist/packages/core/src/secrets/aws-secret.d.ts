/** AWS secret must be 40-char base64 — not reCAPTCHA / Stripe / encoded jokes. */
export declare function isValidAwsSecretKey(s: string): boolean;
export declare function isAwsAccessKey(s: string): boolean;
export declare function isVendorSecretPath(path: string | undefined): boolean;
