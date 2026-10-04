export declare function normalizeScanUrl(line: string): string | null;
export declare function originOf(url: string): string;
/** https://host[:port]/path → http://host/path (default port 80). Handshake-fail fallback, not HTTP-on-443. */
export declare function httpsToHttpDefaultPort(url: string): string;
/** https://host[:port]/path → http://host:port/path (keeps 443 so we do not fall back to :80). */
export declare function httpsToHttpSamePort(url: string): string;
export declare function homepageVariants(url: string): string[];
export declare function resolveUrl(base: string, ref: string): string | null;
export declare function sameHost(a: string, b: string): boolean;
export declare function scanIdentity(rawUrl: string, baseUrl: string): string;
