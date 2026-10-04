/**
 * WAF Bypass — UTF-16LE path encoding.
 *
 * Many WAFs inspect request paths for patterns (e.g. "/.env") only in
 * ASCII / UTF-8. Re-encoding the path bytes as UTF-16LE and then
 * percent-encoding every byte often slips past those inspections while
 * the underlying server (IIS, Nginx with certain configs) still resolves
 * the path correctly.
 *
 * Usage:
 *   encodePathUtf16le("/.env")   → "/%00.%00e%00n%00v%00" (collapsed)
 *   wafBypassVariants("/.env")   → ["/.env", "/%2F.%00e%00n%00v%00", ...]
 */
/**
 * Encode a URL path string using UTF-16LE, then percent-encode each byte.
 * The leading "/" is kept as-is so the URL remains structurally valid.
 *
 * Example: "/.env" → "/%00.%00e%00n%00v" (LE byte pairs per char)
 */
export declare function encodePathUtf16le(path: string): string;
/**
 * Returns a set of path variants to try for WAF bypass purposes.
 * Always starts with the original path (no overhead when not needed).
 *
 * Variants produced:
 *   1. Original path                            → "/.env"
 *   2. UTF-16LE percent-encoded                 → "/%2E%00e%00n%00v%00"
 *   3. Double URL-encoded dot prefix            → "/%252e.env"
 *   4. Null-byte suffix (some parsers stop)     → "/.env%00"
 */
export declare function wafBypassVariants(path: string): string[];
/**
 * Returns only the WAF-bypass variant (UTF-16LE encoded) for a path,
 * suitable for a targeted retry after a detected WAF block.
 */
export declare function utf16leBypassPath(path: string): string;
