import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from "node:zlib";

function looksPlainText(buf: Buffer): boolean {
  if (!buf.length) return true;
  const c = buf[0];
  return c === 0x7b || c === 0x5b || c === 0x3c || c === 0x22 || (c >= 0x20 && c < 0x7f && c !== 0x1f);
}

export function decodeHttpBody(body: Buffer, contentEncoding?: string): string {
  if (!body.length) return "";
  const hint = (contentEncoding ?? "").toLowerCase();
  const gzipMagic = body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b;
  if (gzipMagic || hint.includes("gzip")) {
    try {
      return gunzipSync(body).toString("utf8");
    } catch {
      if (looksPlainText(body)) return body.toString("utf8");
    }
  }
  if (hint.includes("br") || hint.includes("brotli")) {
    try {
      return brotliDecompressSync(body).toString("utf8");
    } catch {
      /* fall through */
    }
  }
  if (hint.includes("deflate")) {
    try {
      return inflateSync(body).toString("utf8");
    } catch {
      try {
        return inflateRawSync(body).toString("utf8");
      } catch {
        /* fall through */
      }
    }
  }
  return body.toString("utf8");
}
