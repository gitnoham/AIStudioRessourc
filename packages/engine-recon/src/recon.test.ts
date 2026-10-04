import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ReconModule } from "./index.js";
import { ContentAnalyzer } from "@scanner/content-analyzer";
import type { IConfigProvider, IHttpClient, RawHit, ScanContext } from "@scanner/core";

describe("ReconModule", () => {
  it("extracts secrets from __NEXT_DATA__", async () => {
    const html = `<script id="__NEXT_DATA__" type="application/json">{"key":"AKIAAAAAAAAAAAAAAAAA"}</script>`;
    const http: IHttpClient = {
      async get(url: string) {
        return { url, status: 404, headers: {}, body: Buffer.alloc(0), text: "" };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const config: IConfigProvider = {
      get: () => ({ modules: { recon: true } }) as never,
      patterns: () =>
        ({
          credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
          discovery: { scriptSrc: [], robotsDisallow: [], sitemapLoc: [] },
        }) as never,
      resolveBudget: () => 1000,
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new ReconModule({
      http,
      analyzer,
      config,
      dedup: { checkAndMark: () => true, reset() {} },
      logger: { info() {}, warn() {}, error() {} },
    });
    const hits: RawHit[] = [];
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      pageContent: html,
      signal: new AbortController().signal,
      emit() {},
    };
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.some((h) => h.source === "recon"), true);
  });

  it("re-scans robots Disallow paths and sitemap loc URLs", async () => {
    const secret = "AKIAAAAAAAAAAAAAAAAA";
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/robots.txt")) {
          const text = "User-agent: *\nDisallow: /backup.env\nAllow: /\nSitemap: https://t.test/sitemap.xml\n";
          return { url, status: 200, headers: {}, body: Buffer.from(text), text };
        }
        if (url.endsWith("/sitemap.xml")) {
          const text = `<?xml version="1.0"?><urlset><url><loc>https://t.test/secret.json</loc></url><url><loc>https://evil.test/skip.json</loc></url></urlset>`;
          return { url, status: 200, headers: {}, body: Buffer.from(text), text };
        }
        if (url.endsWith("/backup.env") || url.endsWith("/secret.json")) {
          return { url, status: 200, headers: {}, body: Buffer.from(secret), text: secret };
        }
        return { url, status: 404, headers: {}, body: Buffer.alloc(0), text: "" };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const config: IConfigProvider = {
      get: () => ({ modules: { recon: true } }) as never,
      patterns: () =>
        ({
          credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
          discovery: {
            scriptSrc: [],
            robotsDisallow: [{ source: "(?:Disallow|Allow):\\s*(\\S+)", flags: "gi" }],
            robotsSitemap: [{ source: "Sitemap:\\s*(\\S+)", flags: "gi" }],
            sitemapLoc: [{ source: "<loc>\\s*([^<]+)\\s*</loc>", flags: "gi" }],
          },
        }) as never,
      resolveBudget: () => 1000,
    };
    const analyzer = new ContentAnalyzer(config);
    const seen = new Set<string>();
    const mod = new ReconModule({
      http,
      analyzer,
      config,
      dedup: {
        checkAndMark: (_s, key) => {
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        },
        reset() {},
      },
      logger: { info() {}, warn() {}, error() {} },
    });
    const hits: RawHit[] = [];
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      pageContent: "<html><body>ok</body></html>",
      signal: new AbortController().signal,
      emit() {},
    };
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.filter((h) => h.payloadType === "guidance-rescan").length >= 1, true);
    assert.equal(
      hits.some((h) => h.matches.some((m) => m.value.startsWith("AKIA"))),
      true,
    );
  });
});
