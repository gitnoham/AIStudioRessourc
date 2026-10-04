import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PathsModule } from "./index.js";
import type { IConfigProvider, IHttpClient, RawHit, ScanContext } from "@scanner/core";
import { DedupStore } from "@scanner/core";
import { ContentAnalyzer } from "@scanner/content-analyzer";

function httpWith(body: string, status = 200): IHttpClient {
  return {
    async get(url: string) {
      return { url, status, headers: {}, body: Buffer.from(body), text: body };
    },
    async post(url: string) {
      return { url, status, headers: {}, body: Buffer.from(body), text: body };
    },
  };
}

function cfg(): IConfigProvider {
  const patterns = {
    credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
    discovery: {},
  };
  return {
    get: () =>
      ({
        modules: { paths: true },
        concurrency: { pathProbesPerHost: 2 },
        pathsToCheck: ["/.env"],
      }) as never,
    patterns: () => patterns as never,
    resolveBudget: () => 1000,
  };
}

describe("PathsModule", () => {
  it("emits a hit from an exposed .env", async () => {
    const config = cfg();
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http: httpWith("AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n"),
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const hits: RawHit[] = [];
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit(h) {
        hits.push(h);
      },
    };
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.length >= 1, true);
    assert.equal(hits[0].source, "path");
  });

  it("still probes /.env.local after /.env is 403 or times out", async () => {
    const secret = "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n";
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 2 },
          pathsToCheck: ["/.env", "/.env.local"],
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/.env") && !url.includes(".local")) {
          const err = new Error("The operation was aborted due to timeout");
          err.name = "TimeoutError";
          throw err;
        }
        if (url.includes("/config.json") || url.includes("wp-config") || url.includes("appsettings")) {
          return { url, status: 403, headers: {}, body: Buffer.alloc(0), text: "forbidden" };
        }
        if (url.includes("/.env.local")) {
          return { url, status: 200, headers: {}, body: Buffer.from(secret), text: secret };
        }
        return { url, status: 403, headers: {}, body: Buffer.from("forbidden"), text: "forbidden" };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http,
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const hits: RawHit[] = [];
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit(h) {
        hits.push(h);
      },
    };
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.some((h) => h.path === "/.env.local"), true);
  });

  it("emits hits from /.env.example and sibling template paths when they contain secrets", async () => {
    const secret = "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n";
    const check = [
      "/.env.example",
      "/laravel/.env.example",
      "/.env.sample",
      "/.env.template",
      "/.env.dist",
      "/.env_example",
    ];
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 4 },
          pathsToCheck: check,
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http: httpWith(secret),
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const hits: RawHit[] = [];
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit(h) {
        hits.push(h);
      },
    };
    for await (const h of mod.scan(ctx)) hits.push(h);
    for (const p of check) {
      assert.equal(hits.some((h) => h.path === p), true, p);
    }
  });

  it("stops remaining path probes when the host is TCP-dead", async () => {
    const seen: string[] = [];
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 1 },
          pathsToCheck: ["/.env", "/.env.local", "/.env.production", "/.env.staging"],
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const http: IHttpClient = {
      async get(url: string) {
        seen.push(url);
        if (url.includes("/.env.local") || url.includes("/.env.production") || url.includes("/.env.staging")) {
          throw new Error("connect ECONNREFUSED 1.2.3.4:443");
        }
        return { url, status: 403, headers: {}, body: Buffer.from("forbidden"), text: "forbidden" };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http,
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit() {},
    };
    const hits: RawHit[] = [];
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.length, 0);
    assert.equal(
      seen.some((u) => u.includes("/.env.production") || u.includes("/.env.staging")),
      false,
    );
  });

  it("fires onPathsHalfway once after half the listed paths are probed", async () => {
    let half = 0;
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 1 },
          pathsToCheck: ["/.env", "/config.json", "/wp-config.php", "/appsettings.json"],
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const http: IHttpClient = {
      async get(url: string) {
        return { url, status: 404, headers: {}, body: Buffer.from("missing"), text: "missing" };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http,
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit() {},
      onPathsHalfway() {
        half++;
      },
    };
    for await (const _h of mod.scan(ctx)) {
      /* drain */
    }
    assert.equal(half, 1);
  });

  it("stops remaining path probes when 3 non-env paths return the same 200 body", async () => {
    const page = `<!DOCTYPE html><html><body><a href="/">home</a></body></html>`;
    const seen: string[] = [];
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 1 },
          pathsToCheck: ["/.env", "/secrets.yaml", "/config.xml", "/backup.sql", "/id_rsa.pub"],
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const http: IHttpClient = {
      async get(url: string) {
        seen.push(url);
        return { url, status: 200, headers: {}, body: Buffer.from(page), text: page };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const analyzer = new ContentAnalyzer(config);
    const warns: string[] = [];
    const mod = new PathsModule({
      http,
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: {
        info() {},
        warn(_ch, msg) {
          warns.push(msg);
        },
        error() {},
      },
    });
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit() {},
    };
    const hits: RawHit[] = [];
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.length, 0);
    assert.equal(
      seen.some((u) => u.includes("/id_rsa.pub") || u.includes("/backup.sql") || u.includes("/secrets.yaml")),
      false,
    );
    assert.equal(
      warns.some((w) => w.includes("html catch-all")),
      true,
    );
  });

  it("never emits a path hit when the body is HTML, even if regexes match", async () => {
    const page = `<!DOCTYPE html><html><body>AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA</body></html>`;
    const config = {
      get: () =>
        ({
          modules: { paths: true },
          concurrency: { pathProbesPerHost: 1 },
          pathsToCheck: ["/.env", "/wp-config.php.save", "/wp-config.php.old", "/wp-config.php.bak", "/secrets.yaml"],
        }) as never,
      patterns: () => ({ credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } }, discovery: {} }) as never,
      resolveBudget: () => 1000,
    };
    const http: IHttpClient = {
      async get(url: string) {
        return { url, status: 200, headers: {}, body: Buffer.from(page), text: page };
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new PathsModule({
      http,
      analyzer,
      config,
      dedup: new DedupStore(),
      logger: { info() {}, warn() {}, error() {} },
    });
    const ctx: ScanContext = {
      rawUrl: "https://t.test",
      origin: "https://t.test",
      signal: new AbortController().signal,
      emit() {},
    };
    const hits: RawHit[] = [];
    for await (const h of mod.scan(ctx)) hits.push(h);
    assert.equal(hits.length, 0);
  });
});
