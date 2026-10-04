import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { VulnModule, nextJsEvidence } from "./index.js";
import type { EngineDeps, RawHit, ScanContext } from "@scanner/core";
import { DedupStore, extractNextActionIds } from "@scanner/core";

const NEXT_PAGE = `<!DOCTYPE html><html><head>
<title>shop</title>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}}}</script>
</head><body>
<div id="__next"></div>
<input type="hidden" name="$ACTION_ID_ab12cd34ef5678ab90cd12ef34ab56cd"/>
<script src="/_next/static/chunks/main-1234.js"></script>
<script>self.__next_f.push([1,"a:0:{}"])</script>
<script>self.__next_f.push([1,"a:1:{\\"id\\":\\"b0a1b2c3d4e5f60718293a4b5c6d7e8f9\\"}"]);</script>
</body></html>`;

const PLAIN_PAGE = `<!DOCTYPE html><html><head><title>legacy</title></head>
<body><script src="/app.js"></script></body></html>`;

function makeDeps(modules: Record<string, boolean>): EngineDeps {
  const config = {
    get: () => ({ modules }),
    patterns: () => ({ credentials: {}, discovery: {} }),
    resolveBudget: () => 1000,
  };
  return {
    http: {
      async get() {
        throw new Error("unused");
      },
      async post() {
        throw new Error("unused");
      },
    },
    analyzer: null as never,
    config: config as never,
    dedup: new DedupStore(),
    logger: { info() {}, warn() {}, error() {} },
  };
}

function ctx(origin: string, pageContent?: string): ScanContext {
  return {
    rawUrl: `${origin}/shop`,
    origin,
    pageContent,
    signal: new AbortController().signal,
    emit() {},
  };
}

describe("extractNextActionIds", () => {
  it("finds $ACTION_ID_ refs before flight chunk ids", () => {
    assert.deepEqual(extractNextActionIds(NEXT_PAGE), [
      "ab12cd34ef5678ab90cd12ef34ab56cd",
      "b0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    ]);
  });

  it("returns no ids for a plain page", () => {
    assert.deepEqual(extractNextActionIds(PLAIN_PAGE), []);
  });

  it("returns no ids for empty input", () => {
    assert.deepEqual(extractNextActionIds(""), []);
  });
});

describe("nextJsEvidence", () => {
  it("detects Next.js markers in a page", () => {
    const markers = nextJsEvidence(NEXT_PAGE);
    assert.deepEqual(markers, ["__NEXT_DATA__", "next/static", "__next_f"]);
  });

  it("returns no markers for a plain page", () => {
    assert.deepEqual(nextJsEvidence(PLAIN_PAGE), []);
  });

  it("returns no markers for an empty page", () => {
    assert.deepEqual(nextJsEvidence(""), []);
  });
});

describe("VulnModule", () => {
  it("emits a react2shell hit for a Next.js page", async () => {
    const mod = new VulnModule(makeDeps({ vuln: true }));
    const hits: RawHit[] = [];
    const c = ctx("https://t.test", NEXT_PAGE);
    for await (const h of mod.scan(c)) hits.push(h);
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.source, "vuln");
    assert.equal(hits[0]?.origin, "https://t.test");
    assert.equal(hits[0]?.matches[0]?.service, "react2shell");
    assert.equal(hits[0]?.matches[0]?.value, "https://t.test");
    assert.match(hits[0]?.matches[0]?.context ?? "", /__NEXT_DATA__/);
    assert.equal(hits[0]?.extra?.nextActionId, "ab12cd34ef5678ab90cd12ef34ab56cd");
  });

  it("emits nothing for a non-Next page", async () => {
    const mod = new VulnModule(makeDeps({ vuln: true }));
    const hits: RawHit[] = [];
    for await (const h of mod.scan(ctx("https://t.test", PLAIN_PAGE))) hits.push(h);
    assert.equal(hits.length, 0);
  });

  it("emits nothing without page content", async () => {
    const mod = new VulnModule(makeDeps({ vuln: true }));
    const hits: RawHit[] = [];
    for await (const h of mod.scan(ctx("https://t.test"))) hits.push(h);
    assert.equal(hits.length, 0);
  });

  it("emits one hit per origin (dedup vuln-origin)", async () => {
    const deps = makeDeps({ vuln: true });
    const mod = new VulnModule(deps);
    const first: RawHit[] = [];
    for await (const h of mod.scan(ctx("https://t.test", NEXT_PAGE))) first.push(h);
    assert.equal(first.length, 1);
    // Deuxième URL du même origin : le HTML de la home est identique → skip.
    const second: RawHit[] = [];
    for await (const h of mod.scan(ctx("https://t.test", NEXT_PAGE))) second.push(h);
    assert.equal(second.length, 0);
  });

  it("is disabled when modules.vuln is false", () => {
    const mod = new VulnModule(makeDeps({ vuln: false }));
    assert.equal(mod.isEnabled({ modules: { vuln: false } } as never), false);
    assert.equal(mod.isEnabled({ modules: { vuln: true } } as never), true);
  });
});
