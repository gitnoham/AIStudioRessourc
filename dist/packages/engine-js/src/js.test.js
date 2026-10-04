import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { JsModule } from "./index.js";
import { ContentAnalyzer } from "@scanner/content-analyzer";
import { DedupStore } from "@scanner/core";
describe("JsModule", () => {
    it("finds secrets in a referenced script", async () => {
        const html = `<script src="/app.js"></script>`;
        const js = "const k='AKIAAAAAAAAAAAAAAAAA';";
        const http = {
            async get(url) {
                const body = url.endsWith("app.js") ? js : "";
                return { url, status: 200, headers: {}, body: Buffer.from(body), text: body };
            },
            async post(url) {
                return this.get(url);
            },
        };
        const config = {
            get: () => ({
                modules: { js: true },
                concurrency: { jsCrawlDepth: 1, jsMaxScripts: 8 },
            }),
            patterns: () => ({
                credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
                discovery: {
                    scriptSrc: [{ source: "<script[^>]+src=[\"']([^\"']+)[\"']", flags: "gi" }],
                    jsImportRef: [],
                    nextStaticJS: [],
                },
            }),
            resolveBudget: () => 1000,
        };
        const analyzer = new ContentAnalyzer(config);
        const mod = new JsModule({
            http,
            analyzer,
            config,
            dedup: new DedupStore(),
            logger: { info() { }, warn() { }, error() { } },
        });
        const hits = [];
        const ctx = {
            rawUrl: "https://t.test",
            origin: "https://t.test",
            pageContent: html,
            signal: new AbortController().signal,
            emit() { },
        };
        for await (const h of mod.scan(ctx))
            hits.push(h);
        assert.equal(hits.some((h) => h.source === "js"), true);
    });
    it("follows quoted chunk imports from a bundle", async () => {
        const html = `<link rel="preload" href="/static/main.js" as="script">`;
        const files = {
            "https://t.test/static/main.js": `import("./chunk.js");`,
            "https://t.test/static/chunk.js": "const k='AKIAAAAAAAAAAAAAAAAA';",
        };
        const http = {
            async get(url) {
                const body = files[url] ?? "";
                return { url, status: body ? 200 : 404, headers: {}, body: Buffer.from(body), text: body };
            },
            async post(url) {
                return this.get(url);
            },
        };
        const config = {
            get: () => ({
                modules: { js: true },
                concurrency: { jsCrawlDepth: 3, jsMaxScripts: 8 },
            }),
            patterns: () => ({
                credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
                discovery: { scriptSrc: [], jsImportRef: [], nextStaticJS: [] },
            }),
            resolveBudget: () => 1000,
        };
        const analyzer = new ContentAnalyzer(config);
        const mod = new JsModule({
            http,
            analyzer,
            config,
            dedup: new DedupStore(),
            logger: { info() { }, warn() { }, error() { } },
        });
        const hits = [];
        const ctx = {
            rawUrl: "https://t.test",
            origin: "https://t.test",
            pageContent: html,
            signal: new AbortController().signal,
            emit() { },
        };
        for await (const h of mod.scan(ctx))
            hits.push(h);
        assert.equal(hits.some((h) => h.scriptUrl?.includes("chunk.js")), true);
    });
});
