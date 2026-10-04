import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deflateSync } from "node:zlib";
import { applyDelta, gitLooksExposed, isValidSha, parseGitIndex, parseGitObject, parsePack, parsePackObjects, } from "./git-objects.js";
import { GitModule, snippetAroundMatches } from "./index.js";
import { ContentAnalyzer } from "@scanner/content-analyzer";
import { DedupStore } from "@scanner/core";
describe("git objects", () => {
    it("parses a zlib git blob", () => {
        const raw = Buffer.concat([Buffer.from("blob 5\0"), Buffer.from("hello")]);
        const packed = deflateSync(raw);
        const parsed = parseGitObject(packed);
        assert.equal(parsed?.type, "blob");
        assert.equal(parsed?.content.toString(), "hello");
    });
    it("returns empty on invalid index", () => {
        assert.equal(parseGitIndex(Buffer.from("nope")).length, 0);
    });
    it("detects HEAD/config like the Go checker", () => {
        assert.equal(gitLooksExposed("/HEAD", "ref: refs/heads/main\n"), true);
        assert.equal(gitLooksExposed("/HEAD", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true);
        assert.equal(gitLooksExposed("/config", "[core]\n\trepositoryformatversion = 0\n"), true);
        assert.equal(gitLooksExposed("/HEAD", "<html>cloudflare</html>"), false);
        assert.equal(isValidSha("a".repeat(40)), true);
    });
    it("applies insert and copy deltas", () => {
        const insert = Buffer.from([0, 5, 5, ...Buffer.from("hello")]);
        assert.equal(applyDelta(Buffer.alloc(0), insert)?.toString(), "hello");
        const base = Buffer.from("ABCDEFGHIJ");
        const copy = Buffer.from([10, 10, 0x91, 0, 10]);
        assert.equal(applyDelta(base, copy)?.toString(), "ABCDEFGHIJ");
    });
    it("resolves OFS_DELTA objects inside a pack", () => {
        const base = Buffer.from("HELLO WORLD");
        const delta = Buffer.from([11, 12, 0x91, 0, 11, 1, 0x21]);
        const pack = buildPack([
            { type: 3, data: base },
            { type: 6, data: delta, ofs: 0 },
        ]);
        const blobs = parsePackObjects(pack);
        assert.equal(blobs.some((b) => b.toString() === "HELLO WORLD!"), true);
        const objs = parsePack(pack);
        assert.equal(objs.length >= 2, true);
    });
});
describe("GitModule", () => {
    it("follows HEAD ref then scans the loose blob", async () => {
        const secret = "AKIAAAAAAAAAAAAAAAAA";
        const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const blob = deflateSync(Buffer.concat([Buffer.from(`blob ${secret.length}\0`), Buffer.from(secret)]));
        const http = {
            async get(url) {
                if (!isOriginGit(url))
                    return notFound(url);
                if (url.endsWith("/HEAD")) {
                    return { url, status: 200, headers: {}, body: Buffer.from("ref: refs/heads/main\n"), text: "ref: refs/heads/main\n" };
                }
                if (url.endsWith("/refs/heads/main")) {
                    return { url, status: 200, headers: {}, body: Buffer.from(sha + "\n"), text: sha + "\n" };
                }
                if (url.includes("/objects/aa/" + sha.slice(2))) {
                    return { url, status: 200, headers: {}, body: blob, text: blob.toString("binary") };
                }
                return notFound(url);
            },
            async post(url) {
                return this.get(url);
            },
        };
        const hits = await runGit(http);
        assert.equal(hits.some((h) => h.source === "git" && h.matches.some((m) => m.value.startsWith("AKIA"))), true);
    });
    it("dumps a pack listed in objects/info/packs without treating the pack SHA as a loose object", async () => {
        const secret = "AKIAAAAAAAAAAAAAAAAA";
        const packSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const pack = buildPack([{ type: 3, data: Buffer.from(secret) }]);
        const fetched = [];
        const http = {
            async get(url) {
                fetched.push(url);
                if (!isOriginGit(url))
                    return notFound(url);
                if (url.endsWith("/HEAD")) {
                    return { url, status: 200, headers: {}, body: Buffer.from("ref: refs/heads/main\n"), text: "ref: refs/heads/main\n" };
                }
                if (url.endsWith("/objects/info/packs")) {
                    const text = `P pack-${packSha}.pack\n`;
                    return { url, status: 200, headers: {}, body: Buffer.from(text), text };
                }
                if (url.endsWith(`/objects/pack/pack-${packSha}.pack`)) {
                    return { url, status: 200, headers: {}, body: pack, text: pack.toString("binary") };
                }
                return notFound(url);
            },
            async post(url) {
                return this.get(url);
            },
        };
        const hits = await runGit(http);
        assert.equal(fetched.some((u) => u.includes(`/objects/bb/${packSha.slice(2)}`)), false);
        assert.equal(hits.some((h) => h.matches.some((m) => m.value.startsWith("AKIA"))), true);
    });
    it("reconstructs /backup/.git when origin /.git is missing", async () => {
        const secret = "AKIAAAAAAAAAAAAAAAAA";
        const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const blob = deflateSync(Buffer.concat([Buffer.from(`blob ${secret.length}\0`), Buffer.from(secret)]));
        const fetched = [];
        const http = {
            async get(url) {
                fetched.push(url);
                if (!url.includes("/backup/.git"))
                    return notFound(url);
                if (url.endsWith("/HEAD")) {
                    return { url, status: 200, headers: {}, body: Buffer.from("ref: refs/heads/main\n"), text: "ref: refs/heads/main\n" };
                }
                if (url.endsWith("/refs/heads/main")) {
                    return { url, status: 200, headers: {}, body: Buffer.from(sha + "\n"), text: sha + "\n" };
                }
                if (url.includes("/objects/aa/" + sha.slice(2))) {
                    return { url, status: 200, headers: {}, body: blob, text: blob.toString("binary") };
                }
                return notFound(url);
            },
            async post(url) {
                return this.get(url);
            },
        };
        const hits = await runGit(http);
        assert.equal(hits.some((h) => h.source === "git" && h.matches.some((m) => m.value.startsWith("AKIA"))), true);
        assert.equal(fetched.some((u) => u.includes("/backup/.git")), true);
        assert.equal(fetched.some((u) => /https:\/\/t\.test\/backup\/?$/.test(u) || u.endsWith("/.DS_Store")), false);
    });
    it("reads SVN wc.db and known text-base without pristine rebuild", async () => {
        const secret = "AKIAAAAAAAAAAAAAAAAA";
        const wc = Buffer.alloc(96, 0);
        Buffer.from("SQLite format 3\0").copy(wc);
        Buffer.from(secret).copy(wc, 40);
        const fetched = [];
        const http = {
            async get(url) {
                fetched.push(url);
                if (url.endsWith("/.svn/wc.db")) {
                    return { url, status: 200, headers: {}, body: wc, text: wc.toString("latin1") };
                }
                if (url.endsWith("/.svn/text-base/.env.svn-base")) {
                    const text = `AWS_ACCESS_KEY_ID=${secret}\n`;
                    return { url, status: 200, headers: {}, body: Buffer.from(text), text };
                }
                return notFound(url);
            },
            async post(url) {
                return this.get(url);
            },
        };
        const hits = await runGit(http);
        assert.equal(hits.some((h) => h.matches.some((m) => m.value.startsWith("AKIA"))), true);
        assert.equal(fetched.some((u) => u.includes("/pristine/")), false);
        assert.equal(fetched.some((u) => u.includes("/.svn/text-base/.env.svn-base")), true);
    });
    it("reads Mercurial hgrc without crawling store/data", async () => {
        const secret = "AKIAAAAAAAAAAAAAAAAA";
        const hgrc = `[auth]\nbb.username = bot\nbb.password = ${secret}\n`;
        const fetched = [];
        const http = {
            async get(url) {
                fetched.push(url);
                if (url.endsWith("/.hg/hgrc")) {
                    return { url, status: 200, headers: {}, body: Buffer.from(hgrc), text: hgrc };
                }
                return notFound(url);
            },
            async post(url) {
                return this.get(url);
            },
        };
        const hits = await runGit(http);
        assert.equal(hits.some((h) => h.matches.some((m) => m.value.startsWith("AKIA"))), true);
        assert.equal(fetched.some((u) => u.includes("/.hg/store/")), false);
    });
});
describe("snippetAroundMatches", () => {
    it("returns the whole unpacked blob when it fits (MAIL_FROM after a long APP_KEY)", () => {
        const env = [
            "MAIL_HOST=smtp.example.test",
            "MAIL_PORT=587",
            "MAIL_USERNAME=apikey",
            "MAIL_PASSWORD=secretpass12",
            "MAIL_ENCRYPTION=tls",
            "APP_KEY=" + "a".repeat(8000),
            "MAIL_FROM_ADDR=noreply@example.test",
            "MAIL_FROM_NAME=${APP_NAME}",
        ].join("\n");
        const snip = snippetAroundMatches(env, [
            { service: "smtp", value: "smtp.example.test", context: "", lineNumber: 1, patternName: "MAIL_HOST" },
        ]);
        assert.equal(snip, env);
        assert.match(snip, /MAIL_FROM_ADDR=noreply@example\.test/);
        assert.match(snip, /MAIL_FROM_NAME=\$\{APP_NAME\}/);
    });
    it("on a huge blob, still pulls MAIL_FROM_* far from MAIL_HOST", () => {
        const pad = "Z".repeat(30_000);
        const text = `${pad}MAIL_HOST=smtp.example.test\nMAIL_PASSWORD=secretpass12\n${pad}MAIL_FROM_ADDR=noreply@example.test\nMAIL_FROM_NAME=\${APP_NAME}\n`;
        const snip = snippetAroundMatches(text, [
            { service: "smtp", value: "smtp.example.test", context: "", lineNumber: 1, patternName: "MAIL_HOST" },
        ]);
        assert.match(snip, /MAIL_HOST=smtp\.example\.test/);
        assert.match(snip, /MAIL_FROM_ADDR=noreply@example\.test/);
        assert.match(snip, /MAIL_FROM_NAME=\$\{APP_NAME\}/);
    });
});
function isOriginGit(url) {
    return /^https:\/\/t\.test\/\.git(?:\/|$)/.test(url);
}
function notFound(url) {
    return { url, status: 404, headers: {}, body: Buffer.alloc(0), text: "" };
}
async function runGit(http) {
    const config = {
        get: () => ({
            modules: { git: true },
            concurrency: { gitWorkers: 2, gitMaxBlobs: 10 },
            gitSecretHints: [".env"],
        }),
        patterns: () => ({
            credentials: { aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] } },
            discovery: {},
        }),
        resolveBudget: () => 1000,
    };
    const analyzer = new ContentAnalyzer(config);
    const mod = new GitModule({
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
        signal: new AbortController().signal,
        emit() { },
    };
    for await (const h of mod.scan(ctx))
        hits.push(h);
    return hits;
}
function encodeTypeSize(type, size) {
    const bytes = [];
    let c = (type << 4) | (size & 15);
    size >>= 4;
    if (size)
        c |= 0x80;
    bytes.push(c);
    while (size) {
        c = size & 0x7f;
        size >>= 7;
        if (size)
            c |= 0x80;
        bytes.push(c);
    }
    return Buffer.from(bytes);
}
function encodeOfs(n) {
    const tmp = [];
    tmp.push(n & 0x7f);
    n >>= 7;
    while (n > 0) {
        n--;
        tmp.push(0x80 | (n & 0x7f));
        n >>= 7;
    }
    return Buffer.from(tmp.reverse());
}
function buildPack(objects) {
    const parts = [Buffer.from("PACK"), Buffer.alloc(8)];
    parts[1].writeUInt32BE(2, 0);
    parts[1].writeUInt32BE(objects.length, 4);
    const starts = [];
    let offset = 12;
    for (const obj of objects) {
        starts.push(offset);
        const header = encodeTypeSize(obj.type, obj.data.length);
        const ofs = obj.type === 6 && obj.ofs !== undefined ? encodeOfs(offset - starts[obj.ofs]) : Buffer.alloc(0);
        const z = deflateSync(obj.data);
        const chunk = Buffer.concat([header, ofs, z]);
        parts.push(chunk);
        offset += chunk.length;
    }
    parts.push(Buffer.alloc(20));
    return Buffer.concat(parts);
}
