import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { ContentAnalyzer, isSecretishPath } from "./analyzer.js";
import { isWAFPage } from "./waf.js";
import { parseSourceMapV3, extractSourceMapRefs } from "./sourcemap.js";
import { extractJSONPayloads } from "./payloads.js";
import { isFalsePositive } from "./false-positives.js";
import { isVendorSecretPath } from "@scanner/core";
function fakeConfig(patterns) {
    return {
        get: () => ({}),
        patterns: () => patterns,
        resolveBudget: () => 1000,
    };
}
describe("ContentAnalyzer", () => {
    const patterns = {
        credentials: {
            aws: { patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"] },
            sendgrid: { patterns: ["(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})"] },
            anthropic: { patterns: ["\\b(sk-ant-api03-[A-Za-z0-9\\-_]{80,})\\b", "(?i)ANTHROPIC_API_KEY\\s*[:=]\\s*['\"]?(sk-ant-[A-Za-z0-9\\-_]{20,})['\"]?"] },
        },
        discovery: {
            scriptSrc: ['<script[^>]+src=["\']([^"\']+)["\']'],
        },
    };
    const analyzer = new ContentAnalyzer(fakeConfig(patterns));
    it("extracts AWS keys", () => {
        const r = analyzer.analyze({ content: "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n" });
        assert.equal(r.rejected, false);
        assert.equal(r.matches.some((m) => m.service === "aws" && m.value.startsWith("AKIA")), true);
    });
    it("pairs an AKIA with a nearby keyword secret (proximityKeywords)", () => {
        const secret = "abcdefghijklmnopqrstuvwxyz0123456789+/AB";
        const near = new ContentAnalyzer(fakeConfig({
            credentials: {
                aws: {
                    patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"],
                    proximityKeywords: ["REACT_APP_AWS_SECRET", "AWS_SECRET_ACCESS_KEY"],
                },
            },
            discovery: {},
        }));
        const r = near.analyze({
            content: `const id = "AKIAAAAAAAAAAAAAAAAA";\nREACT_APP_AWS_SECRET=${secret}\n`,
        });
        assert.equal(r.matches.some((m) => m.value === "AKIAAAAAAAAAAAAAAAAA"), true);
        assert.equal(r.matches.some((m) => m.value === secret), true);
    });
    it("does not pair an encoded joke secret or keys from node_modules", () => {
        const joke = "dGhpc19pc19mYWtlX3lvdV9hYnNvbHV0ZV9kb25rZXlfMTI5MzQ1NzA0Ng==";
        const near = new ContentAnalyzer(fakeConfig({
            credentials: {
                aws: {
                    patterns: [
                        "\\b(AKIA[A-Z0-9]{16})\\b",
                        "(?:AWS_SECRET)\\s*[=:]\\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?(?![A-Za-z0-9/+=])",
                    ],
                    proximityKeywords: ["AWS_SECRET", "AWS_SECRET_ACCESS_KEY"],
                },
            },
            discovery: {},
        }));
        const r = near.analyze({
            content: `AKIAAAAAAAAAAAAAAAAA\nAWS_SECRET=${joke}\n`,
        });
        assert.equal(r.matches.some((m) => m.value.startsWith("dGhpc1")), false);
        const vendor = analyzer.analyze({
            path: "/node_modules/.env",
            content: "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\nAWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz0123456789+/AB\n",
        });
        assert.equal(vendor.matches.length, 0);
    });
    it("does not pair reCAPTCHA as AWS secret even next to AKIA", () => {
        const near = new ContentAnalyzer(fakeConfig({
            credentials: {
                aws: {
                    patterns: ["\\b(AKIA[A-Z0-9]{16})\\b"],
                    proximityKeywords: ["secretAccessKey", "AWS_SECRET_ACCESS_KEY"],
                },
            },
            discovery: {},
        }));
        const r = near.analyze({
            content: `AKIAAAAAAAAAAAAAAAAA secretAccessKey=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`,
        });
        assert.equal(r.matches.some((m) => m.value.startsWith("6Ld")), false);
    });
    it("extracts Anthropic keys", () => {
        const r = analyzer.analyze({
            content: "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcdefghijklmnopqrstuv",
        });
        assert.equal(r.matches.some((m) => m.service === "anthropic"), true);
    });
    it("decompresses gzip", () => {
        const buf = gzipSync(Buffer.from("AKIAAAAAAAAAAAAAAAAA"));
        const text = analyzer.decompress(buf, "gzip");
        assert.match(text, /AKIA/);
    });
    it("rejects WAF pages", () => {
        const html = "<html><title>Attention Required</title>cloudflare cf-ray checking your browser</html>";
        assert.equal(isWAFPage(html), true);
        const r = analyzer.analyze({ content: html });
        assert.equal(r.rejected, true);
    });
    it("parses source map v3", () => {
        const json = JSON.stringify({
            version: 3,
            sources: ["app.ts"],
            sourcesContent: ["const k = 'AKIAAAAAAAAAAAAAAAAA';"],
        });
        const sources = parseSourceMapV3(json);
        assert.equal(sources.length, 1);
        assert.equal(sources[0].file, "app.ts");
    });
    it("extracts sourceMappingURL", () => {
        const refs = extractSourceMapRefs("//# sourceMappingURL=main.js.map\n");
        assert.deepEqual(refs, ["main.js.map"]);
    });
    it("extracts __NEXT_DATA__", () => {
        const html = `<script id="__NEXT_DATA__" type="application/json">{"foo":1}</script>`;
        const payloads = extractJSONPayloads(html);
        assert.equal(payloads[0]?.name, "__NEXT_DATA__");
    });
    it("drops truncated SendGrid keys (must be 69 chars)", () => {
        assert.equal(isFalsePositive({
            service: "sendgrid",
            value: "SG.mA0aAEv22P44yWic7KL2Pn.p1XvUvGcyXPDCDok-1sWprId",
            context: "MAIL_PASSWORD=",
            lineNumber: 1,
            patternName: "sg",
        }), true);
        const full = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;
        assert.equal(isFalsePositive({
            service: "sendgrid",
            value: full,
            context: "SENDGRID_API_KEY=",
            lineNumber: 1,
            patternName: "sg",
        }), false);
    });
    it("drops reCAPTCHA keys paired as AWS secrets", () => {
        assert.equal(isFalsePositive({
            service: "aws",
            value: "6LdMYFoiAAAAABT4bK44uh3FrouPMb9ElGRksUiq",
            context: "secretAccessKey=",
            lineNumber: 1,
            patternName: "aws.secret.env",
        }), true);
        assert.equal(isFalsePositive({
            service: "aws",
            value: "AKIA3TF4DC3BMTMN4IIP",
            context: "AWS_ACCESS_KEY_ID=",
            lineNumber: 1,
            patternName: "aws.AKIA",
        }), false);
    });
    it("drops CSS utility classes as Mandrill false positives", () => {
        assert.equal(isFalsePositive({
            service: "mandrill",
            value: "md-flex-align-flex-start",
            context: 'class="md-flex-align-flex-start"',
            lineNumber: 1,
            patternName: "md-",
        }), true);
    });
    it("keeps secrets on every pathsToCheck, including .env.example / sample / template", () => {
        const settings = JSON.parse(readFileSync(new URL("../../../config/appsettings.json", import.meta.url), "utf8"));
        const paths = settings.pathsToCheck.filter((p) => p.startsWith("/"));
        assert.ok(paths.includes("/.env.example"));
        assert.ok(paths.includes("/laravel/.env.example"));
        const secret = "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n";
        const vendor = [];
        const dropped = [];
        for (const path of paths) {
            if (isVendorSecretPath(path))
                vendor.push(path);
            const r = analyzer.analyze({ path, url: `https://t.test${path}`, content: secret });
            if (!r.matches.some((m) => m.value.startsWith("AKIA")))
                dropped.push(path);
        }
        assert.deepEqual(vendor, []);
        assert.deepEqual(dropped, []);
        for (const p of [
            "/.env",
            "/.env.local",
            "/.env.example",
            "/.env.sample",
            "/.env.template",
            "/.env.dist",
            "/.env_example",
            "/laravel/.env.example",
            "/node/.env_example",
            "/wp-config.php.bak",
            "/wp-config.php.txt",
            "/.env~",
        ]) {
            assert.equal(isSecretishPath(p), true, p);
            assert.equal(analyzer.isLikelySecretFile(secret, p), true, p);
        }
    });
    it("does not treat a long HTML 200 as a secret file unless the path is env/config-like", () => {
        const html = `<html><body><nav></nav><div>${"x".repeat(400)}</div></body></html>`;
        assert.equal(analyzer.isLikelySecretFile(html, "/index.html"), false);
        assert.equal(analyzer.isLikelySecretFile(`${html}\nAWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA`, "/.env.example"), false);
    });
    it("does not treat a catch-all HTML page as a secret just because the path is yaml/sql/zip", () => {
        const page = `<!DOCTYPE html><html><head></head><body><a href="/login">home</a><div class="wrap">${"x".repeat(400)}</div></body></html>`;
        assert.equal(analyzer.isLikelySecretFile(page, "/secrets.yaml"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/backup.sql"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/id_rsa.pub"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/config.xml"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/wp-config.php.save"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/wp-config.php.old"), false);
        assert.equal(analyzer.isLikelySecretFile(page, "/wp-config.php.bak"), false);
    });
});
