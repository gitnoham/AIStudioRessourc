import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizeScanUrl, originOf, httpsToHttpSamePort, httpsToHttpDefaultPort } from "./normalize.js";
import { DedupStore, hashUrl } from "../dedup/dedup-store.js";
describe("normalizeScanUrl", () => {
    it("adds https when scheme is missing", () => {
        assert.equal(normalizeScanUrl("example.com"), "https://example.com");
    });
    it("keeps http as-is", () => {
        assert.equal(normalizeScanUrl("http://example.com"), "http://example.com");
    });
    it("skips comments and blanks", () => {
        assert.equal(normalizeScanUrl("# skip"), null);
        assert.equal(normalizeScanUrl("  "), null);
    });
    it("collapses trailing slash on origin", () => {
        assert.equal(normalizeScanUrl("https://example.com/"), "https://example.com");
    });
});
describe("DedupStore", () => {
    it("marks a key only once", () => {
        const d = new DedupStore();
        assert.equal(d.checkAndMark("url", hashUrl("https://a.com")), true);
        assert.equal(d.checkAndMark("url", hashUrl("https://a.com")), false);
    });
});
describe("originOf", () => {
    it("returns scheme://host", () => {
        assert.equal(originOf("https://a.com/foo"), "https://a.com");
    });
});
describe("httpsToHttpSamePort", () => {
    it("keeps port 443 instead of falling back to 80", () => {
        assert.equal(httpsToHttpSamePort("https://50.114.96.118/auth.json"), "http://50.114.96.118:443/auth.json");
    });
    it("keeps an explicit non-443 port", () => {
        assert.equal(httpsToHttpSamePort("https://a.test:8443/.env"), "http://a.test:8443/.env");
    });
    it("leaves http URLs unchanged", () => {
        assert.equal(httpsToHttpSamePort("http://a.test/.env"), "http://a.test/.env");
    });
});
describe("httpsToHttpDefaultPort", () => {
    it("falls back to http on port 80", () => {
        assert.equal(httpsToHttpDefaultPort("https://50.34.104.21/"), "http://50.34.104.21/");
    });
    it("strips explicit 443", () => {
        assert.equal(httpsToHttpDefaultPort("https://a.test:443/.env"), "http://a.test/.env");
    });
});
