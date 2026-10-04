import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseModelIds, modelsMeta, MODEL_LIST_CAP } from "./ai-models.js";
import { HttpCheckHandler } from "./handlers.js";
import { aiHandlers } from "./ai-handler.js";
function res(url, status, text = "") {
    return { url, status, headers: {}, body: Buffer.from(text), text };
}
function hit(service, value) {
    return {
        source: "path",
        url: "https://t.test/.env",
        origin: "https://t.test",
        path: "/.env",
        matches: [{ service, value, context: "", lineNumber: 1, patternName: service }],
    };
}
const openaiKey = {
    service: "openai",
    value: "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    context: "",
    lineNumber: 1,
    patternName: "openai",
};
describe("parseModelIds", () => {
    it("reads OpenAI data[].id", () => {
        assert.deepEqual(parseModelIds(JSON.stringify({ data: [{ id: "gpt-4o" }, { id: "gpt-4o-mini" }] })), ["gpt-4o", "gpt-4o-mini"]);
    });
    it("reads Cohere models[].name", () => {
        assert.deepEqual(parseModelIds(JSON.stringify({ models: [{ name: "command-r" }] })), ["command-r"]);
    });
    it("dedupes and skips junk", () => {
        assert.deepEqual(parseModelIds("not-json"), []);
        assert.deepEqual(parseModelIds(JSON.stringify({ data: [{ id: "a" }, { id: "a" }] })), ["a"]);
    });
});
describe("modelsMeta", () => {
    it("caps the stored list", () => {
        const ids = Array.from({ length: MODEL_LIST_CAP + 5 }, (_, i) => `m${i}`);
        const meta = modelsMeta(ids);
        assert.equal(meta.modelCount, String(MODEL_LIST_CAP + 5));
        assert.equal(meta.models.split("\n").length, MODEL_LIST_CAP);
    });
});
describe("HttpCheckHandler models", () => {
    it("marks OpenAI valid and lists models", async () => {
        const http = {
            async get(url) {
                return res(url, 200, JSON.stringify({ data: [{ id: "gpt-4o" }, { id: "o3-mini" }] }));
            },
            async post(url) {
                return this.get(url);
            },
        };
        const h = new HttpCheckHandler(http, "openai", (key) => key.startsWith("sk-") ? { url: "https://api.openai.com/v1/models", headers: { authorization: `Bearer ${key}` } } : null);
        const r = await h.validate(hit("openai", openaiKey.value), openaiKey, []);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.modelCount, "2");
        assert.equal(r.meta?.models, "gpt-4o\no3-mini");
    });
    it("truncates glued Replicate r8_ tokens to 40 chars and reads the account", async () => {
        let auth = "";
        const http = {
            async get(url, opts) {
                auth = String(opts?.headers?.authorization ?? "");
                return res(url, 200, JSON.stringify({ username: "acme", type: "user" }));
            },
            async post(url) {
                return this.get(url);
            },
        };
        const glued = `r8_${"A".repeat(51)}`;
        const h = new HttpCheckHandler(http, "replicate", (key) => ({
            url: "https://api.replicate.com/v1/account",
            headers: { authorization: `Bearer ${key}` },
        }));
        const r = await h.validate(hit("replicate", glued), { service: "replicate", value: glued, context: "", lineNumber: 1, patternName: "replicate" }, []);
        assert.equal(auth, `Bearer r8_${"A".repeat(37)}`);
        assert.equal(auth.length, "Bearer ".length + 40);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.identity, "acme");
    });
    it("marks 401 invalid without models", async () => {
        const http = {
            async get(url) {
                return res(url, 401, '{"error":"invalid"}');
            },
            async post(url) {
                return this.get(url);
            },
        };
        const h = new HttpCheckHandler(http, "openai", (key) => ({
            url: "https://api.openai.com/v1/models",
            headers: { authorization: `Bearer ${key}` },
        }));
        const r = await h.validate(hit("openai", openaiKey.value), openaiKey, []);
        assert.equal(r.valid, false);
        assert.equal(r.meta?.models, undefined);
    });
});
describe("AiHandler extras", () => {
    it("keeps OpenAI models and attaches billing when the extra endpoints answer", async () => {
        const http = {
            async get(url) {
                if (url.includes("/models"))
                    return res(url, 200, JSON.stringify({ data: [{ id: "gpt-4o" }] }));
                if (url.includes("subscription")) {
                    return res(url, 200, JSON.stringify({ plan: { title: "payg" }, hard_limit_usd: 120, has_payment_method: true }));
                }
                if (url.includes("credit_grants")) {
                    return res(url, 200, JSON.stringify({ total_used: 12, total_available: 100 }));
                }
                return res(url, 404, "");
            },
            async post(url) {
                return this.get(url);
            },
        };
        const h = aiHandlers(http).find((x) => x.service === "openai");
        const r = await h.validate(hit("openai", openaiKey.value), openaiKey, []);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.modelCount, "1");
        assert.equal(r.meta?.plan, "payg");
        assert.equal(r.meta?.quota, "120 USD");
        assert.equal(r.meta?.balance, "12/100 USD");
        assert.equal(r.meta?.accountType, "paid");
    });
    it("parses HuggingFace whoami into account fields", async () => {
        const http = {
            async get(url) {
                return res(url, 200, JSON.stringify({
                    name: "ops",
                    email: "ops@acme.example",
                    type: "user",
                    plan: "hf_pro",
                    orgs: [{ name: "acme" }],
                }));
            },
            async post(url) {
                return this.get(url);
            },
        };
        const h = aiHandlers(http).find((x) => x.service === "huggingface");
        const m = { service: "huggingface", value: "hf_abcdefghijklmnopqrstuvwxyz012345", context: "", lineNumber: 1, patternName: "hf" };
        const r = await h.validate(hit("huggingface", m.value), m, []);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.identity, "ops");
        assert.equal(r.meta?.email, "ops@acme.example");
        assert.equal(r.meta?.org, "acme");
        assert.equal(r.meta?.plan, "hf_pro");
    });
    it("reads DeepSeek balance after models", async () => {
        const http = {
            async get(url) {
                if (url.includes("balance")) {
                    return res(url, 200, JSON.stringify({ balance_infos: [{ currency: "USD", total_balance: "18.50" }] }));
                }
                return res(url, 200, JSON.stringify({ data: [{ id: "deepseek-chat" }] }));
            },
            async post(url) {
                return this.get(url);
            },
        };
        const h = aiHandlers(http).find((x) => x.service === "deepseek");
        const m = { service: "deepseek", value: "sk-deepseekabcdefghijklmnopqrstuvwxyz", context: "", lineNumber: 1, patternName: "ds" };
        const r = await h.validate(hit("deepseek", m.value), m, []);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.balance, "18.50 USD");
        assert.equal(r.meta?.modelCount, "1");
    });
});
