import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hitChannelId } from "./channel.js";
const tg = {
    statsChannelId: "stats",
    validHitsChannelId: "valid",
    invalidHitsChannelId: "invalid",
    iaValidHitsChannelId: "ia-valid",
};
function hit(service, status) {
    return {
        source: "path",
        url: "https://example.com",
        origin: "https://example.com",
        path: "/.env",
        matches: [{ service, value: "k", context: "", lineNumber: 1, patternName: service }],
        validationStatus: status,
        validationDetails: "ok",
    };
}
describe("hitChannelId", () => {
    it("sends valid OpenAI / Anthropic to the IA channel", () => {
        assert.equal(hitChannelId(hit("openai", "valid"), tg), "ia-valid");
        assert.equal(hitChannelId(hit("anthropic", "valid"), tg), "ia-valid");
    });
    it("keeps Stripe / GitHub on the main valid channel", () => {
        assert.equal(hitChannelId(hit("stripe", "valid"), tg), "valid");
        assert.equal(hitChannelId(hit("github", "valid"), tg), "valid");
    });
    it("sends invalid IA to the invalid channel", () => {
        assert.equal(hitChannelId(hit("openai", "invalid"), tg), "invalid");
    });
    it("falls back to valid when IA channel is empty", () => {
        assert.equal(hitChannelId(hit("openai", "valid"), { ...tg, iaValidHitsChannelId: "" }), "valid");
    });
});
