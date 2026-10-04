import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { collectAzureEnv, isUsableAzure, parseAzureAssignments } from "./azure-env.js";
describe("azure env", () => {
    it("needs tenant + client + secret", () => {
        const env = parseAzureAssignments([
            "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111",
            "AZURE_CLIENT_ID=22222222-2222-2222-2222-222222222222",
            "AZURE_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz0123456789~-._",
        ].join("\n"));
        assert.equal(isUsableAzure(env), true);
        assert.equal(isUsableAzure({ AZURE_CLIENT_SECRET: "abcdefghijklmnopqrstuvwxyz0123456789~-._" }), false);
    });
    it("collects keys from a hit blob", () => {
        const blob = "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111 AZURE_CLIENT_ID=22222222-2222-2222-2222-222222222222 AZURE_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz0123456789~-._";
        const m = { service: "azure", value: "abcdefghijklmnopqrstuvwxyz0123456789~-._", context: blob, lineNumber: 1, patternName: "secret" };
        const hit = { source: "path", url: "https://t.test/.env", origin: "https://t.test", path: "/.env", matches: [m], contentSnippet: blob };
        const env = collectAzureEnv(hit, m, [m]);
        assert.equal(env.AZURE_TENANT_ID, "11111111-1111-1111-1111-111111111111");
        assert.equal(env.AZURE_CLIENT_ID, "22222222-2222-2222-2222-222222222222");
    });
});
