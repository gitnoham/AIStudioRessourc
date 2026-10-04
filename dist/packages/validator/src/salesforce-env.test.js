import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { collectSalesforceEnv, formatSalesforceBlock, isUsableSalesforce, parseSalesforceAssignments, salesforceFingerprint, } from "./salesforce-env.js";
const SID = "00D000000000001!AQEAQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
describe("salesforce env", () => {
    it("pulls username password token session and instance from one blob", () => {
        const blob = [
            `SF_USERNAME=ops@acme.example`,
            `SF_PASSWORD=hunter2token`,
            `SF_SECURITY_TOKEN=Abcdefghijklmnopqrstuvwx`,
            `SF_SESSION_ID=${SID}`,
            `SF_INSTANCE_URL=https://acme.my.salesforce.com`,
        ].join("\n");
        const env = parseSalesforceAssignments(blob);
        assert.equal(env.SF_USERNAME, "ops@acme.example");
        assert.equal(env.SF_PASSWORD, "hunter2token");
        assert.equal(env.SF_SECURITY_TOKEN, "Abcdefghijklmnopqrstuvwx");
        assert.equal(env.SF_SESSION_ID, SID);
        assert.equal(env.SF_INSTANCE_URL, "https://acme.my.salesforce.com");
        assert.equal(isUsableSalesforce(env), true);
        const block = formatSalesforceBlock(env);
        assert.match(block, /SF_USERNAME=/);
        assert.match(block, /SF_SESSION_ID=/);
    });
    it("finds a glued 00D session even without a key name", () => {
        const env = parseSalesforceAssignments(`token=${SID} leftover`);
        assert.equal(env.SF_SESSION_ID, SID);
    });
    it("fingerprints one org session so duplicates collapse", () => {
        const hit = {
            source: "path",
            url: "https://t.test/.env",
            origin: "https://t.test",
            path: "/.env",
            contentSnippet: `SALESFORCE_USERNAME=a@b.co SF_PASSWORD=secret12 ${SID}`,
            matches: [],
        };
        const m = {
            service: "salesforce",
            value: SID,
            context: hit.contentSnippet ?? "",
            lineNumber: 1,
            patternName: "session",
        };
        const env = collectSalesforceEnv(hit, m, [m]);
        assert.equal(env.SF_USERNAME, "a@b.co");
        assert.equal(salesforceFingerprint(env), `sf:sid:${SID}`);
    });
    it("treats client id + secret as usable without user/pass", () => {
        const env = parseSalesforceAssignments("SALESFORCE_CLIENT_ID=3MVG9abcdefghijklmnopqrstuv SF_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert.equal(env.SF_CLIENT_ID, "3MVG9abcdefghijklmnopqrstuv");
        assert.equal(isUsableSalesforce(env), true);
        assert.equal(isUsableSalesforce({ SF_CLIENT_ID: "3MVG9abcdefghijklmnopqrstuv" }), false);
    });
});
