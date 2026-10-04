import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AzureHandler, SalesforceHandler, ZohoHandler } from "./crm-handlers.js";
function res(url, status, text = "") {
    return { url, status, headers: {}, body: Buffer.from(text), text };
}
function hit(matches, snippet) {
    return {
        source: "path",
        url: "https://t.test/.env",
        origin: "https://t.test",
        path: "/.env",
        matches,
        contentSnippet: snippet,
    };
}
describe("SalesforceHandler", () => {
    it("logs in over SOAP and returns org/user", async () => {
        const xml = `<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <loginResponse>
      <result>
        <sessionId>00Dxx0000001!session</sessionId>
        <serverUrl>https://acme.my.salesforce.com/services/Soap/u/59.0</serverUrl>
        <userId>005xx</userId>
        <userFullName>Ops User</userFullName>
        <userEmail>ops@acme.example</userEmail>
        <organizationId>00Dxx</organizationId>
        <organizationName>Acme</organizationName>
      </result>
    </loginResponse>
  </soapenv:Body>
</soapenv:Envelope>`;
        const http = {
            async get(url) {
                return res(url, 404, "");
            },
            async post(url) {
                return res(url, 200, xml);
            },
        };
        const blob = "SF_USERNAME=ops@acme.example SF_PASSWORD=hunter2token SF_SECURITY_TOKEN=Abcdefghijklmnopqrstuvwx";
        const m = { service: "salesforce", value: "ops@acme.example", context: blob, lineNumber: 1, patternName: "user" };
        const r = await new SalesforceHandler(http).validate(hit([m], blob), m, [m]);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.org, "Acme");
        assert.equal(r.meta?.email, "ops@acme.example");
        assert.match(r.meta?.instance ?? "", /acme\.my\.salesforce\.com/);
        assert.notEqual(r.meta?.skipNotify, "1");
    });
    it("skips a session dump without login material", async () => {
        const http = {
            async get() {
                throw new Error("should not fetch");
            },
            async post() {
                throw new Error("should not post");
            },
        };
        const m = { service: "salesforce", value: "not-a-session", context: "SF_CLIENT_ID=abc", lineNumber: 1, patternName: "cid" };
        const r = await new SalesforceHandler(http).validate(hit([m], "SF_CLIENT_ID=abc"), m, [m]);
        assert.equal(r.meta?.skipNotify, "1");
    });
    it("exchanges client id + secret via OAuth client_credentials", async () => {
        const cid = "3MVG9abcdefghijklmnopqrstuv";
        const secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        const http = {
            async get(url) {
                if (url.includes("/Organization/")) {
                    return res(url, 200, JSON.stringify({ Name: "Acme Org", OrganizationType: "Enterprise", IsSandbox: false, InstanceName: "EU46" }));
                }
                return res(url, 200, JSON.stringify({
                    display_name: "Integration User",
                    email: "int@acme.example",
                    organization_id: "00Dxx0000000001",
                    username: "int@acme.example",
                }));
            },
            async post(url) {
                assert.match(url, /\/services\/oauth2\/token$/);
                return res(url, 200, JSON.stringify({
                    access_token: "00Dxx!oauth",
                    instance_url: "https://acme.my.salesforce.com",
                    id: "https://login.salesforce.com/id/00Dxx0000000001/005xx",
                }));
            },
        };
        const blob = `SALESFORCE_CLIENT_ID=${cid} SF_CLIENT_SECRET=${secret}`;
        const m = { service: "salesforce", value: secret, context: blob, lineNumber: 1, patternName: "secret" };
        const r = await new SalesforceHandler(http).validate(hit([m], blob), m, [m]);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.org, "Acme Org");
        assert.equal(r.meta?.user, "Integration User");
        assert.match(r.meta?.instance ?? "", /acme\.my\.salesforce\.com/);
        assert.match(r.meta?.envBlock ?? "", /SF_CLIENT_ID=/);
    });
});
describe("AzureHandler", () => {
    it("exchanges client credentials and reads the tenant", async () => {
        const http = {
            async get(url) {
                return res(url, 200, JSON.stringify({
                    value: [{ displayName: "Contoso", id: "11111111-1111-1111-1111-111111111111", verifiedDomains: [{ name: "acme.com", isDefault: true }] }],
                }));
            },
            async post(url) {
                return res(url, 200, JSON.stringify({ access_token: "tok" }));
            },
        };
        const blob = "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111 AZURE_CLIENT_ID=22222222-2222-2222-2222-222222222222 AZURE_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz0123456789~-._";
        const m = { service: "azure", value: "abcdefghijklmnopqrstuvwxyz0123456789~-._", context: blob, lineNumber: 1, patternName: "secret" };
        const r = await new AzureHandler(http).validate(hit([m], blob), m, [m]);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.org, "Contoso");
        assert.equal(r.meta?.domains, "acme.com");
    });
    it("does not notify a lone Azure secret", async () => {
        const http = {
            async get() {
                throw new Error("no");
            },
            async post() {
                throw new Error("no");
            },
        };
        const m = { service: "azure", value: "abcdefghijklmnopqrstuvwxyz0123456789~-._", context: "AZURE_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz0123456789~-._", lineNumber: 1, patternName: "secret" };
        const r = await new AzureHandler(http).validate(hit([m], m.context), m, [m]);
        assert.equal(r.meta?.skipNotify, "1");
    });
});
describe("ZohoHandler", () => {
    it("refreshes the token then loads org and current user", async () => {
        const refresh = `1000.${"a".repeat(32)}.${"b".repeat(32)}`;
        const client = `1000.${"c".repeat(32)}`;
        const secret = "d".repeat(32);
        const http = {
            async get(url) {
                if (url.includes("/org")) {
                    return res(url, 200, JSON.stringify({ org: [{ company_name: "Acme CRM", primary_email: "ops@acme.example", license_details: { paid: true, paid_type: "enterprise", users_license_purchased: 12 } }] }));
                }
                return res(url, 200, JSON.stringify({ users: [{ full_name: "Ops", email: "ops@acme.example", role: { name: "Admin" } }] }));
            },
            async post(url) {
                return res(url, 200, JSON.stringify({ access_token: "zoho-at" }));
            },
        };
        const blob = `ZOHO_CLIENT_ID=${client} ZOHO_CLIENT_SECRET=${secret} ZOHO_REFRESH_TOKEN=${refresh} accounts.zoho.eu`;
        const m = { service: "zoho", value: refresh, context: blob, lineNumber: 1, patternName: "refresh" };
        const r = await new ZohoHandler(http).validate(hit([m], blob), m, [m]);
        assert.equal(r.valid, true);
        assert.equal(r.meta?.org, "Acme CRM");
        assert.equal(r.meta?.dc, "eu");
        assert.match(r.meta?.license ?? "", /enterprise/);
    });
    it("does not notify a refresh token without client secret", async () => {
        const refresh = `1000.${"a".repeat(32)}.${"b".repeat(32)}`;
        const http = {
            async get() {
                throw new Error("no");
            },
            async post() {
                throw new Error("no");
            },
        };
        const m = { service: "zoho", value: refresh, context: refresh, lineNumber: 1, patternName: "zoho" };
        const r = await new ZohoHandler(http).validate(hit([m], refresh), m, [m]);
        assert.equal(r.meta?.skipNotify, "1");
    });
});
