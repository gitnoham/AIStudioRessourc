import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isUsableZoho, parseZohoAssignments, zohoDcHosts } from "./zoho-env.js";

const REFRESH = `1000.${"a".repeat(32)}.${"b".repeat(32)}`;
const CLIENT = `1000.${"c".repeat(32)}`;

describe("zoho env", () => {
  it("does not treat a refresh token as client id", () => {
    const env = parseZohoAssignments(`ZOHO_REFRESH_TOKEN=${REFRESH} ZOHO_CLIENT_ID=${CLIENT} ZOHO_CLIENT_SECRET=${"d".repeat(32)}`);
    assert.equal(env.ZOHO_REFRESH_TOKEN, REFRESH);
    assert.equal(env.ZOHO_CLIENT_ID, CLIENT);
    assert.equal(isUsableZoho(env), true);
    assert.equal(isUsableZoho({ ZOHO_REFRESH_TOKEN: REFRESH }), false);
  });

  it("prefers accounts.zoho.eu when the blob mentions it", () => {
    const env = parseZohoAssignments(`ZOHO_REFRESH_TOKEN=${REFRESH} https://accounts.zoho.eu/oauth`);
    assert.equal(zohoDcHosts(env)[0]?.dc, "eu");
  });
});
