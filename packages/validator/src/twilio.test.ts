import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { HttpResponse, IHttpClient, PatternMatch, RawHit } from "@scanner/core";
import { TwilioHandler, collectTwilioCreds } from "./twilio.js";

function res(url: string, status: number, text = ""): HttpResponse {
  return { url, status, headers: {}, body: Buffer.from(text), text };
}

const sid = "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const token = "e38123f77e9d6dc18df78efa3e2dfa1f";

function hit(matches: PatternMatch[], snippet = ""): RawHit {
  return {
    source: "js",
    url: "https://water-science.com",
    origin: "https://water-science.com",
    scriptUrl: "https://water-science.com/js/xserverv3.js",
    matches,
    contentSnippet: snippet,
  };
}

describe("collectTwilioCreds", () => {
  it("pairs Account SID from the JS snippet with the auth token match", () => {
    const creds = collectTwilioCreds(
      hit(
        [{ service: "twilio", value: token, context: `authToken:"${token}"`, lineNumber: 1, patternName: "authToken" }],
        `accountSid:"${sid}",authToken:"${token}"`,
      ),
      {
        service: "twilio",
        value: token,
        context: `authToken:"${token}"`,
        lineNumber: 1,
        patternName: "authToken",
      },
      [],
    );
    assert.equal(creds.sid, sid);
    assert.equal(creds.token, token);
  });
});

describe("TwilioHandler", () => {
  it("loads account name, balance and phone numbers", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith(".json") && url.includes("/Accounts/AC") && !url.includes("Balance") && !url.includes("Incoming")) {
          return res(url, 200, JSON.stringify({ friendly_name: "Water", status: "active", type: "Full" }));
        }
        if (url.includes("Balance.json")) return res(url, 200, JSON.stringify({ balance: "12.50", currency: "USD" }));
        if (url.includes("IncomingPhoneNumbers.json")) {
          return res(url, 200, JSON.stringify({ incoming_phone_numbers: [{ phone_number: "+15551234567" }] }));
        }
        return res(url, 404, "");
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const handler = new TwilioHandler(http);
    const r = await handler.validate(
      hit(
        [
          { service: "twilio", value: sid, context: sid, lineNumber: 1, patternName: "sid" },
          { service: "twilio", value: token, context: token, lineNumber: 2, patternName: "authToken" },
        ],
        `${sid} ${token}`,
      ),
      { service: "twilio", value: sid, context: sid, lineNumber: 1, patternName: "sid" },
      [{ service: "twilio", value: token, context: token, lineNumber: 2, patternName: "authToken" }],
    );
    assert.equal(r.valid, true);
    assert.equal(r.meta?.friendlyName, "Water");
    assert.equal(r.meta?.balance, "12.50 USD");
    assert.equal(r.meta?.numbers, "+15551234567");
  });

  it("skips a Twilio token without Account SID", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        return res(url, 500, "");
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const r = await new TwilioHandler(http).validate(
      hit([{ service: "twilio", value: token, context: `authToken="${token}"`, lineNumber: 1, patternName: "authToken" }]),
      { service: "twilio", value: token, context: `authToken="${token}"`, lineNumber: 1, patternName: "authToken" },
      [],
    );
    assert.equal(r.raw, true);
    assert.equal(r.meta?.skipNotify, "1");
  });
});
