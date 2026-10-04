import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type {
  HttpRequestOptions,
  HttpResponse,
  IConfigProvider,
  IHttpClient,
  ILogger,
  PatternMatch,
  RawHit,
} from "@scanner/core";
import { HttpClient } from "@scanner/core";
import {
  React2ShellHandler,
  buildReact2ShellProbe,
  classifyReact2Shell,
  isVulnerableReactServerDom,
} from "./react2shell.js";

const VULN_FIXTURE = `Error: Cannot read properties of undefined (reading 'call')
    at decodeReply (/app/node_modules/react-server-dom-webpack@19.0.0/cjs/react-server-dom-webpack-server.node.js:123:1)`;

const PATCHED_FIXTURE = `Error: Server Reference is not callable: react-server-dom-turbopack@19.1.2`;

const CRASH_NO_VERSION = `TypeError: Cannot read properties of undefined (reading 'call')
    at Object.decodeReply (webpack:///./node_modules/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.development.js:123)`;

const GENERIC_500 = `Internal Server Error`;

function res(url: string, status: number, text = ""): HttpResponse {
  return { url, status, headers: {}, body: Buffer.from(text), text };
}

function match(): PatternMatch {
  return {
    service: "react2shell",
    value: "https://t.test",
    context: "__NEXT_DATA__, next/static",
    lineNumber: 0,
    patternName: "nextjs",
  };
}

function hit(m: PatternMatch): RawHit {
  return {
    source: "vuln",
    url: "https://t.test/shop",
    origin: "https://t.test",
    matches: [m],
    contentSnippet: m.context,
  };
}

describe("isVulnerableReactServerDom", () => {
  const cases: Array<[string, boolean]> = [
    ["0.0.0", true], // runtimes expérimentaux Next 13/14
    ["0.0.0-experimental-123", true],
    ["18.3.1", true], // React 18 (Next 14) : toute la branche est vulnérable
    ["19.0.0", true],
    ["19.0.1", false],
    ["19.1.0", true],
    ["19.1.1", true],
    ["19.1.2", false],
    ["19.2.0", true],
    ["19.2.1", false],
    ["19.3.0", false],
    ["garbage", false],
  ];
  for (const [version, expected] of cases) {
    it(`${version} → ${expected ? "vulnérable" : "patché"}`, () => {
      assert.equal(isVulnerableReactServerDom(version), expected);
    });
  }
});

describe("classifyReact2Shell", () => {
  it("is inconclusive when the status is not 500", () => {
    assert.equal(classifyReact2Shell(200, VULN_FIXTURE).verdict, "inconclusive");
  });

  it("flags a vulnerable version leaked in a 500", () => {
    const c = classifyReact2Shell(500, VULN_FIXTURE);
    assert.equal(c.verdict, "vulnerable");
    assert.equal(c.version, "19.0.0");
    assert.equal(c.flavor, "webpack");
  });

  it("flags a patched version leaked in a 500", () => {
    const c = classifyReact2Shell(500, PATCHED_FIXTURE);
    assert.equal(c.verdict, "patched");
    assert.equal(c.version, "19.1.2");
    assert.equal(c.flavor, "turbopack");
  });

  it("flags the crash signature as vulnerable even without a version", () => {
    const c = classifyReact2Shell(500, CRASH_NO_VERSION);
    assert.equal(c.verdict, "vulnerable");
    assert.equal(c.version, undefined);
  });

  it("is inconclusive on a generic 500 without react-server-dom leak", () => {
    assert.equal(classifyReact2Shell(500, GENERIC_500).verdict, "inconclusive");
  });
});

describe("buildReact2ShellProbe", () => {
  it("normalizes the URL and builds the multipart body", () => {
    const p = buildReact2ShellProbe("https://t.test");
    assert.equal(p.url, "https://t.test/");
    assert.match(p.headers["content-type"] ?? "", /^multipart\/form-data; boundary=/);
    assert.equal(p.headers["next-action"], "r2s-probe");
    assert.match(p.body, /name="\$ACTION_REF_0"/);
    assert.match(p.body, /\["", null\]/);
    assert.match(p.body, new RegExp(`--${p.headers["content-type"]!.split("boundary=")[1]}--`));
  });

  it("uses a real action id when provided", () => {
    const id = "ab12cd34ef5678ab90cd12ef34ab56cd";
    const p = buildReact2ShellProbe("https://t.test", id);
    assert.equal(p.headers["next-action"], id);
  });
});

describe("React2ShellHandler", () => {
  it("confirms a vulnerable server and sends the well-formed multipart probe", async () => {
    let capturedUrl = "";
    let capturedHeaders: Record<string, string> = {};
    let capturedBody = "";
    const http: IHttpClient = {
      async get(url) {
        return res(url, 200, "");
      },
      async post(url, opts?: HttpRequestOptions) {
        capturedUrl = url;
        capturedHeaders = opts?.headers ?? {};
        capturedBody = opts?.body ?? "";
        return res(url, 500, VULN_FIXTURE);
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, true);
    assert.equal(r.meta?.statusKind, "vulnerable");
    assert.equal(r.meta?.version, "19.0.0");
    assert.equal(r.meta?.flavor, "webpack");
    assert.equal(r.meta?.cve, "CVE-2025-55182");
    assert.equal(r.meta?.marker, "__NEXT_DATA__, next/static");
    assert.notEqual(r.meta?.skipNotify, "1");
    assert.equal(capturedUrl, "https://t.test/");
    assert.match(capturedHeaders["content-type"] ?? "", /^multipart\/form-data; boundary=/);
    assert.equal(capturedHeaders["next-action"], "r2s-probe");
    assert.match(capturedBody, /name="\$ACTION_REF_0"/);
    assert.match(capturedBody, /\["", null\]/);
  });

  it("reports a patched server without skipNotify", async () => {
    const http: IHttpClient = {
      async get(url) {
        return res(url, 200, "");
      },
      async post(url) {
        return res(url, 500, PATCHED_FIXTURE);
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, false);
    assert.equal(r.raw, undefined);
    assert.equal(r.meta?.statusKind, "patched");
    assert.equal(r.meta?.version, "19.1.2");
    assert.notEqual(r.meta?.skipNotify, "1");
  });

  it("skips notification on an inconclusive probe", async () => {
    const http: IHttpClient = {
      async get(url) {
        return res(url, 200, "");
      },
      async post(url) {
        return res(url, 200, GENERIC_500);
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, false);
    assert.equal(r.raw, true);
    assert.equal(r.meta?.skipNotify, "1");
  });

  it("uses the action id provided by the engine without fetching the page", async () => {
    let capturedAction = "";
    let fetched = 0;
    const http: IHttpClient = {
      async get() {
        fetched++;
        throw new Error("should not fetch");
      },
      async post(_url, opts?: HttpRequestOptions) {
        capturedAction = opts?.headers?.["next-action"] ?? "";
        return res("https://t.test/", 500, VULN_FIXTURE);
      },
    };
    const m = match();
    const h = { ...hit(m), extra: { nextActionId: "ab12cd34ef5678ab90cd12ef34ab56cd" } };
    const r = await new React2ShellHandler(http).validate(h, m, [m]);
    assert.equal(r.valid, true);
    assert.equal(fetched, 0);
    assert.equal(capturedAction, "ab12cd34ef5678ab90cd12ef34ab56cd");
  });

  it("extracts an action id from the page when the engine did not provide one", async () => {
    let capturedAction = "";
    const page = `<html><body><input type="hidden" name="$ACTION_ID_cafebabecafebabecafebabecafebabe"/></body></html>`;
    const http: IHttpClient = {
      async get(url) {
        return res(url, 200, page);
      },
      async post(_url, opts?: HttpRequestOptions) {
        capturedAction = opts?.headers?.["next-action"] ?? "";
        return res("https://t.test/", 500, VULN_FIXTURE);
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, true);
    assert.equal(capturedAction, "cafebabecafebabecafebabecafebabe");
  });

  it("keeps the fallback id when the page fetch fails", async () => {
    let capturedAction = "";
    const http: IHttpClient = {
      async get() {
        throw new Error("boom");
      },
      async post(_url, opts?: HttpRequestOptions) {
        capturedAction = opts?.headers?.["next-action"] ?? "";
        return res("https://t.test/", 500, VULN_FIXTURE);
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, true);
    assert.equal(capturedAction, "r2s-probe");
  });

  it("skips notification when the request fails", async () => {
    const http: IHttpClient = {
      async get(url) {
        throw new Error("no get");
      },
      async post() {
        throw new Error("ECONNREFUSED");
      },
    };
    const m = match();
    const r = await new React2ShellHandler(http).validate(hit(m), m, [m]);
    assert.equal(r.valid, false);
    assert.equal(r.raw, true);
    assert.equal(r.meta?.skipNotify, "1");
    assert.match(r.error ?? "", /ECONNREFUSED/);
  });

  it("e2e local: le multipart envoyé est parsable et le verdict est vulnérable", async () => {
    let receivedRef = "";
    let receivedAction = "";
    const server = createServer(async (req, res) => {
      receivedAction = String(req.headers["next-action"] ?? "");
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
      try {
        const form = await new Response(Buffer.concat(chunks), {
          headers: { "content-type": String(req.headers["content-type"] ?? "") },
        }).formData();
        receivedRef = String(form.get("$ACTION_REF_0") ?? "");
      } catch {
        receivedRef = "<multipart parse error>";
      }
      res.statusCode = 500;
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(VULN_FIXTURE);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      const config = {
        get: () => ({}),
        patterns: () => ({ credentials: {}, discovery: {} }),
        resolveBudget: () => 5000,
      } as unknown as IConfigProvider;
      const logger: ILogger = { info() {}, warn() {}, error() {} };
      const client = new HttpClient(config, logger);
      const origin = `http://127.0.0.1:${port}`;
      const m: PatternMatch = {
        service: "react2shell",
        value: origin,
        context: "__NEXT_DATA__",
        lineNumber: 0,
        patternName: "nextjs",
      };
      const h: RawHit = {
        source: "vuln",
        url: `${origin}/`,
        origin,
        matches: [m],
        contentSnippet: m.context,
      };
      const r = await new React2ShellHandler(client).validate(h, m, [m]);
      assert.equal(r.valid, true);
      assert.equal(r.meta?.version, "19.0.0");
      assert.equal(receivedAction, "r2s-probe");
      assert.equal(receivedRef, '["", null]');
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
