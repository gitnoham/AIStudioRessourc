import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { HttpResponse, IHttpClient, PatternMatch } from "@scanner/core";
import { extractXml, extractXmlList, awsOk, awsDenied } from "./aws-api.js";
import { formatAwsPermLines } from "./aws-handler.js";
import { githubCardMeta } from "./github-meta.js";
import { GitHubHandler } from "./handlers.js";

function res(url: string, status: number, text: string, headers: Record<string, string> = {}): HttpResponse {
  return { url, status, headers, body: Buffer.from(text), text };
}

describe("aws xml", () => {
  it("extracts STS identity fields", () => {
    const xml = "<GetCallerIdentityResponse><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/ses</Arn></GetCallerIdentityResponse>";
    assert.equal(extractXml(xml, "Account"), "123456789012");
    assert.equal(extractXml(xml, "Arn"), "arn:aws:iam::123456789012:user/ses");
  });

  it("lists S3 bucket names", () => {
    const xml = "<ListAllMyBucketsResult><Buckets><Bucket><Name>alpha</Name></Bucket><Bucket><Name>beta</Name></Bucket></Buckets></ListAllMyBucketsResult>";
    assert.deepEqual(extractXmlList(xml, "Name"), ["alpha", "beta"]);
    assert.equal(awsOk(xml, "<ListAllMyBucketsResult"), true);
    assert.equal(awsDenied("<Error><Code>AccessDenied</Code></Error>"), true);
  });
});

describe("formatAwsPermLines", () => {
  it("splits active vs denied like the old scanner", () => {
    const text = formatAwsPermLines([
      { service: "SES", action: "RÉSUMÉ", ok: true, details: "🟢 ACTIVÉ | 1 région(s) | Quota total: 200/jour | 1 sender(s) | 0 domaine(s)" },
      { service: "S3", action: "ListBuckets", ok: true, details: "2 bucket(s): a, b" },
      { service: "EC2", action: "DescribeInstances", ok: false, details: "" },
    ]);
    assert.match(text, /Permissions Actives:/);
    assert.match(text, /✅ SES \(RÉSUMÉ\):/);
    assert.match(text, /✅ S3 \(ListBuckets\): 2 bucket\(s\): a, b/);
    assert.match(text, /❌ EC2 \(DescribeInstances\)/);
  });
});

describe("githubCardMeta", () => {
  it("fills identity and repo counts from /user/repos when /user is empty", () => {
    const meta = githubCardMeta(
      {},
      "read:org, repo",
      [
        { name: "shop", private: false, owner: { login: "acme" } },
        { name: "secret-app", private: true, owner: { login: "acme" } },
      ],
    );
    assert.equal(meta.identity, "acme");
    assert.equal(meta.publicRepos, "1");
    assert.equal(meta.privateRepos, "1");
    assert.equal(meta.scopes, "read:org, repo");
    assert.match(meta.recentRepos ?? "", /shop/);
    assert.match(meta.recentRepos ?? "", /secret-app 🔒/);
  });

  it("keeps login from /user and still counts private repos listed with repo scope", () => {
    const meta = githubCardMeta(
      { login: "dudaz", name: "Duda", public_repos: 0, total_private_repos: 0, followers: 2 },
      "repo",
      [{ name: "priv", private: true, owner: { login: "dudaz" } }],
    );
    assert.equal(meta.identity, "dudaz (Duda)");
    assert.equal(meta.privateRepos, "1");
    assert.equal(meta.followers, "2");
  });

  it("fills identity from repo full_name when owner is omitted", () => {
    const meta = githubCardMeta({}, "repo", [{ full_name: "dudaz/secret-app", private: true }]);
    assert.equal(meta.identity, "dudaz");
    assert.match(meta.recentRepos ?? "", /secret-app 🔒/);
  });
});

const ghToken: PatternMatch = {
  service: "github",
  value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  context: "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  lineNumber: 1,
  patternName: "ghp",
};

describe("GitHubHandler", () => {
  it("fills identity from GraphQL viewer when /user has no login", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/user") && !url.includes("repos")) {
          return res(url, 200, "{}");
        }
        if (url.includes("/user/repos")) {
          return res(url, 200, "[]");
        }
        return res(url, 404, "");
      },
      async post(url: string) {
        if (url.includes("/graphql")) {
          return res(url, 200, JSON.stringify({ data: { viewer: { login: "dudaz", name: "Duda" } } }));
        }
        return res(url, 404, "");
      },
    };
    const r = await new GitHubHandler(http).validate(
      { source: "path", url: "https://t.test/.env", origin: "https://t.test", path: "/.env", matches: [ghToken] },
      ghToken,
    );
    assert.equal(r.valid, true);
    assert.equal(r.meta?.identity, "dudaz (Duda)");
  });

  it("harvests repo files after a valid token", async () => {
    const content = Buffer.from("AKIAAAAAAAAAAAAAAAAA\n").toString("base64");
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/user") && !url.includes("repos")) {
          return res(url, 200, JSON.stringify({ login: "alice" }));
        }
        if (url.includes("/user/repos")) {
          return res(url, 200, JSON.stringify([{ full_name: "alice/app", name: "app", owner: { login: "alice" } }]));
        }
        if (url.includes("/git/trees/HEAD")) {
          return res(url, 200, JSON.stringify({ tree: [{ path: ".env", type: "blob", size: 40 }] }));
        }
        if (url.includes("/contents/.env")) {
          return res(url, 200, JSON.stringify({ encoding: "base64", content, html_url: "https://github.com/alice/app/blob/1/.env" }));
        }
        return res(url, 404, "");
      },
      async post(url: string) {
        return res(url, 404, "");
      },
    };
    const r = await new GitHubHandler(http).validate(
      { source: "path", url: "https://t.test/.env", origin: "https://t.test", path: "/.env", matches: [ghToken] },
      ghToken,
    );
    assert.equal(r.valid, true);
    assert.equal(r.meta?.crawled, "1");
    assert.equal(r.harvested?.length, 1);
    assert.equal(r.harvested?.[0].filePath, ".env");
  });
});
