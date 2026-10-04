import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { HttpResponse, IHttpClient, PatternMatch, RawHit } from "@scanner/core";
import { BitbucketHandler, GitBucketHandler, GitLabHandler } from "./git-forges.js";

function res(url: string, status: number, text = "", headers: Record<string, string> = {}): HttpResponse {
  return { url, status, headers, body: Buffer.from(text), text };
}

function hit(over: Partial<RawHit> & Pick<RawHit, "matches">): RawHit {
  return {
    source: "path",
    url: "https://t.test/.env",
    origin: "https://t.test",
    path: "/.env",
    ...over,
  };
}

const token: PatternMatch = {
  service: "gitlab",
  value: "glpat-abcdefghijklmnopqrstuvwx",
  context: "GITLAB_TOKEN=glpat-abcdefghijklmnopqrstuvwx",
  lineNumber: 1,
  patternName: "glpat",
};

describe("GitLabHandler", () => {
  it("skips placeholder tokens", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        return res(url, 500);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new GitLabHandler(http);
    const r = await h.validate(
      hit({ matches: [{ ...token, value: "changeme" }] }),
      { ...token, value: "changeme" },
      [],
    );
    assert.equal(r.meta?.skipNotify, "1");
  });

  it("fills identity from /api/v4/user", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/api/v4/user")) {
          return res(url, 200, JSON.stringify({ username: "alice", name: "Alice", email: "a@x.test", is_admin: false }));
        }
        if (url.includes("/api/v4/projects")) {
          return res(
            url,
            200,
            JSON.stringify([
              { path_with_namespace: "acme/app", visibility: "private" },
              { path_with_namespace: "acme/www", visibility: "public" },
            ]),
            { "x-total": "3" },
          );
        }
        return res(url, 404);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new GitLabHandler(http);
    const r = await h.validate(hit({ matches: [token] }), token, [token]);
    assert.equal(r.valid, true);
    assert.equal(r.meta?.identity, "alice (Alice) | a@x.test");
    assert.equal(r.meta?.host, "gitlab.com");
    assert.match(r.meta?.recentRepos ?? "", /acme\/app/);
  });

  it("harvests .env files from GitLab projects", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.endsWith("/api/v4/user")) {
          return res(url, 200, JSON.stringify({ username: "alice", name: "Alice" }));
        }
        if (url.includes("/repository/tree")) {
          return res(url, 200, JSON.stringify([{ type: "blob", path: ".env" }]));
        }
        if (url.includes("/repository/files/") && url.includes("/raw")) {
          return res(url, 200, "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n");
        }
        if (url.includes("/api/v4/projects")) {
          return res(url, 200, JSON.stringify([{ path_with_namespace: "acme/app", visibility: "private" }]));
        }
        return res(url, 404);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new GitLabHandler(http);
    const r = await h.validate(hit({ matches: [token] }), token, [token]);
    assert.equal(r.valid, true);
    assert.equal(r.harvested?.length, 1);
    assert.equal(r.harvested?.[0].filePath, ".env");
    assert.equal(r.harvested?.[0].forge, "gitlab");
  });

  it("probes origin when the leak is a GitLab path", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.startsWith("https://git.acme.test/api/v4/user")) {
          return res(url, 200, JSON.stringify({ username: "bob", name: "Bob" }));
        }
        if (url.includes("gitlab.com")) return res(url, 401);
        return res(url, 404);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new GitLabHandler(http);
    const r = await h.validate(
      hit({
        url: "https://git.acme.test/.gitlab-ci.yml",
        origin: "https://git.acme.test",
        path: "/.gitlab-ci.yml",
        matches: [token],
      }),
      token,
      [token],
    );
    assert.equal(r.valid, true);
    assert.equal(r.meta?.host, "git.acme.test");
  });
});

const bbToken: PatternMatch = {
  service: "bitbucket",
  value: "ATBBabcdefghijklmnopqrstuvwxyz12",
  context: "BITBUCKET_TOKEN=ATBBabcdefghijklmnopqrstuvwxyz12",
  lineNumber: 1,
  patternName: "atbb",
};

describe("BitbucketHandler", () => {
  it("fills identity from /2.0/user", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url.includes("/2.0/user") && !url.includes("repositories")) {
          return res(url, 200, JSON.stringify({ username: "bob", display_name: "Bob" }));
        }
        if (url.includes("/2.0/repositories")) {
          return res(
            url,
            200,
            JSON.stringify({
              size: 2,
              values: [
                { full_name: "acme/app", is_private: true },
                { full_name: "acme/www", is_private: false },
              ],
            }),
          );
        }
        return res(url, 404);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new BitbucketHandler(http);
    const r = await h.validate(hit({ matches: [bbToken] }), bbToken, [bbToken]);
    assert.equal(r.valid, true);
    assert.equal(r.meta?.identity, "bob (Bob)");
    assert.match(r.meta?.recentRepos ?? "", /acme\/app/);
  });
});

const gbToken: PatternMatch = {
  service: "gitbucket",
  value: "abcdefghijklmnopqrstuvwxyz12",
  context: "GITBUCKET_TOKEN=abcdefghijklmnopqrstuvwxyz12\nGITBUCKET_URL=https://gb.acme.test",
  lineNumber: 1,
  patternName: "gitbucket.token",
};

describe("GitBucketHandler", () => {
  it("fills identity from /api/v3/user", async () => {
    const http: IHttpClient = {
      async get(url: string) {
        if (url === "https://gb.acme.test/api/v3/user") {
          return res(url, 200, JSON.stringify({ login: "cara", name: "Cara", public_repos: 4, total_private_repos: 1 }));
        }
        return res(url, 404);
      },
      async post(url: string) {
        return this.get(url);
      },
    };
    const h = new GitBucketHandler(http);
    const r = await h.validate(hit({ matches: [gbToken] }), gbToken, [gbToken]);
    assert.equal(r.valid, true);
    assert.equal(r.meta?.identity, "cara (Cara)");
    assert.equal(r.meta?.host, "gb.acme.test");
  });
});
