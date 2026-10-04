import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractHarvestMatches, harvestGitHubRepos, harvestedToHits, shouldScanGitHubBlob } from "./github-harvest.js";
function res(url, status, text) {
    return { url, status, headers: {}, body: Buffer.from(text), text };
}
describe("github harvest", () => {
    it("scans README and .env like the old crawler", () => {
        assert.equal(shouldScanGitHubBlob("README.md", 1200), true);
        assert.equal(shouldScanGitHubBlob(".env", 80), true);
        assert.equal(shouldScanGitHubBlob("photo.png", 100), false);
        assert.equal(shouldScanGitHubBlob(".env", 300 * 1024), false);
        assert.equal(shouldScanGitHubBlob("node_modules/.env", 80), false);
        assert.equal(shouldScanGitHubBlob(".env.smtp", 80), true);
    });
    it("extracts AKIA from file content", () => {
        const matches = extractHarvestMatches("AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\nAWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz0123456789+/AB");
        assert.equal(matches.some((m) => m.service === "aws" && m.value.startsWith("AKIA")), true);
    });
    it("crawls a repo tree and emits a harvested file", async () => {
        const content = Buffer.from("AKIAAAAAAAAAAAAAAAAA\n").toString("base64");
        const http = {
            async get(url) {
                if (url.includes("/git/trees/HEAD")) {
                    return res(url, 200, JSON.stringify({ tree: [{ path: "README.md", type: "blob", size: 40 }] }));
                }
                if (url.includes("/contents/README.md")) {
                    return res(url, 200, JSON.stringify({
                        encoding: "base64",
                        content,
                        html_url: "https://github.com/makethunder/awsudo/blob/abc/README.md",
                        sha: "abc",
                    }));
                }
                return res(url, 404, "");
            },
            async post(url) {
                return this.get(url);
            },
        };
        const files = await harvestGitHubRepos(http, {}, [{ full_name: "makethunder/awsudo", name: "awsudo" }]);
        assert.equal(files.length, 1);
        assert.equal(files[0].fullName, "makethunder/awsudo");
        assert.equal(files[0].filePath, "README.md");
        assert.equal(files[0].htmlUrl.includes("github.com/makethunder/awsudo/blob/"), true);
        assert.equal(files[0].matches.some((m) => m.value.startsWith("AKIA")), true);
    });
    it("turns a harvested .env into one real hit per service", () => {
        const matches = extractHarvestMatches("STRIPE_SECRET=sk_test_5103erp2Y5xYsh7PXGr8h1vKRzJDD9\nSENDGRID_API_KEY=SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        const hits = harvestedToHits([
            {
                fullName: "acme/app",
                filePath: ".env.development",
                content: "x",
                htmlUrl: "https://github.com/acme/app/blob/1/.env.development",
                matches,
                summary: "",
            },
        ]);
        assert.equal(hits.some((h) => h.path === "gh-harvest:acme/app/.env.development"), true);
        assert.equal(hits.some((h) => h.matches.every((m) => m.service === "stripe")), true);
        assert.equal(hits.some((h) => h.matches.every((m) => m.service === "sendgrid")), true);
    });
    it("harvests Gmail SMTP from a Laravel .env instead of tagging it SendGrid", () => {
        const env = [
            "MAIL_HOST=smtp.gmail.com",
            "MAIL_PORT=587",
            "MAIL_USERNAME=sarwanjploft@gmail.com",
            "MAIL_PASSWORD=dmyf awlv gwpx yvbt",
            "MAIL_ENCRYPTION=tls",
        ].join("\n");
        const matches = extractHarvestMatches(env);
        assert.equal(matches.some((m) => m.service === "smtp" && m.value === "smtp.gmail.com"), true);
        assert.equal(matches.some((m) => m.service === "sendgrid"), false);
    });
    it("pulls GitLab and Bitbucket tokens out of harvested files", () => {
        const matches = extractHarvestMatches("GITLAB_TOKEN=glpat-abcdefghijklmnopqrstuvwx\nBITBUCKET_TOKEN=ATATT3xFfGF0abcdefghijklmnopqrstuvwxyz012345");
        assert.equal(matches.some((m) => m.service === "gitlab" && m.value.startsWith("glpat-")), true);
        assert.equal(matches.some((m) => m.service === "bitbucket" && m.value.startsWith("ATATT")), true);
    });
    it("tags GitLab harvest hits as gl-harvest", () => {
        const hits = harvestedToHits([
            {
                fullName: "acme/app",
                filePath: ".env",
                content: "x",
                htmlUrl: "https://gitlab.com/acme/app/-/blob/HEAD/.env",
                matches: [{ service: "aws", value: "AKIAAAAAAAAAAAAAAAAA", context: "", lineNumber: 1, patternName: "harvest.AKIA" }],
                summary: "",
                forge: "gitlab",
            },
        ]);
        assert.equal(hits[0].path, "gl-harvest:acme/app/.env");
        assert.equal(hits[0].origin, "https://gitlab.com");
    });
});
