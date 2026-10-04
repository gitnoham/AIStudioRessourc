import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IEventBus, IHttpClient, ILogger, INotifier } from "@scanner/core";
import { ValidatorService } from "./index.js";

function makeService(persistFile: string): ValidatorService {
  const http: IHttpClient = {
    async get() {
      throw new Error("unused");
    },
    async post() {
      throw new Error("unused");
    },
  };
  const notifier: INotifier = {
    async startScan() {},
    async updateProgress() {},
    async sendHit() {},
    async sendFinalStats() {},
  };
  const bus: IEventBus = { on: () => () => undefined, emit: () => undefined };
  const logger: ILogger = { info() {}, warn() {}, error() {} };
  return new ValidatorService(http, notifier, bus, logger, 0, [], persistFile);
}

describe("seen_keys persistence (clés volatiles)", () => {
  it("recharge les clés persistées mais ignore les clés smtp/react2shell", () => {
    const dir = mkdtempSync(join(tmpdir(), "scan-seen-"));
    const file = join(dir, "seen_keys.json");
    try {
      writeFileSync(
        file,
        [
          "github:ghp_tok123",
          "sent:github:ghp_tok123",
          "smtp:mail.example.com:user@example.com:p@ss",
          "sent:smtp:mail.example.com:user@example.com:p@ss",
          "smtp-ok:mail.example.com:user@example.com",
          "sent:smtp-acct:mail.example.com:user@example.com",
          "react2shell:https://site.example",
          "sent:react2shell:https://site.example",
        ].join("\n"),
      );
      const svc = makeService(file);
      const seen = (svc as unknown as { seen: Set<string> }).seen;
      assert.ok(seen.has("github:ghp_tok123"));
      assert.ok(seen.has("sent:github:ghp_tok123"));
      assert.ok(!seen.has("smtp:mail.example.com:user@example.com:p@ss"));
      assert.ok(!seen.has("sent:smtp:mail.example.com:user@example.com:p@ss"));
      assert.ok(!seen.has("smtp-ok:mail.example.com:user@example.com"));
      assert.ok(!seen.has("sent:smtp-acct:mail.example.com:user@example.com"));
      assert.ok(!seen.has("react2shell:https://site.example"));
      assert.ok(!seen.has("sent:react2shell:https://site.example"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("ne persiste pas les clés volatiles (re-test à chaque run)", () => {
    const dir = mkdtempSync(join(tmpdir(), "scan-seen-"));
    const file = join(dir, "seen_keys.json");
    try {
      const svc = makeService(file);
      (svc as unknown as { persistKeys(keys: string[]): void }).persistKeys([
        "github:ghp_tok456",
        "smtp:mail.example.com:user@example.com:p@ss",
        "sent:smtp:mail.example.com:user@example.com:p@ss",
        "smtp-ok:mail.example.com:user@example.com",
        "sent:smtp-acct:mail.example.com:user@example.com",
        "react2shell:https://site.example",
        "sent:react2shell:https://site.example",
      ]);
      const text = readFileSync(file, "utf8");
      assert.ok(text.includes("github:ghp_tok456"));
      assert.ok(!text.includes("smtp:"));
      assert.ok(!text.includes("smtp-ok:"));
      assert.ok(!text.includes("smtp-acct:"));
      assert.ok(!text.includes("react2shell:"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
