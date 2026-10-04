import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { collectBotTokens, parseRetryAfter, TelegramBotPool } from "./bot-pool.js";

describe("TelegramBotPool", () => {
  it("collects unique tokens from botToken + botTokens", () => {
    const tokens = collectBotTokens({
      botToken: "a:1",
      botTokens: ["a:1", "b:2", "", "c:3"],
    });
    assert.deepEqual(tokens, ["a:1", "b:2", "c:3"]);
  });

  it("rotates across ready bots", () => {
    const pool = new TelegramBotPool(["a", "b", "c"]);
    assert.equal(pool.nextReady(), "a");
    assert.equal(pool.nextReady(), "b");
    assert.equal(pool.nextReady(), "c");
    assert.equal(pool.nextReady(), "a");
  });

  it("skips a cooling bot on 429", () => {
    const pool = new TelegramBotPool(["a", "b", "c"]);
    pool.markCooling("a", 60);
    const first = pool.nextReady();
    const second = pool.nextReady();
    assert.equal(first === "a", false);
    assert.equal(second === "a", false);
    assert.equal(new Set([first, second]).size, 2);
  });

  it("parses Telegram retry_after", () => {
    assert.equal(parseRetryAfter({ parameters: { retry_after: 12 } }), 12);
    assert.equal(parseRetryAfter({}, 3), 3);
  });
});
