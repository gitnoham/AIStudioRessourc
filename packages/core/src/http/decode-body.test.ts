import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { decodeHttpBody } from "./decode-body.js";

describe("decodeHttpBody", () => {
  it("gunzips GitHub-style compressed JSON", () => {
    const json = '{"login":"dudaz","name":"Duda"}';
    const gz = gzipSync(json);
    assert.equal(decodeHttpBody(gz, "gzip"), json);
    assert.equal(decodeHttpBody(gz), json);
  });

  it("leaves already-decoded JSON alone even if content-encoding says gzip", () => {
    const json = '{"login":"dudaz"}';
    assert.equal(decodeHttpBody(Buffer.from(json), "gzip"), json);
  });
});
