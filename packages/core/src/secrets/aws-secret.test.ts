import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isAwsAccessKey, isValidAwsSecretKey, isVendorSecretPath } from "./aws-secret.js";

describe("isValidAwsSecretKey", () => {
  it("accepts a random-looking 40-char secret", () => {
    assert.equal(isValidAwsSecretKey("abcdefghijklmnopqrstuvwxyz0123456789+/AB"), true);
  });

  it("rejects the encoded this_is_fake joke (full and 40-char prefix)", () => {
    const full = "dGhpc19pc19mYWtlX3lvdV9hYnNvbHV0ZV9kb25rZXlfMTI5MzQ1NzA0Ng==";
    assert.equal(isValidAwsSecretKey(full), false);
    assert.equal(isValidAwsSecretKey(full.slice(0, 40)), false);
  });

  it("rejects recaptcha and access-key shaped values", () => {
    assert.equal(isValidAwsSecretKey("6LdMYFoiAAAAABT4bK44uh3FrouPMb9ElGRksUiq"), false);
    assert.equal(isAwsAccessKey("AKIA49739FB9BB068680"), true);
  });

  it("flags node_modules env paths as vendor junk, not /.env.example", () => {
    assert.equal(isVendorSecretPath("/node_modules/.env"), true);
    assert.equal(isVendorSecretPath("/.env"), false);
    assert.equal(isVendorSecretPath("/.env.example"), false);
    assert.equal(isVendorSecretPath("/laravel/.env.example"), false);
  });
});
