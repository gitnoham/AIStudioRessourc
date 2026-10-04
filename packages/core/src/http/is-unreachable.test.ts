import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isUnreachableError, isDeadHostError, isTlsPlaintextError, isTlsHandshakeError } from "./is-unreachable.js";

describe("isUnreachableError", () => {
  it("treats refused / missing hosts as dead", () => {
    assert.equal(isUnreachableError(new Error("connect ECONNREFUSED 1.2.3.4:443")), true);
    assert.equal(isUnreachableError(new Error("getaddrinfo ENOTFOUND nope.invalid")), true);
    assert.equal(isUnreachableError(new Error("Connect Timeout Error")), true);
    const timeout = new Error("The operation was aborted due to timeout");
    timeout.name = "TimeoutError";
    assert.equal(isUnreachableError(timeout), true);
    const abort = new Error("This operation was aborted");
    abort.name = "AbortError";
    assert.equal(isUnreachableError(abort), true);
  });

  it("only treats DNS / refused as a dead host — not HTTP timeout or 403", () => {
    assert.equal(isDeadHostError(new Error("connect ECONNREFUSED 1.2.3.4:443")), true);
    assert.equal(isDeadHostError(new Error("getaddrinfo ENOTFOUND nope.invalid")), true);
    assert.equal(isDeadHostError(new Error("Connect Timeout Error")), true);
    const timeout = new Error("The operation was aborted due to timeout");
    timeout.name = "TimeoutError";
    assert.equal(isDeadHostError(timeout), false);
    assert.equal(isDeadHostError(new Error("HTTP 403")), false);
    const abort = new Error("This operation was aborted");
    abort.name = "AbortError";
    assert.equal(isDeadHostError(abort), false);
  });

  it("does not skip HTTP 404 or TLS pages", () => {
    assert.equal(isUnreachableError(new Error("HTTP 404")), false);
    assert.equal(isUnreachableError(new Error("unable to verify the first certificate")), false);
  });

  it("treats pool churn and HTTP-on-443 as unreachable, not dead", () => {
    assert.equal(isUnreachableError(new Error("The client is destroyed")), true);
    assert.equal(isDeadHostError(new Error("The client is destroyed")), false);
    assert.equal(
      isUnreachableError(new Error("Client network socket disconnected before secure TLS connection was established")),
      true,
    );
    const ssl = new Error("SSL routines:ssl3_get_record:wrong version number");
    assert.equal(isTlsPlaintextError(ssl), true);
    assert.equal(isUnreachableError(ssl), true);
    assert.equal(isDeadHostError(ssl), false);
    const chunk = new Error("Response does not match the HTTP/1.1 protocol (Invalid character in chunk size)");
    assert.equal(isUnreachableError(chunk), true);
    assert.equal(isDeadHostError(chunk), false);
    const reneg = new Error("SSL routines:final_renegotiate:unsafe legacy renegotiation disabled");
    assert.equal(isUnreachableError(reneg), true);
    assert.equal(isDeadHostError(reneg), false);
  });

  it("treats TLS handshake failures as unreachable, not dead", () => {
    const samples = [
      "SSL routines:ssl_choose_client_version:unsupported protocol",
      "SSL routines:ssl3_read_bytes:tlsv1 unrecognized name",
      "SSL routines:ssl3_read_bytes:tlsv1 alert internal error",
      "SSL routines:ssl3_read_bytes:sslv3 alert handshake failure",
      "SSL routines:ssl3_read_bytes:tlsv1 alert decrypt error",
    ];
    for (const msg of samples) {
      const err = new Error(msg);
      assert.equal(isTlsHandshakeError(err), true, msg);
      assert.equal(isUnreachableError(err), true, msg);
      assert.equal(isDeadHostError(err), false, msg);
    }
    const plaintext = new Error("SSL routines:ssl3_get_record:wrong version number");
    assert.equal(isTlsHandshakeError(plaintext), false);
    assert.equal(isTlsPlaintextError(plaintext), true);
  });
});
