import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type AddressInfo } from "node:net";
import { authenticateSmtp, smtpPortOrder } from "./smtp-probe.js";

function listenFake(handler: (line: string, write: (s: string) => void) => void): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createServer((sock) => {
    sock.write("220 test ESMTP\r\n");
    let buf = "";
    sock.on("data", (chunk) => {
      buf += chunk.toString();
      while (buf.includes("\r\n")) {
        const i = buf.indexOf("\r\n");
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        handler(line, (s) => sock.write(s));
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
          }),
      });
    });
  });
}

describe("smtpPortOrder", () => {
  it("tries preferred then 587/465/25", () => {
    assert.deepEqual(smtpPortOrder(587, "tls"), [587, 465, 25]);
    assert.deepEqual(smtpPortOrder(587, "ssl"), [465, 587, 25]);
    assert.deepEqual(smtpPortOrder(2525, "tls"), [2525, 587, 465, 25]);
  });
});

describe("authenticateSmtp", () => {
  it("returns ok after AUTH LOGIN 235", async () => {
    const userB64 = Buffer.from("user", "utf8").toString("base64");
    const passB64 = Buffer.from("secret12", "utf8").toString("base64");
    const srv = await listenFake((line, write) => {
      if (/^EHLO|^HELO/i.test(line)) write("250-test\r\n250 AUTH LOGIN PLAIN\r\n");
      else if (/^AUTH LOGIN/i.test(line)) write("334 VXNlcm5hbWU6\r\n");
      else if (line === userB64) write("334 UGFzc3dvcmQ6\r\n");
      else if (line === passB64) write("235 Authentication succeeded\r\n");
      else if (/^QUIT/i.test(line)) write("221 bye\r\n");
    });
    try {
      const r = await authenticateSmtp({
        host: "127.0.0.1",
        user: "user",
        pass: "secret12",
        preferredPort: srv.port,
        encryption: "tls",
        timeoutMs: 2000,
      });
      assert.equal(r.ok, true);
      if (r.ok) assert.equal(r.port, srv.port);
    } finally {
      await srv.close();
    }
  });

  it("returns auth fail on 535", async () => {
    const userB64 = Buffer.from("user", "utf8").toString("base64");
    const passB64 = Buffer.from("wrong", "utf8").toString("base64");
    const srv = await listenFake((line, write) => {
      if (/^EHLO|^HELO/i.test(line)) write("250 AUTH LOGIN\r\n");
      else if (/^AUTH LOGIN/i.test(line)) write("334 VXNlcm5hbWU6\r\n");
      else if (line === userB64) write("334 UGFzc3dvcmQ6\r\n");
      else if (line === passB64) write("535 5.7.8 Error: authentication failed\r\n");
      else if (/^QUIT/i.test(line)) write("221 bye\r\n");
    });
    try {
      const r = await authenticateSmtp({
        host: "127.0.0.1",
        user: "user",
        pass: "wrong",
        preferredPort: srv.port,
        timeoutMs: 2000,
      });
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.kind, "auth");
    } finally {
      await srv.close();
    }
  });

  it("returns connect when nothing listens", async () => {
    const r = await authenticateSmtp({
      host: "127.0.0.1",
      user: "user",
      pass: "secret12",
      preferredPort: 1,
      ports: [1],
      timeoutMs: 500,
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.kind, "connect");
  });
});
