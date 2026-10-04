import { isIP } from "node:net";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { constants as cryptoConstants } from "node:crypto";
import { lookup } from "node:dns/promises";
export async function probeSmtpPorts(host, ports, timeoutMs) {
    let ip = host;
    try {
        ip = (await lookup(host)).address;
    }
    catch {
        /* keep hostname */
    }
    const open = [];
    const errors = [];
    for (const port of ports) {
        const err = await tcpDial(host, port, timeoutMs);
        if (err)
            errors.push(`dial tcp ${ip}:${port}: ${err}`);
        else
            open.push(port);
    }
    return { ip, open, errors };
}
export async function authenticateSmtp(opts) {
    const ports = opts.ports ?? smtpPortOrder(opts.preferredPort, opts.encryption);
    const errors = [];
    for (const port of ports) {
        const r = await authOnPort(opts.host, port, opts.user, opts.pass, opts.timeoutMs);
        if (r.kind === "ok")
            return { ok: true, port };
        if (r.kind === "auth")
            return { ok: false, kind: "auth", port, reply: r.reply };
        errors.push(r.error);
    }
    return { ok: false, kind: "connect", errors };
}
export function smtpPortOrder(preferred, encryption) {
    const p = preferred > 0 && preferred < 65536 ? preferred : 587;
    const ssl = /ssl|smtps/i.test(encryption ?? "") || p === 465;
    const rest = ssl ? [465, p, 587, 25] : [p, 587, 465, 25];
    return [...new Set(rest.filter((x) => x > 0 && x < 65536))];
}
async function authOnPort(host, port, user, pass, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    let sock = null;
    try {
        sock = port === 465 ? await tlsDial(host, port, deadline) : await plainDial(host, port, deadline);
        const session = { sock, buf: "" };
        const banner = await readReply(session, deadline);
        if (banner.code !== 220)
            return { kind: "connect", error: `banner ${banner.code}` };
        let ehlo = await smtpCmd(session, `EHLO dreks.local`, deadline);
        if (ehlo.code >= 500)
            ehlo = await smtpCmd(session, `HELO dreks.local`, deadline);
        if (port !== 465 && /STARTTLS/i.test(ehlo.text)) {
            const st = await smtpCmd(session, "STARTTLS", deadline);
            if (st.code === 220) {
                sock = await tlsUpgrade(sock, host, deadline);
                session.sock = sock;
                session.buf = "";
                ehlo = await smtpCmd(session, `EHLO dreks.local`, deadline);
            }
        }
        const auth = await tryAuth(session, ehlo.text, user, pass, deadline);
        await smtpCmd(session, "QUIT", Math.min(deadline, Date.now() + 1500)).catch(() => undefined);
        return auth;
    }
    catch (err) {
        const msg = err.message || "i/o timeout";
        return { kind: "connect", error: `dial tcp ${host}:${port}: ${msg}` };
    }
    finally {
        sock?.destroy();
    }
}
async function tryAuth(session, ehlo, user, pass, deadline) {
    const methods = ehlo.toUpperCase();
    const loginOk = /AUTH[^\n]*LOGIN/.test(methods) || !/AUTH[^\n]*/.test(methods);
    const plainOk = /AUTH[^\n]*PLAIN/.test(methods);
    if (loginOk) {
        const r = await authLogin(session, user, pass, deadline);
        if (r)
            return r;
    }
    if (plainOk || !loginOk) {
        const r = await authPlain(session, user, pass, deadline);
        if (r)
            return r;
    }
    return { kind: "connect", error: "AUTH not advertised" };
}
async function authLogin(session, user, pass, deadline) {
    const start = await smtpCmd(session, "AUTH LOGIN", deadline);
    if (start.code === 503 || start.code === 504)
        return null;
    if (start.code === 530)
        return { kind: "connect", error: start.text.slice(0, 180) };
    if (start.code === 535 || start.code === 534) {
        return { kind: "auth", reply: start.text.slice(0, 180) };
    }
    if (start.code !== 334)
        return null;
    const u = await smtpCmd(session, Buffer.from(user, "utf8").toString("base64"), deadline);
    if (u.code === 535 || u.code === 534)
        return { kind: "auth", reply: u.text.slice(0, 180) };
    if (u.code !== 334)
        return { kind: "auth", reply: u.text.slice(0, 180) };
    const p = await smtpCmd(session, Buffer.from(pass, "utf8").toString("base64"), deadline);
    if (p.code === 235)
        return { kind: "ok" };
    if (p.code >= 500)
        return { kind: "auth", reply: p.text.slice(0, 180) };
    return { kind: "auth", reply: p.text.slice(0, 180) };
}
async function authPlain(session, user, pass, deadline) {
    const payload = Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64");
    const r = await smtpCmd(session, `AUTH PLAIN ${payload}`, deadline);
    if (r.code === 235)
        return { kind: "ok" };
    if (r.code === 504)
        return null;
    if (r.code >= 500)
        return { kind: "auth", reply: r.text.slice(0, 180) };
    return { kind: "auth", reply: r.text.slice(0, 180) };
}
async function smtpCmd(session, line, deadline) {
    session.sock.write(`${line}\r\n`);
    return readReply(session, deadline);
}
async function readReply(session, deadline) {
    const lines = [];
    while (Date.now() < deadline) {
        if (!session.buf.includes("\n")) {
            session.buf += await readChunk(session.sock, deadline);
            continue;
        }
        const nl = session.buf.indexOf("\n");
        const line = session.buf.slice(0, nl).replace(/\r$/, "");
        session.buf = session.buf.slice(nl + 1);
        const m = line.match(/^(\d{3})([ -])(.*)$/);
        if (!m)
            continue;
        lines.push(m[3] ?? "");
        if (m[2] === " ")
            return { code: Number(m[1]), text: lines.join("\n") };
    }
    throw new Error("i/o timeout");
}
function readChunk(sock, deadline) {
    const ms = Math.max(1, deadline - Date.now());
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error("i/o timeout"));
        }, ms);
        const onData = (buf) => {
            cleanup();
            resolve(buf.toString("utf8"));
        };
        const onErr = (err) => {
            cleanup();
            reject(err);
        };
        const onEnd = () => {
            cleanup();
            reject(new Error("connection closed"));
        };
        const cleanup = () => {
            clearTimeout(timer);
            sock.off("data", onData);
            sock.off("error", onErr);
            sock.off("end", onEnd);
        };
        sock.once("data", onData);
        sock.once("error", onErr);
        sock.once("end", onEnd);
    });
}
function remaining(deadline) {
    return Math.max(1, deadline - Date.now());
}
function plainDial(host, port, deadline) {
    return new Promise((resolve, reject) => {
        const sock = netConnect({ host, port });
        const timer = setTimeout(() => {
            sock.destroy();
            reject(new Error("i/o timeout"));
        }, remaining(deadline));
        sock.once("connect", () => {
            clearTimeout(timer);
            resolve(sock);
        });
        sock.once("error", (err) => {
            clearTimeout(timer);
            sock.destroy();
            reject(new Error(err.code === "ECONNREFUSED" ? "connect: connection refused" : err.message || "i/o timeout"));
        });
    });
}
function tlsDial(host, port, deadline) {
    return new Promise((resolve, reject) => {
        const sock = tlsConnect(tlsOpts(host, port));
        const timer = setTimeout(() => {
            sock.destroy();
            reject(new Error("i/o timeout"));
        }, remaining(deadline));
        sock.once("secureConnect", () => {
            clearTimeout(timer);
            resolve(sock);
        });
        sock.once("error", (err) => {
            clearTimeout(timer);
            sock.destroy();
            reject(err);
        });
    });
}
function tlsUpgrade(socket, host, deadline) {
    return new Promise((resolve, reject) => {
        const sock = tlsConnect(tlsOpts(host, undefined, socket));
        const timer = setTimeout(() => {
            sock.destroy();
            reject(new Error("i/o timeout"));
        }, remaining(deadline));
        sock.once("secureConnect", () => {
            clearTimeout(timer);
            resolve(sock);
        });
        sock.once("error", (err) => {
            clearTimeout(timer);
            sock.destroy();
            reject(err);
        });
    });
}
function tlsOpts(host, port, socket) {
    const ip = isIP(host) > 0;
    return {
        host,
        port,
        socket,
        minVersion: "TLSv1",
        rejectUnauthorized: false,
        servername: ip ? "" : host,
        secureOptions: cryptoConstants.SSL_OP_LEGACY_SERVER_CONNECT,
    };
}
function tcpDial(host, port, ms) {
    return new Promise((resolve) => {
        const sock = netConnect({ host, port });
        const timer = setTimeout(() => {
            sock.destroy();
            resolve("i/o timeout");
        }, ms);
        sock.once("connect", () => {
            clearTimeout(timer);
            sock.destroy();
            resolve(null);
        });
        sock.once("error", (err) => {
            clearTimeout(timer);
            sock.destroy();
            if (err.code === "ETIMEDOUT")
                resolve("i/o timeout");
            else if (err.code === "ECONNREFUSED")
                resolve("connect: connection refused");
            else
                resolve(err.message || "i/o timeout");
        });
    });
}
