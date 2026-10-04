import { Pool, request } from "undici";
import { setMaxListeners } from "node:events";
import { isIP } from "node:net";
import { constants as cryptoConstants } from "node:crypto";
import { decodeHttpBody } from "./decode-body.js";
import { isClientDestroyedError, isTlsPlaintextError, isUnreachableError } from "./is-unreachable.js";
import { httpsToHttpSamePort, originOf } from "../url/normalize.js";
const EMPTY = Buffer.alloc(0);
const MAX_ORIGIN_POOLS = 4096;
/** Curated pool of real browser User-Agents + matching Sec-CH-UA triples. */
const BROWSER_PROFILES = [
    {
        // Chrome 124 / Windows
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"',
    },
    {
        // Chrome 122 / Windows (older, common)
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="122", "Google Chrome";v="122", "Not-A.Brand";v="24"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"',
    },
    {
        // Edge 124 / Windows
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        secChUa: '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"',
    },
    {
        // Firefox 125 / Windows (no sec-ch-ua — Firefox doesn't send it)
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        secChUa: "",
        secChUaMobile: "",
        secChUaPlatform: "",
    },
    {
        // Chrome 124 / macOS
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"macOS"',
    },
];
/** Rotate between profiles using a deterministic counter for even distribution. */
let _profileIdx = 0;
function nextProfile() {
    const p = BROWSER_PROFILES[_profileIdx % BROWSER_PROFILES.length];
    _profileIdx++;
    return p;
}
/**
 * Chrome TLS cipher suite order (matches Chrome 124 ClientHello).
 * Undici exposes this through the `connect.ciphers` option.
 */
const CHROME_CIPHERS = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
].join(":");
/**
 * Build browser-spoof request headers for a given profile.
 * Returns a minimal set for `curl`-style requests (no browser UA headers).
 *
 * IMPORTANT: This only affects HTTP headers, not the TLS fingerprint.
 * Cloudflare / Akamai bot detection operates at the TLS layer (JA3/JA4)
 * and will still see a Node.js ClientHello.
 */
function impersonateHeaders(impersonate, profile) {
    if (impersonate === "curl") {
        return {
            "user-agent": "curl/8.6.0",
            accept: "*/*",
        };
    }
    const base = {
        "user-agent": profile.ua,
        accept: impersonate === "firefox"
            ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "max-age=0",
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
    };
    if (profile.secChUa) {
        base["sec-ch-ua"] = profile.secChUa;
        base["sec-ch-ua-mobile"] = profile.secChUaMobile;
        base["sec-ch-ua-platform"] = profile.secChUaPlatform;
    }
    return base;
}
function maxBytesFor(budget, override) {
    if (override != null)
        return override;
    if (budget === "gitDump")
        return 8 * 1024 * 1024;
    if (budget === "jsFetch")
        return 384 * 1024;
    if (budget === "pathProbe" || budget === "pathSlow")
        return 128 * 1024;
    return 256 * 1024;
}
const POOL_OPTS = {
    connect: {
        rejectUnauthorized: false,
        timeout: 1_500,
        minVersion: "TLSv1.2",
        secureOptions: cryptoConstants.SSL_OP_LEGACY_SERVER_CONNECT,
        /** Chrome-ordered cipher list to match ClientHello fingerprint. */
        ciphers: CHROME_CIPHERS,
    },
    keepAliveTimeout: 4_000,
    keepAliveMaxTimeout: 12_000,
    connections: 40,
    pipelining: 1,
    headersTimeout: 3_000,
    bodyTimeout: 12_000,
};
function hostnameOf(origin) {
    try {
        return new URL(origin).hostname;
    }
    catch {
        return origin;
    }
}
export class HttpClient {
    config;
    logger;
    pools = new Map();
    inFlight = new Map();
    /** HTTPS origins that answered with plaintext HTTP — later GETs use http://host:443. */
    plaintextHttps = new Map();
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }
    get(url, options = {}) {
        return this.request("GET", url, options);
    }
    post(url, options = {}) {
        return this.request("POST", url, options);
    }
    bump(origin, delta) {
        const next = (this.inFlight.get(origin) ?? 0) + delta;
        if (next <= 0)
            this.inFlight.delete(origin);
        else
            this.inFlight.set(origin, next);
    }
    dropPool(origin) {
        const stale = this.pools.get(origin);
        this.pools.delete(origin);
        void stale?.destroy();
    }
    evictIdle() {
        while (this.pools.size >= MAX_ORIGIN_POOLS) {
            let evicted = false;
            for (const origin of this.pools.keys()) {
                if ((this.inFlight.get(origin) ?? 0) > 0)
                    continue;
                this.dropPool(origin);
                evicted = true;
                break;
            }
            if (!evicted)
                break;
        }
    }
    markPlaintextHttps(url) {
        const origin = originOf(url);
        if (!origin.startsWith("https:"))
            return;
        if (this.plaintextHttps.has(origin)) {
            this.plaintextHttps.delete(origin);
            this.plaintextHttps.set(origin, true);
            return;
        }
        while (this.plaintextHttps.size >= MAX_ORIGIN_POOLS) {
            const oldest = this.plaintextHttps.keys().next().value;
            if (!oldest)
                break;
            this.plaintextHttps.delete(oldest);
        }
        this.plaintextHttps.set(origin, true);
    }
    rewriteIfPlaintext(url) {
        try {
            const origin = new URL(url).origin;
            if (this.plaintextHttps.has(origin))
                return httpsToHttpSamePort(url);
        }
        catch {
            /* keep */
        }
        return url;
    }
    abortFor(options, budgetMs) {
        const ac = new AbortController();
        setMaxListeners(32, ac.signal);
        const timer = setTimeout(() => ac.abort(), budgetMs);
        const onParent = () => ac.abort();
        const parent = options.signal;
        if (parent) {
            if (parent.aborted)
                ac.abort();
            else
                parent.addEventListener("abort", onParent, { once: true });
        }
        return {
            signal: ac.signal,
            dispose: () => {
                clearTimeout(timer);
                parent?.removeEventListener("abort", onParent);
            },
        };
    }
    dispatcherFor(url) {
        let origin = url;
        try {
            origin = new URL(url).origin;
        }
        catch {
            /* keep url */
        }
        const hit = this.pools.get(origin);
        if (hit) {
            this.pools.delete(origin);
            this.pools.set(origin, hit);
            return hit;
        }
        this.evictIdle();
        const ip = isIP(hostnameOf(origin)) !== 0;
        const pool = new Pool(origin, {
            ...POOL_OPTS,
            connect: {
                ...POOL_OPTS.connect,
                ...(ip ? { servername: "" } : {}),
            },
        });
        this.pools.set(origin, pool);
        return pool;
    }
    async request(method, url, options, retried = false) {
        const target = this.rewriteIfPlaintext(url);
        const origin = originOf(target);
        const budget = this.config.resolveBudget(options.budget ?? "httpRequest");
        const maxBytes = maxBytesFor(options.budget, options.maxBytes);
        const abort = this.abortFor(options, budget);
        this.bump(origin, 1);
        try {
            const res = await request(target, {
                method,
                dispatcher: this.dispatcherFor(target),
                signal: abort.signal,
                body: method === "POST" ? options.body : undefined,
                headers: {
                    // Browser header spoof: realistic UA + sec-ch-ua headers.
                    // Does NOT affect TLS fingerprint — see module-level comment.
                    ...impersonateHeaders(options.impersonate ?? "chrome", nextProfile()),
                    ...(method === "POST" && options.body ? { "content-type": "application/json" } : {}),
                    ...options.headers,
                },
                maxRedirections: 5,
            });
            const chunks = [];
            let total = 0;
            let truncated = false;
            for await (const chunk of res.body) {
                const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                total += buf.length;
                if (total > maxBytes) {
                    truncated = true;
                    break;
                }
                chunks.push(buf);
            }
            if (truncated) {
                try {
                    await res.body.dump();
                }
                catch {
                    try {
                        res.body.destroy();
                    }
                    catch {
                        /* ignore */
                    }
                }
            }
            const raw = Buffer.concat(chunks);
            const headers = {};
            for (const [k, v] of Object.entries(res.headers)) {
                if (typeof v === "string")
                    headers[k.toLowerCase()] = v;
                else if (Array.isArray(v))
                    headers[k.toLowerCase()] = v.join(", ");
            }
            const text = decodeHttpBody(raw, headers["content-encoding"]);
            const body = options.keepBody ? raw : EMPTY;
            return {
                url: target,
                status: res.statusCode,
                headers,
                body,
                text,
            };
        }
        catch (err) {
            if (!retried && isTlsPlaintextError(err)) {
                const alt = httpsToHttpSamePort(target);
                if (alt !== target) {
                    this.markPlaintextHttps(target);
                    return this.request(method, alt, options, true);
                }
            }
            if (!retried && isClientDestroyedError(err)) {
                this.dropPool(origin);
                return this.request(method, target, options, true);
            }
            if (!isUnreachableError(err)) {
                this.logger.warn("HTTP", `${method} failed ${target}: ${err.message}`);
            }
            throw err;
        }
        finally {
            abort.dispose();
            this.bump(origin, -1);
        }
    }
}
