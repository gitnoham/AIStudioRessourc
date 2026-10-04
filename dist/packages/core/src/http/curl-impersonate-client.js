import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { which } from "../util/which.js";
const execFileAsync = promisify(execFile);
// ---------------------------------------------------------------------------
// CurlImpersonateClient — real TLS impersonation via curl-impersonate binary.
// https://github.com/lwthiker/curl-impersonate
//
// undici (Node.js) sends its own TLS ClientHello. Cloudflare Bot Management,
// Akamai, DataDome detect it at the TLS layer (JA3/JA4) — HTTP headers don't
// matter. This client shells out to curl-impersonate-chrome which patches
// libcurl to produce a byte-identical Chrome 120 ClientHello:
//   - JA3 / JA4 fingerprint = Chrome 120
//   - HTTP/2 SETTINGS + WINDOW_UPDATE frames = Chrome
//   - GREASE, extension order, EC groups = Chrome
//
// Activation (automatic, no code change needed):
//   export CURL_IMPERSONATE_BIN=/path/to/curl-impersonate-chrome
//   — or —
//   ensure curl-impersonate-chrome is in PATH
//
// If neither is found → falls back to undici (HttpClient), logged as warning.
// ---------------------------------------------------------------------------
const CANDIDATE_BINS = [
    "curl-impersonate-chrome",
    "curl-impersonate-ff",
    "curl-impersonate",
];
// undefined = not yet probed; null = not found; string = resolved path
let _resolvedBin = undefined;
async function resolveBin() {
    if (_resolvedBin !== undefined)
        return _resolvedBin;
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
export async function hasCurlImpersonate() {
    return (await resolveBin()) !== null;
}
// ---------------------------------------------------------------------------
// curl -i output parser
// Format:  HTTP/2 200\r\nheader: val\r\n\r\n<body>
// With --location: multiple header blocks separated by \r\n\r\n; use the last.
// ---------------------------------------------------------------------------
function parseCurlOutput(raw) {
    // Work in latin1 to preserve raw bytes; re-encode body separately.
    const text = raw.toString("latin1");
    // Split on blank lines (\r\n\r\n or \n\n)
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
    // Only curl-impersonate (not the -chrome/-ff variants) needs --impersonate flag.
    if (!bin.includes("chrome") && !bin.includes("ff")) {
        args.push("--impersonate", "chrome120");
    }
    args.push("-s", // silent — no progress bar
    "-i", // include response headers
    "-o", "-", // body → stdout
    "--location", // follow redirects
    "--max-time", String(timeout), "--compressed");
    if (insecure)
        args.push("--insecure");
    if (method === "HEAD")
        args.push("--head");
    if (method === "POST") {
        args.push("-X", "POST");
        if (options.body)
            args.push("--data-raw", options.body);
    }
    for (const [k, v] of Object.entries(options.headers ?? {})) {
        args.push("-H", `${k}: ${v}`);
    }
    args.push(url);
    return args;
}
async function exec(url, method, options, timeout, insecure) {
    const bin = await resolveBin();
    if (!bin) {
        throw new Error("curl-impersonate not found. " +
            "Set CURL_IMPERSONATE_BIN or install from https://github.com/lwthiker/curl-impersonate");
    }
    const args = buildArgs(url, method, options, bin, timeout, insecure);
    const { stdout } = await execFileAsync(bin, args, {
        encoding: "buffer",
        timeout: (timeout + 5) * 1000,
        maxBuffer: 10 * 1024 * 1024,
    });
    const raw = stdout;
    const { status, headers, body } = parseCurlOutput(raw);
    const text = body.toString("utf8");
    return { url, status, headers, body, text };
}
export class CurlImpersonateClient {
    _timeout;
    _insecure;
    constructor(opts = {}) {
        this._timeout = opts.timeout ?? 15;
        this._insecure = opts.insecure ?? false;
    }
    get(url, options = {}) {
        return exec(url, "GET", options, this._timeout, this._insecure);
    }
    post(url, options = {}) {
        return exec(url, "POST", options, this._timeout, this._insecure);
    }
}
