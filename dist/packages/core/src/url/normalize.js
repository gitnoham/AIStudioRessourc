export function normalizeScanUrl(line) {
    let s = line.replace(/^\uFEFF/, "").trim();
    if (!s || s.startsWith("#"))
        return null;
    if (!/^https?:\/\//i.test(s))
        s = `https://${s}`;
    let parsed;
    try {
        parsed = new URL(s);
    }
    catch {
        return null;
    }
    if (!parsed.hostname)
        return null;
    parsed.hash = "";
    let href = parsed.toString();
    if (href.endsWith("/") && parsed.pathname === "/") {
        href = href.slice(0, -1);
    }
    return href;
}
export function originOf(url) {
    try {
        const u = new URL(url);
        return `${u.protocol}//${u.host}`;
    }
    catch {
        return url;
    }
}
/** https://host[:port]/path → http://host/path (default port 80). Handshake-fail fallback, not HTTP-on-443. */
export function httpsToHttpDefaultPort(url) {
    try {
        const u = new URL(url);
        if (u.protocol !== "https:")
            return url;
        u.protocol = "http:";
        u.port = "";
        return u.toString();
    }
    catch {
        return url;
    }
}
/** https://host[:port]/path → http://host:port/path (keeps 443 so we do not fall back to :80). */
export function httpsToHttpSamePort(url) {
    try {
        const u = new URL(url);
        if (u.protocol !== "https:")
            return url;
        const port = u.port || "443";
        u.protocol = "http:";
        u.port = port;
        return u.toString();
    }
    catch {
        return url;
    }
}
export function homepageVariants(url) {
    const out = [];
    try {
        const u = new URL(url);
        out.push(u.toString());
        u.protocol = u.protocol === "https:" ? "http:" : "https:";
        out.push(u.toString());
    }
    catch {
        out.push(url);
    }
    return out;
}
export function resolveUrl(base, ref) {
    try {
        return new URL(ref, base).toString();
    }
    catch {
        return null;
    }
}
export function sameHost(a, b) {
    try {
        return new URL(a).hostname === new URL(b).hostname;
    }
    catch {
        return false;
    }
}
export function scanIdentity(rawUrl, baseUrl) {
    return `${originOf(rawUrl)}|${originOf(baseUrl || rawUrl)}`;
}
