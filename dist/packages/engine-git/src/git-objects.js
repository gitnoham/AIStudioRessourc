import { inflateSync } from "node:zlib";
import { createHash } from "node:crypto";
export const GIT_META_SEEDS = [
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
    "logs/refs/stash",
];
/** Extra .git locations besides origin `/.git`. Bare repo: `/www.git`. */
export const GIT_ROOTS = [
    "/.git",
    "/backup/.git",
    "/old/.git",
    "/html/.git",
    "/public/.git",
    "/www.git",
    "/.git.bak",
];
const gitRefsRe = /refs\/(?:heads|remotes|tags)\/[\w\-./]+/g;
const gitSHARe = /\b[a-f0-9]{40}\b/g;
const gitHrefRe = /href=["']([^"']+)["']/gi;
export function isValidSha(s) {
    return /^[a-f0-9]{40}$/.test(s);
}
export function gitLooksExposed(path, body) {
    const t = body.trim();
    if (!t)
        return false;
    if (path.endsWith("/config") || path.endsWith("config"))
        return t.includes("[core]");
    if (path.endsWith("/HEAD") || path.endsWith("HEAD")) {
        return t.startsWith("ref:") || isValidSha(t.split(/\s/)[0] ?? "");
    }
    if (path.endsWith("/.git") || path.endsWith("/.git/")) {
        return t.includes("HEAD") || t.includes("config");
    }
    return false;
}
export function extractGitRefs(content) {
    const refs = [];
    for (const m of content.matchAll(gitRefsRe)) {
        refs.push(m[0]);
        refs.push(`logs/${m[0]}`);
    }
    return refs;
}
export function extractShas(content) {
    return content.match(gitSHARe) ?? [];
}
export function extractGitHrefs(html) {
    const out = [];
    gitHrefRe.lastIndex = 0;
    let m;
    while ((m = gitHrefRe.exec(html))) {
        const href = m[1].trim();
        if (href && !href.startsWith("?") && !href.startsWith("#"))
            out.push(href);
    }
    return out;
}
export function parseGitIndex(buf) {
    if (buf.length < 12 || buf.subarray(0, 4).toString() !== "DIRC")
        return [];
    const version = buf.readUInt32BE(4);
    const count = buf.readUInt32BE(8);
    if (version !== 2 && version !== 3)
        return [];
    const entries = [];
    let offset = 12;
    for (let i = 0; i < count && offset + 62 < buf.length; i++) {
        const size = buf.readUInt32BE(offset + 36);
        const sha = buf.subarray(offset + 40, offset + 60).toString("hex");
        const flags = buf.readUInt16BE(offset + 60);
        const nameLen = flags & 0x0fff;
        const nameStart = offset + 62;
        const nameEnd = nameStart + nameLen;
        if (nameEnd > buf.length)
            break;
        const path = buf.subarray(nameStart, nameEnd).toString("utf8");
        entries.push({ path, sha, size });
        const rawLen = 62 + nameLen + 1;
        offset += Math.ceil(rawLen / 8) * 8;
    }
    return entries;
}
export function inflateFrom(buf, offset) {
    const rest = buf.subarray(offset);
    if (rest.length < 2)
        return null;
    let found = null;
    for (let n = 8; n <= rest.length; n = n === rest.length ? rest.length + 1 : Math.min(rest.length, n * 2)) {
        try {
            const data = inflateSync(rest.subarray(0, n));
            found = { data, consumed: n };
            break;
        }
        catch {
            /* grow */
        }
    }
    if (!found) {
        try {
            return { data: inflateSync(rest), consumed: rest.length };
        }
        catch {
            return null;
        }
    }
    let lo = Math.max(2, Math.floor(found.consumed / 2));
    let hi = found.consumed;
    while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        try {
            const data = inflateSync(rest.subarray(0, mid));
            found = { data, consumed: mid };
            hi = mid;
        }
        catch {
            lo = mid + 1;
        }
    }
    try {
        return { data: inflateSync(rest.subarray(0, lo)), consumed: lo };
    }
    catch {
        return found;
    }
}
export function parseGitObject(buf) {
    let inflated;
    try {
        inflated = inflateSync(buf);
    }
    catch {
        const r = inflateFrom(buf, 0);
        if (!r)
            return null;
        inflated = r.data;
    }
    const nul = inflated.indexOf(0);
    if (nul < 0)
        return { type: "blob", content: inflated };
    const header = inflated.subarray(0, nul).toString("utf8");
    const type = header.split(" ")[0] ?? "blob";
    return { type, content: inflated.subarray(nul + 1) };
}
function readPackSize(buf, i) {
    let c = buf[i.p++];
    const type = (c >> 4) & 7;
    let size = c & 15;
    let shift = 4;
    while (c & 0x80 && i.p < buf.length) {
        c = buf[i.p++];
        size |= (c & 0x7f) << shift;
        shift += 7;
    }
    return { type, size };
}
function readOfsDelta(buf, i) {
    let c = buf[i.p++];
    let n = c & 0x7f;
    while (c & 0x80 && i.p < buf.length) {
        c = buf[i.p++];
        n = ((n + 1) << 7) | (c & 0x7f);
    }
    return n;
}
export function applyDelta(base, delta) {
    const cur = { p: 0 };
    const srcSize = readGitVarint(delta, cur);
    const dstSize = readGitVarint(delta, cur);
    void srcSize;
    const out = Buffer.alloc(dstSize);
    let o = 0;
    while (cur.p < delta.length && o < dstSize) {
        const cmd = delta[cur.p++];
        if (cmd & 0x80) {
            let off = 0;
            let sz = 0;
            if (cmd & 0x01)
                off |= delta[cur.p++];
            if (cmd & 0x02)
                off |= delta[cur.p++] << 8;
            if (cmd & 0x04)
                off |= delta[cur.p++] << 16;
            if (cmd & 0x08)
                off |= delta[cur.p++] << 24;
            if (cmd & 0x10)
                sz |= delta[cur.p++];
            if (cmd & 0x20)
                sz |= delta[cur.p++] << 8;
            if (cmd & 0x40)
                sz |= delta[cur.p++] << 16;
            if (sz === 0)
                sz = 0x10000;
            if (off + sz > base.length || o + sz > out.length)
                return null;
            base.copy(out, o, off, off + sz);
            o += sz;
        }
        else if (cmd !== 0) {
            if (cur.p + cmd > delta.length || o + cmd > out.length)
                return null;
            delta.copy(out, o, cur.p, cur.p + cmd);
            cur.p += cmd;
            o += cmd;
        }
        else {
            return null;
        }
    }
    return o === dstSize ? out : out.subarray(0, o);
}
function readGitVarint(buf, i) {
    let n = 0;
    let shift = 0;
    for (;;) {
        const c = buf[i.p++];
        n |= (c & 0x7f) << shift;
        if (!(c & 0x80))
            break;
        shift += 7;
    }
    return n;
}
export function parsePackObjects(buf, max = 400) {
    const blobs = [];
    for (const o of parsePack(buf, max)) {
        if (o.type === 3)
            blobs.push(stripGitHeader(o.content));
        else if (o.type === 1 || o.type === 2 || o.type === 4)
            blobs.push(stripGitHeader(o.content));
        else
            blobs.push(o.content);
    }
    return blobs;
}
function stripGitHeader(content) {
    const nul = content.indexOf(0);
    if (nul >= 0 && nul < 64)
        return content.subarray(nul + 1);
    return content;
}
export function parsePack(buf, max = 400) {
    if (buf.length < 12 || buf.subarray(0, 4).toString("ascii") !== "PACK")
        return [];
    const count = buf.readUInt32BE(8);
    const byOffset = new Map();
    const bySha = new Map();
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
        }
        else if (type === 7) {
            if (cur.p + 20 > buf.length)
                break;
            baseSha = buf.subarray(cur.p, cur.p + 20).toString("hex");
            cur.p += 20;
        }
        const inf = inflateFrom(buf, cur.p);
        if (!inf)
            break;
        let content = inf.data;
        let resolvedType = type;
        if (type === 6 || type === 7) {
            const base = type === 6 ? byOffset.get(baseOff)?.content : bySha.get(baseSha);
            if (base) {
                const applied = applyDelta(stripGitHeader(base), content);
                if (applied) {
                    content = applied;
                    resolvedType = type === 6 ? (byOffset.get(baseOff)?.type ?? 3) : 3;
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
    return createHash("sha1").update(payload).digest("hex");
}
export function gitObjectUrl(site, sha) {
    return `${site}/objects/${sha.slice(0, 2)}/${sha.slice(2)}`;
}
export function priorityScore(path, hints) {
    const lower = path.toLowerCase();
    let score = 0;
    for (const h of hints) {
        if (lower.includes(h.toLowerCase()))
            score += 10;
    }
    if (lower.endsWith(".env") || lower.includes("wp-config") || lower.includes("credentials"))
        score += 20;
    return score;
}
export function shouldScanGitBlob(path, hints) {
    return priorityScore(path, hints) > 0 || /\.(env|php|yml|yaml|json|xml|properties|conf|cfg|ini|key|pem|txt)$/i.test(path);
}
