import { GIT_META_SEEDS, GIT_ROOTS, extractGitHrefs, extractGitRefs, extractShas, gitLooksExposed, gitObjectUrl, isValidSha, parseGitIndex, parseGitObject, parsePackObjects, priorityScore, } from "./git-objects.js";
import { scanSvnHg } from "./vcs-extra.js";
const LIST_DIR_CAP = 24;
export class GitModule {
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
            if (ctx.signal.aborted)
                break;
            yield* this.scanDump(ctx, `${ctx.origin}${root}`);
        }
        if (!ctx.signal.aborted) {
            yield* scanSvnHg({
                http: this.http,
                analyzer: this.analyzer,
                config: this.config,
                dedup: this.dedup,
                logger: this.logger,
            }, ctx);
        }
    }
    async *scanDump(ctx, site) {
        if (!this.dedup.checkAndMark("git-site", site))
            return;
        let finished = false;
        try {
            const exposed = await this.detect(site, ctx);
            if (ctx.signal.aborted)
                return;
            if (!exposed) {
                finished = true;
                return;
            }
            this.logger.info("GIT", `exposed ${site}`);
            yield* this.reconstruct(site, ctx);
            finished = !ctx.signal.aborted;
        }
        finally {
            if (!finished)
                this.dedup.unmark?.("git-site", site);
        }
    }
    async detect(site, ctx) {
        const probes = ["HEAD", "config", ""];
        const hits = await Promise.all(probes.map(async (p) => {
            const res = await this.safeGet(p ? `${site}/${p}` : `${site}/`, ctx);
            if (!res)
                return false;
            if (this.analyzer.isWAFPage(res.text))
                return false;
            const label = p ? `${site}/${p}` : `${site}/`;
            if (gitLooksExposed(label, res.text) || (p === "HEAD" && gitLooksExposed("/HEAD", res.text))) {
                return true;
            }
            return p === "" && (res.text.includes("HEAD") || res.text.includes("config"));
        }));
        return hits.some(Boolean);
    }
    async *reconstruct(site, ctx) {
        const cfg = this.config.get();
        const hints = cfg.gitSecretHints;
        const maxBlobs = cfg.concurrency.gitMaxBlobs;
        const maxDownloads = Math.max(64, cfg.concurrency.gitMaxDownloads ?? 400);
        const workers = Math.max(1, cfg.concurrency.gitWorkers);
        const fetched = new Map();
        const processed = new Set();
        const packNames = new Set();
        await this.fetchMany(site, ctx, [...GIT_META_SEEDS], fetched, processed, packNames, workers, maxDownloads);
        const listed = [];
        let listDirs = 0;
        for (const [path, file] of fetched) {
            if (!this.looksHtml(file.text) || listDirs >= LIST_DIR_CAP)
                continue;
            listDirs++;
            for (const href of extractGitHrefs(file.text)) {
                const next = resolveGitRel(path, href);
                if (next && !processed.has(next))
                    listed.push(next);
            }
        }
        await this.fetchMany(site, ctx, listed, fetched, processed, packNames, workers, maxDownloads);
        const extraRefs = [];
        for (const file of fetched.values()) {
            for (const ref of extractGitRefs(file.text)) {
                if (!processed.has(ref))
                    extraRefs.push(ref);
            }
        }
        await this.fetchMany(site, ctx, extraRefs, fetched, processed, packNames, workers, maxDownloads);
        for (const [path, file] of fetched) {
            const named = path.match(/pack-([a-f0-9]{40})\.pack$/i);
            if (named)
                packNames.add(named[1].toLowerCase());
            for (const listed of file.text.matchAll(/pack-([a-f0-9]{40})\.pack/gi)) {
                packNames.add(listed[1].toLowerCase());
            }
        }
        const index = fetched.get("index");
        const indexEntries = index ? parseGitIndex(index.body) : [];
        const hasPacks = packNames.size > 0;
        const hasIndex = indexEntries.length > 0;
        if (!hasIndex && !hasPacks) {
            const loose = [];
            for (const [path, file] of fetched) {
                if (skipShaExtract(path))
                    continue;
                let added = 0;
                for (const sha of extractShas(file.text)) {
                    if (!isValidSha(sha) || added >= 75)
                        continue;
                    const obj = `objects/${sha.slice(0, 2)}/${sha.slice(2)}`;
                    if (processed.has(obj))
                        continue;
                    loose.push(obj);
                    added++;
                }
            }
            await this.fetchMany(site, ctx, loose, fetched, processed, packNames, workers, Math.min(maxDownloads, 80));
        }
        const blobHits = [];
        if (hasIndex && !hasPacks) {
            const toFetch = [...indexEntries]
                .sort((a, b) => priorityScore(b.path, hints) - priorityScore(a.path, hints))
                .slice(0, maxBlobs);
            let bi = 0;
            const run = async () => {
                while (bi < toFetch.length && !ctx.signal.aborted) {
                    const e = toFetch[bi++];
                    const obj = await this.safeGet(gitObjectUrl(site, e.sha), ctx);
                    if (!obj)
                        continue;
                    const parsed = parseGitObject(obj.body);
                    const content = parsed?.content ?? obj.body;
                    const hit = this.analyzeBuf(ctx, site, e.path, content);
                    if (hit)
                        blobHits.push(hit);
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
                if (!pack)
                    continue;
                this.logger.info("GIT", `pack ${sha.slice(0, 8)}… on ${site}`);
                for (const blob of parsePackObjects(pack.body, maxBlobs)) {
                    const hit = this.analyzeBuf(ctx, site, `pack-${sha}`, blob);
                    if (hit)
                        blobHits.push(hit);
                }
            }
        };
        await Promise.all(Array.from({ length: Math.min(2, workers) }, () => packRun()));
        for (const [path, file] of fetched) {
            if (path.endsWith(".pack") || path.endsWith(".idx"))
                continue;
            let body = file.body.length ? file.body : file.text;
            if (path.includes("objects/") && !path.includes("info/") && file.body.length) {
                const parsed = parseGitObject(file.body);
                if (parsed)
                    body = parsed.content;
            }
            const hit = this.analyzeBuf(ctx, site, path, body);
            if (hit)
                yield hit;
        }
        for (const h of blobHits)
            yield h;
    }
    async fetchMany(site, ctx, items, fetched, processed, packNames, workers, cap) {
        const queue = items
            .map((rel) => rel.replace(/^\/+/, "").replace(/^\.git\//, ""))
            .filter((norm) => {
            if (!norm || processed.has(norm))
                return false;
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
                if (!res)
                    continue;
                fetched.set(norm, { body: res.body, text: res.text });
            }
        };
        await Promise.all(Array.from({ length: Math.max(1, workers) }, () => run()));
    }
    analyzeBuf(ctx, site, path, content) {
        const analyzed = this.analyzer.analyze({ url: site, path, content });
        if (analyzed.rejected || !analyzed.matches.length)
            return null;
        return {
            source: "git",
            url: ctx.rawUrl,
            origin: ctx.origin,
            site,
            blobPath: path,
            matches: analyzed.matches,
            contentSnippet: snippetAroundMatches(analyzed.text, analyzed.matches),
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
                keepBody,
            });
            if (res.status !== 200 || (res.body.length === 0 && !res.text))
                return null;
            if (this.analyzer.isWAFPage(res.text))
                return null;
            return res;
        }
        catch {
            return null;
        }
    }
}
/** Unpacked git blob: keep the whole object when small; else windows around SMTP + every MAIL_* / FROM. */
export function snippetAroundMatches(text, matches) {
    const cap = 48_000;
    if (!text)
        return "";
    if (text.length <= cap)
        return text;
    const windows = [];
    const add = (i, before, after) => {
        if (i < 0)
            return;
        windows.push([Math.max(0, i - before), Math.min(text.length, i + after)]);
    };
    for (const m of matches) {
        if (!m.value || m.value.length < 4)
            continue;
        const i = text.indexOf(m.value);
        if (i < 0)
            continue;
        const smtpish = /smtp|mail|from|salesforce/i.test(`${m.service} ${m.patternName}`);
        add(i, smtpish ? 800 : 200, smtpish ? 4000 : 200);
    }
    const mailMark = /(?:MAIL_|SMTP_|EMAIL_HOST|DEFAULT_FROM_EMAIL|SENDER_EMAIL|WP_MAIL_FROM|FROM_EMAIL|FROM_ADDRESS|NOREPLY_EMAIL|SALESFORCE_|SFDC_|SF_USERNAME|SF_PASSWORD|SF_SESSION)/gi;
    let mm;
    let n = 0;
    while ((mm = mailMark.exec(text)) && n < 80) {
        add(mm.index, 200, 600);
        n++;
    }
    if (!windows.length)
        return text.slice(0, 1500);
    windows.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const w of windows) {
        const last = merged[merged.length - 1];
        if (last && w[0] <= last[1] + 80)
            last[1] = Math.max(last[1], w[1]);
        else
            merged.push([w[0], w[1]]);
    }
    let out = "";
    for (const [a, b] of merged) {
        if (out.length >= cap)
            break;
        const chunk = text.slice(a, Math.min(b, a + (cap - out.length)));
        out += out ? `\n${chunk}` : chunk;
    }
    return out;
}
function skipShaExtract(path) {
    return /(?:^index$|\.pack$|\.idx$|objects\/info\/packs$)/i.test(path);
}
function resolveGitRel(current, href) {
    if (/^https?:/i.test(href))
        return null;
    const dir = current.includes("/") ? current.slice(0, current.lastIndexOf("/") + 1) : "";
    let next = href.replace(/^\.\//, "");
    if (next.startsWith("/")) {
        const idx = next.indexOf(".git/");
        next = idx >= 0 ? next.slice(idx + 5) : next.replace(/^\/+/, "");
    }
    else {
        next = (dir + next).replace(/\/+/g, "/");
    }
    if (next.includes(".."))
        return null;
    return next.replace(/^\/+/, "");
}
export default GitModule;
export { parseGitIndex, parseGitObject };
