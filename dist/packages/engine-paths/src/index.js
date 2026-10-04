import { isDeadHostError, resolveUrl, utf16leBypassPath } from "@scanner/core";
const CANARIES = ["/.env", "/config.json", "/wp-config.php", "/appsettings.json"];
function looksLive(status, body, analyzer, path) {
    if (![200, 201, 401, 403].includes(status))
        return false;
    if (analyzer.isHTML(body))
        return false;
    return analyzer.isLikelySecretFile(body, path);
}
export class PathsModule {
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
        if (!this.dedup.checkAndMark("path-origin", origin))
            return;
        const cfg = this.config.get();
        const allPaths = cfg.pathsToCheck.filter((p) => p.startsWith("/"));
        if (!allPaths.length)
            return;
        let finished = false;
        const state = { hostDead: false, catchAll: false, htmlHits: 0 };
        try {
            const total = allPaths.length;
            const listed = new Set(allPaths);
            const done = new Set();
            let halfway = false;
            const notePath = (path) => {
                if (!listed.has(path))
                    return;
                done.add(path);
                if (!halfway && done.size >= Math.ceil(total / 2)) {
                    halfway = true;
                    ctx.onPathsHalfway?.();
                }
            };
            const canary = await this.canary(origin, ctx, notePath, state);
            for (const hit of canary.hits)
                yield hit;
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
                    if (ctx.signal.aborted || state.hostDead || state.catchAll)
                        break;
                    const path = paths[i++];
                    const { hit, dead } = await this.probe(origin, path, ctx, state);
                    notePath(path);
                    if (dead)
                        state.hostDead = true;
                    if (hit)
                        hits.push(hit);
                }
                return hits;
            });
            const groups = await Promise.all(workers);
            if (state.hostDead) {
                this.logger.warn("PATHS", `skip remaining paths ${origin} (host dead)`);
            }
            else if (state.catchAll) {
                this.logger.warn("PATHS", `skip remaining paths ${origin} (html catch-all)`);
            }
            for (const g of groups) {
                for (const h of g)
                    yield h;
            }
            finished = !ctx.signal.aborted;
        }
        finally {
            if (!finished)
                this.dedup.unmark?.("path-origin", origin);
        }
    }
    async canary(origin, ctx, notePath, state) {
        const fetched = new Set();
        const hits = [];
        const hard = await Promise.all(CANARIES.map(async (path) => {
            const { hit, dead, fetched: ok } = await this.probe(origin, path, ctx, state);
            notePath(path);
            if (ok)
                fetched.add(path);
            if (hit)
                hits.push(hit);
            return dead;
        }));
        return { skip: hard.filter(Boolean).length >= 3, hits, fetched };
    }
    async probe(origin, path, ctx, state) {
        const url = resolveUrl(origin + "/", path.replace(/^\//, "")) ?? origin + path;
        let release = () => { };
        try {
            release = this.limiter ? await this.limiter.acquire(ctx.signal) : () => { };
            const res = await this.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
            if ((res.status === 200 || res.status === 201) && this.analyzer.isHTML(res.text)) {
                state.htmlHits += 1;
                if (state.htmlHits >= 3)
                    state.catchAll = true;
            }
            // — WAF detected? retry with UTF-16LE encoded path variant —
            if (res.status === 403 &&
                this.analyzer.isWAFPage(res.text) &&
                !ctx.signal.aborted) {
                const bypassPath = utf16leBypassPath(path);
                const bypassUrl = resolveUrl(origin + "/", bypassPath.replace(/^\//, "")) ?? origin + bypassPath;
                if (bypassUrl !== url) {
                    try {
                        const bypass = await this.http.get(bypassUrl, {
                            signal: ctx.signal,
                            budget: "pathProbe",
                        });
                        if (looksLive(bypass.status, bypass.text, this.analyzer, path)) {
                            const result = this.analyzer.analyze({
                                url: bypassUrl,
                                path,
                                content: bypass.text,
                                contentEncoding: bypass.headers["content-encoding"],
                                contentType: bypass.headers["content-type"],
                            });
                            if (!result.rejected && result.matches.length > 0) {
                                this.logger.info("PATHS", `WAF bypass hit (utf16le) ${bypassUrl} (${result.matches.length} match)`);
                                return {
                                    hit: {
                                        source: "path",
                                        url: bypassUrl,
                                        origin,
                                        path,
                                        payloadType: "utf16le-bypass",
                                        statusCode: bypass.status,
                                        contentSnippet: result.text.slice(0, 12_000),
                                        matches: result.matches,
                                    },
                                    dead: false,
                                    fetched: true,
                                };
                            }
                        }
                    }
                    catch {
                        /* bypass attempt failed — fall through */
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
                contentType: res.headers["content-type"],
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
                    contentSnippet: result.text.slice(0, 12_000),
                    matches: result.matches,
                },
                dead: false,
                fetched: true,
            };
        }
        catch (err) {
            return { hit: null, dead: isDeadHostError(err), fetched: false };
        }
        finally {
            release();
        }
    }
}
export default PathsModule;
