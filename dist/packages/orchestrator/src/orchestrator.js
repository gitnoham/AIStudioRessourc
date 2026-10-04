import { mkdir, readdir, rename } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { writeFileSync } from "node:fs";
import { setMaxListeners } from "node:events";
import { homepageVariants, hashUrl, httpsToHttpDefaultPort, isDeadHostError, isTlsHandshakeError, isUnreachableError, originOf, } from "@scanner/core";
import { credentialFingerprints } from "@scanner/validator";
import { loadExcluded, streamUrlFile, countUrlFile } from "./url-stream.js";
import { AsyncPipeline } from "./pipeline.js";
export class Orchestrator {
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
    originProbe = new Map();
    stats = {
        urlsProcessed: 0,
        hitsValid: 0,
        hitsInvalid: 0,
        hitsRaw: 0,
        byService: {},
        cpm: 0,
    };
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
            if (hit.validationStatus === "valid")
                this.stats.hitsValid++;
            else if (hit.validationStatus === "invalid")
                this.stats.hitsInvalid++;
            else
                this.stats.hitsRaw++;
            const svc = hit.matches[0]?.service;
            if (svc) {
                const key = svc === "newmailgun" ? "mailgun" : svc;
                this.stats.byService[key] = (this.stats.byService[key] ?? 0) + 1;
            }
        });
    }
    async scanCheckFolder() {
        const cfg = this.config.get();
        await mkdir(cfg.checkDir, { recursive: true });
        await mkdir(cfg.doneDir, { recursive: true });
        await mkdir(cfg.dataDir, { recursive: true });
        const files = (await readdir(cfg.checkDir)).filter((f) => f.toLowerCase().endsWith(".txt"));
        if (!files.length) {
            this.logger.warn("ORCH", `no .txt files in ${cfg.checkDir}`);
            return;
        }
        for (const file of files) {
            const full = resolve(cfg.checkDir, file);
            await this.scanFile(full);
            await rename(full, join(cfg.doneDir, basename(file)));
            this.logger.info("ORCH", `moved ${file} → Done/`);
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
        this.dedup.reset("map");
        this.dedup.reset("hit");
        this.originProbe.clear();
        const excluded = loadExcluded(resolve(cfg.excludedUrlsFile));
        const seen = new Set();
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
            startedAt: this.startedAt,
        };
        this.stats.urlsTotal = await countUrlFile(file, excluded);
        await this.notifier.startScan(basename(file));
        const ticker = setInterval(() => {
            void this.notifier.updateProgress(this.snapshot());
        }, 15_000);
        const queueCap = cfg.concurrency.pipelineQueueCap ?? cfg.concurrency.urlWorkers * 8;
        const pipeline = new AsyncPipeline(cfg.concurrency.urlWorkers, async (url) => {
            try {
                await this.processUrl(url);
            }
            catch (err) {
                this.logger.error("ORCH", `url panic ${url}: ${err.message}`);
            }
            this.urlsProcessed++;
            this.stats.urlsProcessed = this.urlsProcessed;
        }, queueCap);
        try {
            for await (const url of streamUrlFile(file, excluded, seen)) {
                await pipeline.push(url); // back-pressure: suspends when queue is full
            }
            await pipeline.drain();
            await this.validator.drain();
            await new Promise((r) => setTimeout(r, 80));
            await this.validator.drain();
        }
        finally {
            clearInterval(ticker);
        }
        this.persist();
        await this.notifier.sendFinalStats({ ...this.snapshot(), done: true });
        this.logger.info("ORCH", `file done ${basename(file)} urls=${this.urlsProcessed}`);
    }
    async processUrl(rawUrl) {
        if (!this.dedup.checkAndMark("url-run", hashUrl(rawUrl)))
            return;
        const origin = originOf(rawUrl);
        const ac = new AbortController();
        setMaxListeners(64, ac.signal);
        const budget = this.config.resolveBudget("laneBudget");
        const timer = setTimeout(() => ac.abort(), budget);
        const ctx = {
            rawUrl,
            origin,
            signal: ac.signal,
            emit: (hit) => this.acceptHit(hit),
        };
        try {
            let probe = this.originProbe.get(origin);
            if (!probe) {
                probe = await this.probeOrigin(origin, ac.signal);
                if (!probe.dead) {
                    this.originProbe.set(origin, probe);
                    if (probe.origin && probe.origin !== origin)
                        this.originProbe.set(probe.origin, probe);
                }
            }
            if (probe.dead)
                return;
            if (probe.origin)
                ctx.origin = probe.origin;
            const enabled = this.config.get();
            const git = this.modules.filter((m) => m.name === "git" && m.isEnabled(enabled));
            const pathMods = this.modules.filter((m) => m.name === "paths" && m.isEnabled(enabled));
            ctx.pageContent = probe.home;
            const runContent = async () => {
                if (!ctx.pageContent)
                    ctx.pageContent = await this.fetchHome(rawUrl, ac.signal);
                if (ctx.pageContent) {
                    const home = this.analyzer.analyze({ url: rawUrl, content: ctx.pageContent });
                    if (!home.rejected && home.matches.length) {
                        this.acceptHit({
                            source: "homepage",
                            url: rawUrl,
                            origin: ctx.origin,
                            matches: home.matches,
                            contentSnippet: home.text.slice(0, 1500),
                        });
                    }
                }
                const content = this.modules.filter((m) => m.phase === "content" && m.isEnabled(enabled) && (!m.requiresPage || !!ctx.pageContent));
                await Promise.all(content.map((m) => this.runModule(m, ctx)));
                ctx.pageContent = undefined;
                const post = this.modules.filter((m) => m.phase === "post" && m.isEnabled(enabled));
                await Promise.all(post.map((m) => this.runModule(m, ctx)));
            };
            await Promise.all([
                Promise.all(pathMods.map((m) => this.runModule(m, ctx))),
                Promise.all(git.map((m) => this.runModule(m, ctx))),
                runContent(),
            ]);
        }
        finally {
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
        }
        catch (err) {
            this.logger.error(mod.name.toUpperCase(), `engine failed: ${err.message}`);
        }
    }
    async fetchHome(url, signal) {
        for (const u of homepageVariants(url)) {
            try {
                const res = await this.http.get(u, { signal, budget: "pathProbe" });
                if (res.status >= 200 && res.status < 400 && res.text) {
                    const a = this.analyzer.analyze({ url: u, content: res.text });
                    if (!a.rejected)
                        return a.text || res.text;
                }
            }
            catch {
                continue;
            }
        }
        return undefined;
    }
    async probeOrigin(origin, signal) {
        const first = await this.tryOriginHome(`${origin}/`, signal, "pathProbe");
        if (first.live)
            return { dead: false, origin: first.origin ?? origin, home: first.home };
        if (first.dead)
            return { dead: true };
        if (first.tlsHandshake && origin.startsWith("https:")) {
            const httpHome = httpsToHttpDefaultPort(`${origin}/`);
            if (httpHome !== `${origin}/`) {
                const viaHttp = await this.tryOriginHome(httpHome, signal, "pathProbe");
                if (viaHttp.live)
                    return { dead: false, origin: viaHttp.origin ?? originOf(httpHome), home: viaHttp.home };
            }
            return { dead: true };
        }
        const retry = await this.tryOriginHome(`${origin}/`, signal, "pathSlow");
        if (retry.live)
            return { dead: false, origin: retry.origin ?? origin, home: retry.home };
        return { dead: true };
    }
    async tryOriginHome(url, signal, budget) {
        try {
            const res = await this.http.get(url, { signal, budget });
            let home;
            if (res.status >= 200 && res.status < 400 && res.text) {
                const a = this.analyzer.analyze({ url: res.url, content: res.text });
                if (!a.rejected)
                    home = a.text || res.text;
            }
            return { live: true, dead: false, origin: originOf(res.url), home };
        }
        catch (err) {
            if (isDeadHostError(err))
                return { live: false, dead: true };
            if (isTlsHandshakeError(err))
                return { live: false, dead: false, tlsHandshake: true };
            if (isUnreachableError(err))
                return { live: false, dead: false };
            return { live: false, dead: false };
        }
    }
    acceptHit(hit) {
        if (!hit.matches.length)
            return;
        const keys = credentialFingerprints(hit);
        if (!keys.length)
            return;
        const fresh = keys.filter((k) => this.dedup.checkAndMark("hit", k));
        if (!fresh.length)
            return;
        this.validator.submit(hit);
    }
    snapshot() {
        const mins = Math.max(0.01, (Date.now() - this.startedAt) / 60000);
        return {
            ...this.stats,
            byService: { ...this.stats.byService },
            cpm: this.urlsProcessed / mins,
            urlsProcessed: this.urlsProcessed,
            fileName: this.stats.fileName,
            startedAt: this.startedAt,
        };
    }
    persist() {
        const dir = this.config.get().dataDir;
        try {
            writeFileSync(join(dir, "hit-counter.json"), JSON.stringify(this.snapshot(), null, 2));
        }
        catch (err) {
            this.logger.warn("ORCH", `persist ${err.message}`);
        }
    }
}
