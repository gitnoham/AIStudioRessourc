import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";
import { resolveUrl, sameHost } from "@scanner/core";
import { applyDiscovery, compilePatternSets } from "@scanner/content-analyzer";

const ROBOTS_PATH = /(?:Disallow|Allow):\s*(\S+)/gi;
const ROBOTS_SITEMAP = /Sitemap:\s*(\S+)/gi;
const SITEMAP_LOC = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
const MAX_ROBOTS_PATHS = 40;
const MAX_SITEMAP_URLS = 24;
const MAX_SITEMAPS = 3;
const RECON_FETCH = 8;

const SKIP_EXT = /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|css|mp4|mp3|pdf)$/i;

export class ReconModule implements ScanModule {
  readonly name = "recon";
  readonly phase = "content" as const;
  readonly requiresPage = true;

  constructor(deps: EngineDeps) {
    this.http = deps.http;
    this.analyzer = deps.analyzer;
    this.config = deps.config;
    this.dedup = deps.dedup;
    this.logger = deps.logger;
    this.compiled = compilePatternSets(deps.config.patterns());
  }

  private readonly http: EngineDeps["http"];
  private readonly analyzer: EngineDeps["analyzer"];
  private readonly config: EngineDeps["config"];
  private readonly dedup: EngineDeps["dedup"];
  private readonly logger: EngineDeps["logger"];
  private readonly compiled: ReturnType<typeof compilePatternSets>;

  isEnabled(config: AppConfig): boolean {
    return config.modules.recon !== false;
  }

  async *scan(ctx: ScanContext): AsyncGenerator<RawHit> {
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
        matches: analyzed.matches,
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

    // robots.txt / sitemap / endpoint re-scan are origin-scoped resources:
    // run them once per origin instead of once per URL (the per-page SSR
    // payload and script-map analysis above stays per URL).
    if (this.dedup.checkAndMark("recon-origin", ctx.origin)) {
      yield* this.guidanceAndRescan(ctx, compiled);
    }
  }

  private async *guidanceAndRescan(
    ctx: ScanContext,
    compiled: ReturnType<typeof compilePatternSets>,
  ): AsyncGenerator<RawHit> {
    const endpoints: string[] = [];
    const sitemaps: string[] = [];

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
            matches: analyzed.matches,
          };
        }
        for (const p of [...applyDiscovery(robots.text, compiled, "robotsDisallow"), ...matchAll(ROBOTS_PATH, robots.text)]) {
          if (!p || p === "/" || p.includes("*")) continue;
          const abs = resolveUrl(ctx.origin + "/", p);
          if (abs && sameHost(abs, ctx.origin) && !SKIP_EXT.test(abs)) endpoints.push(abs);
        }
        for (const sm of [...applyDiscovery(robots.text, compiled, "robotsSitemap"), ...matchAll(ROBOTS_SITEMAP, robots.text)]) {
          if (!sm || sitemaps.length >= MAX_SITEMAPS) continue;
          const abs = sm.startsWith("http") ? sm : resolveUrl(ctx.origin + "/", sm);
          if (abs && sameHost(abs, ctx.origin)) sitemaps.push(abs);
        }
      }
    } catch {
      /* ignore */
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
            matches: analyzed.matches,
          };
        }
        let locs = 0;
        for (const loc of [...applyDiscovery(sm.text, compiled, "sitemapLoc"), ...matchAll(SITEMAP_LOC, sm.text)]) {
          if (locs >= MAX_SITEMAP_URLS) break;
          const abs = loc.startsWith("http") ? loc : resolveUrl(ctx.origin + "/", loc);
          if (!abs || !sameHost(abs, ctx.origin) || SKIP_EXT.test(abs)) continue;
          endpoints.push(abs);
          locs++;
        }
      } catch {
        /* ignore */
      }
    }

    const unique = [...new Set(endpoints)].slice(0, MAX_ROBOTS_PATHS + MAX_SITEMAP_URLS);
    const interesting = unique.sort((a, b) => reconScore(b) - reconScore(a));
    this.logger.info("RECON", `${interesting.length} endpoint(s) to re-scan on ${ctx.origin}`);

    let i = 0;
    const hits: RawHit[] = [];
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

  private async fetchAndScan(ctx: ScanContext, url: string, source: RawHit["source"]): Promise<RawHit | null> {
    // Shared scope "map": also used by the js module, so a sourcemap is
    // fetched once per run instead of once per module/URL.
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
        contentSnippet: analyzed.text.slice(0, 200),
      };
    } catch {
      return null;
    }
  }
}

function matchAll(re: RegExp, text: string): string[] {
  const out: string[] = [];
  const g = new RegExp(re.source, re.flags);
  let m: RegExpExecArray | null;
  while ((m = g.exec(text))) out.push(m[1]);
  return out;
}

function reconScore(url: string): number {
  const u = url.toLowerCase();
  let s = 0;
  for (const h of [".env", "config", "backup", "secret", "admin", "/api/", ".json", ".xml", ".php", ".git", "wp-config", "credentials"]) {
    if (u.includes(h)) s += 10;
  }
  return s;
}

export default ReconModule;
