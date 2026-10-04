import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";
import { resolveUrl, sameHost, scanIdentity } from "@scanner/core";
import { applyDiscovery, compilePatternSets } from "@scanner/content-analyzer";

const SCRIPT_SRC = /<script[^>]+src\s*=\s*["']?([^"'\s>]+)["']?/gi;
const LINK_PRELOAD =
  /<link[^>]+rel\s*=\s*["'](?:modulepreload|preload|prefetch)["'][^>]+href\s*=\s*["']([^"']+)["']/gi;
const NEXT_STATIC = /(\/_next\/static\/[^"'\\\s>]+\.(?:js|mjs))/g;
const QUOTED_JS = /["']([^"'\\\s]{1,500}\.(?:js|mjs|cjs)(?:[?#][^"'\\\s]*)?)["']/gi;
const JS_CONCURRENCY = 8;

export class JsModule implements ScanModule {
  readonly name = "js";
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
    return config.modules.js !== false;
  }

  async *scan(ctx: ScanContext): AsyncGenerator<RawHit> {
    if (!ctx.pageContent) return;
    const id = scanIdentity(ctx.rawUrl, ctx.origin);
    if (!this.dedup.checkAndMark("js", id)) return;

    const compiled = this.compiled;
    const refs = extractPageScriptRefs(ctx.pageContent, ctx.origin, compiled);
    if (!refs.length) return;

    const cfg = this.config.get();
    const maxDepth = cfg.concurrency.jsCrawlDepth;
    const maxScripts = cfg.concurrency.jsMaxScripts;
    const seen = new Set<string>();
    const queue: Array<{ url: string; depth: number }> = refs.map((url) => ({ url, depth: 0 }));
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
          contentType: "application/javascript",
        });
        if (!analyzed.rejected && analyzed.matches.length) {
          yield {
            source: "js",
            url: ctx.rawUrl,
            origin: ctx.origin,
            scriptUrl: job.url,
            contentSnippet: analyzed.text.slice(0, 1500),
            matches: analyzed.matches,
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
            ...matchAll(QUOTED_JS, analyzed.text),
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

  private async fetchScript(url: string, ctx: ScanContext): Promise<string | null> {
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

  private async scanMap(mapUrl: string, ctx: ScanContext): Promise<RawHit | null> {
    // Shared scope "map": also used by the recon module, so a sourcemap is
    // fetched once per run instead of once per module/URL.
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
}

export function extractPageScriptRefs(
  html: string,
  origin: string,
  compiled?: ReturnType<typeof compilePatternSets>,
): string[] {
  const found: string[] = [];
  if (compiled) {
    for (const k of ["scriptSrc", "jsImportRef", "nextStaticJS", "linkPreload"] as const) {
      found.push(...applyDiscovery(html, compiled, k));
    }
  }
  found.push(...matchAll(SCRIPT_SRC, html));
  found.push(...matchAll(LINK_PRELOAD, html).filter((h) => isJsHint(h)));
  found.push(...matchAll(NEXT_STATIC, html));
  const out: string[] = [];
  const seen = new Set<string>();
  for (const r of found) {
    const abs = resolveUrl(origin + "/", htmlUnescape(r));
    if (!abs || seen.has(abs)) continue;
    if (!isJsUrl(abs) && !abs.includes("/_next/static/") && !abs.includes("/chunks/")) continue;
    seen.add(abs);
    out.push(abs);
  }
  return out.slice(0, 64);
}

function matchAll(re: RegExp, text: string): string[] {
  const out: string[] = [];
  const g = re.global ? new RegExp(re.source, re.flags) : new RegExp(re.source, re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = g.exec(text))) out.push(m[1] ?? m[0]);
  return out;
}

function htmlUnescape(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

function isJsUrl(u: string): boolean {
  return /\.(js|mjs|cjs)(\?|$)/i.test(u) || u.includes("/_next/static/");
}

function isJsHint(href: string): boolean {
  const lc = href.toLowerCase();
  return lc.includes(".js") || lc.includes("/static/") || lc.includes("/chunks/") || lc.includes("as=script");
}

export default JsModule;
