import type { EngineDeps, RawHit, ScanContext } from "@scanner/core";

/** Known secret filenames in SVN text-base — not a full working-copy rebuild. */
const SVN_TEXTBASE = [
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
  "docker-compose.yml",
];

const HG_SEEDS = ["hgrc", "requires", "branch", "last-message.txt"];

const EXTRA_FILE_CAP = 24;

/** SVN + Mercurial metadata (no repo rebuild, no Index-of / .DS_Store crawl). */
export async function* scanSvnHg(deps: EngineDeps, ctx: ScanContext): AsyncGenerator<RawHit> {
  yield* scanSvn(deps, ctx);
  if (ctx.signal.aborted) return;
  yield* scanHg(deps, ctx);
}

async function* scanSvn(deps: EngineDeps, ctx: ScanContext): AsyncGenerator<RawHit> {
  const base = `${ctx.origin}/.svn`;
  if (!deps.dedup.checkAndMark("svn-site", base)) return;
  const entries = await getText(deps, ctx, `${base}/entries`);
  const wc = await getBuf(deps, ctx, `${base}/wc.db`);
  const fmt = await getText(deps, ctx, `${base}/format`);
  const exposed =
    (entries && /dir|svn:|dirent/i.test(entries) && !deps.analyzer.isWAFPage(entries)) ||
    (fmt && /^\d/.test(fmt.trim()) && !deps.analyzer.isWAFPage(fmt)) ||
    (wc && wc.length > 64 && wc.subarray(0, 16).toString("utf8").includes("SQLite"));
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

async function* scanHg(deps: EngineDeps, ctx: ScanContext): AsyncGenerator<RawHit> {
  const base = `${ctx.origin}/.hg`;
  if (!deps.dedup.checkAndMark("hg-site", base)) return;
  const hgrc = await getText(deps, ctx, `${base}/hgrc`);
  const req = await getText(deps, ctx, `${base}/requires`);
  const exposed =
    (hgrc && /\[(?:paths|ui|auth)\]|revlog/i.test(hgrc) && !deps.analyzer.isWAFPage(hgrc)) ||
    (req && /revlog|store|fncache/i.test(req) && !deps.analyzer.isWAFPage(req));
  if (!exposed) return;
  deps.logger.info("HG", `exposed ${base}`);

  const seeds = new Map<string, string>();
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

function analyzeContent(
  deps: EngineDeps,
  ctx: ScanContext,
  url: string,
  content: Buffer | string,
): RawHit | null {
  if (!content || (typeof content === "string" && !content)) return null;
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
    contentSnippet: analyzed.text.slice(0, 1500),
  };
}

async function fetchAnalyze(deps: EngineDeps, ctx: ScanContext, url: string): Promise<RawHit | null> {
  try {
    const res = await deps.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
    if (res.status !== 200) return null;
    if (deps.analyzer.isWAFPage(res.text)) return null;
    return analyzeContent(deps, ctx, url, res.body.length ? res.body : res.text);
  } catch {
    return null;
  }
}

async function getText(deps: EngineDeps, ctx: ScanContext, url: string): Promise<string | null> {
  try {
    const res = await deps.http.get(url, { signal: ctx.signal, budget: "pathProbe" });
    if (res.status !== 200 || !res.text) return null;
    return res.text;
  } catch {
    return null;
  }
}

async function getBuf(deps: EngineDeps, ctx: ScanContext, url: string): Promise<Buffer | null> {
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

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
