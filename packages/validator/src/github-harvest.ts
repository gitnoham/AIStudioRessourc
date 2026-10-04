import type { HarvestedGitFile, IHttpClient, PatternMatch, RawHit } from "@scanner/core";
import type { GithubRepo } from "./github-meta.js";
import { formatMailBlock, isUsableSmtp, parseMailAssignments, smtpApiRoute } from "./smtp-env.js";

export type { HarvestedGitFile };

const HIGH_PRIORITY = new Set([
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
  "auth.json",
]);

const SCAN_EXT = new Set([
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
  ".xml",
]);

const HARVEST_PATTERNS: Array<{ service: string; name: string; re: RegExp }> = [
  { service: "aws", name: "harvest.AKIA", re: /\b(AKIA[A-Z0-9]{16})\b/g },
  {
    service: "aws",
    name: "harvest.secret",
    re: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9+/]{40})["']?/gi,
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
    re: /(?:TWILIO_AUTH_TOKEN|authToken|auth_token)\s*[=:]\s*["']?([0-9a-fA-F]{32})\b/gi,
  },
  { service: "mailgun", name: "harvest.mg", re: /\b(key-[A-Za-z0-9]{32})\b/g },
  { service: "openai", name: "harvest.openai", re: /\b(sk-[A-Za-z0-9]{48,})\b/g },
  { service: "anthropic", name: "harvest.ant", re: /\b(sk-ant-[A-Za-z0-9\-_]{90,110})\b/g },
  { service: "hubspot", name: "harvest.hubspot", re: /\b(pat-(?:na1|eu1)-[a-f0-9-]{36})\b/g },
  { service: "klaviyo", name: "harvest.klaviyo", re: /\b(pk_[a-f0-9]{34})\b/g },
  { service: "clickup", name: "harvest.clickup", re: /\b(pk_[0-9]+_[A-Z0-9]{32})\b/g },
];

const MAX_CREDS = 20;
const MAX_FILE_BYTES = 200 * 1024;
const JUNK = /example|your_|xxx|changeme|placeholder/i;

const JUNK_DIR = /(^|\/)(node_modules|vendor|dist|bower_components|\.next|coverage|__pycache__)\//;

export function shouldScanGitHubBlob(filePath: string, size: number): boolean {
  if (size > MAX_FILE_BYTES) return false;
  if (JUNK_DIR.test(filePath.replace(/\\/g, "/"))) return false;
  const base = filePath.split("/").pop()?.toLowerCase() ?? "";
  if (base.startsWith(".env")) return true;
  if (HIGH_PRIORITY.has(base) || HIGH_PRIORITY.has(filePath.toLowerCase())) return true;
  const dot = base.lastIndexOf(".");
  const ext = dot >= 0 ? base.slice(dot) : "";
  return SCAN_EXT.has(ext);
}

function blobScore(filePath: string): number {
  const base = filePath.split("/").pop()?.toLowerCase() ?? "";
  if (base.startsWith(".env")) return 0;
  if (HIGH_PRIORITY.has(base)) return 1;
  if (/\.(ya?ml|json|php|properties|toml|ini|cfg|conf)$/.test(base)) return 2;
  if (/\.(md|txt|markdown)$/.test(base)) return 8;
  return 4;
}

function preferPrivate<T>(items: T[], isPrivate: (x: T) => boolean): T[] {
  return [...items].sort((a, b) => Number(isPrivate(b)) - Number(isPrivate(a)));
}

export function extractHarvestMatches(content: string): PatternMatch[] {
  const out: PatternMatch[] = [];
  const seen = new Set<string>();
  for (const p of HARVEST_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
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
        patternName: p.name,
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
        patternName: "harvest.smtp",
      });
    }
  }
  return out;
}

function json(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {};
  }
}

function repoFullName(repo: GithubRepo): string {
  if (repo.full_name?.includes("/")) return repo.full_name;
  const owner = repo.owner?.login;
  const name = repo.name;
  if (owner && name) return `${owner}/${name}`;
  return "";
}

export function harvestSummary(fullName: string, filePath: string, matches: PatternMatch[]): string {
  const labels = matches.map((m) => `[${m.service}] ${m.value.length > 80 ? `${m.value.slice(0, 80)}…` : m.value}`);
  return `🚨 ${fullName}/${filePath}\n${labels.join("\n")}`;
}

export async function harvestGitHubRepos(
  http: IHttpClient,
  headers: Record<string, string>,
  repos: GithubRepo[],
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
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

async function crawlRepo(
  http: IHttpClient,
  headers: Record<string, string>,
  fullName: string,
  remaining: number,
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
  let treeRes;
  try {
    treeRes = await http.get(`https://api.github.com/repos/${fullName}/git/trees/HEAD?recursive=1`, {
      budget: "httpRequest",
      headers,
    });
  } catch {
    return found;
  }
  if (treeRes.status !== 200) return found;
  const body = json(treeRes.text) as { tree?: Array<{ path?: string; type?: string; size?: number; sha?: string }> };
  const items = Array.isArray(body.tree) ? body.tree : [];
  const blobs = items
    .filter((item) => item.type === "blob" && item.path && shouldScanGitHubBlob(item.path, Number(item.size ?? 0)))
    .sort((a, b) => blobScore(a.path ?? "") - blobScore(b.path ?? ""));
  for (const item of blobs) {
    if (found.length >= remaining) break;
    const file = await fetchBlob(http, headers, fullName, item.path ?? "", item.sha);
    if (!file) continue;
    found.push(file);
  }
  return found;
}

async function fetchBlob(
  http: IHttpClient,
  headers: Record<string, string>,
  fullName: string,
  filePath: string,
  sha?: string,
): Promise<HarvestedGitFile | null> {
  let res;
  try {
    res = await http.get(`https://api.github.com/repos/${fullName}/contents/${encodeURIComponent(filePath).replace(/%2F/g, "/")}`, {
      budget: "httpRequest",
      headers,
    });
  } catch {
    return null;
  }
  if (res.status !== 200) return null;
  const obj = json(res.text) as { encoding?: string; content?: string; html_url?: string; sha?: string };
  if (obj.encoding !== "base64" || !obj.content) return null;
  let content: string;
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
    forge: "github",
  };
}

function forgePrefix(forge: HarvestedGitFile["forge"]): string {
  if (forge === "gitlab") return "gl-harvest";
  if (forge === "bitbucket") return "bb-harvest";
  return "gh-harvest";
}

function forgeOrigin(file: HarvestedGitFile): string {
  try {
    return new URL(file.htmlUrl).origin;
  } catch {
    if (file.forge === "gitlab") return "https://gitlab.com";
    if (file.forge === "bitbucket") return "https://bitbucket.org";
    return "https://github.com";
  }
}

export function harvestedToHits(files: HarvestedGitFile[]): RawHit[] {
  const hits: RawHit[] = [];
  for (const file of files) {
    const byService = new Map<string, PatternMatch[]>();
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
        contentSnippet: file.content.slice(0, 2500),
      });
    }
  }
  return hits;
}

const GITLAB_BRANCHES = ["HEAD", "main", "master"];

export async function harvestGitLabRepos(
  http: IHttpClient,
  headers: Record<string, string>,
  base: string,
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
  let projRes;
  try {
    projRes = await http.get(
      `${base}/api/v4/projects?membership=true&simple=true&per_page=20&order_by=last_activity_at`,
      { budget: "httpRequest", headers },
    );
  } catch {
    return found;
  }
  if (projRes.status !== 200) return found;
  const list = json(projRes.text) as Array<{ path_with_namespace?: string; visibility?: string }>;
  if (!Array.isArray(list)) return found;
  const projects = preferPrivate(list, (p) => p.visibility !== "public");
  for (const project of projects) {
    if (found.length >= MAX_CREDS) break;
    const fullName = project.path_with_namespace?.trim() ?? "";
    if (!fullName) continue;
    found.push(...(await crawlGitLabProject(http, headers, base, fullName, MAX_CREDS - found.length)));
  }
  return found;
}

async function crawlGitLabProject(
  http: IHttpClient,
  headers: Record<string, string>,
  base: string,
  fullName: string,
  remaining: number,
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
  const id = encodeURIComponent(fullName);
  let treeRes;
  try {
    treeRes = await http.get(`${base}/api/v4/projects/${id}/repository/tree?recursive=true&per_page=100`, {
      budget: "httpRequest",
      headers,
    });
  } catch {
    return found;
  }
  if (treeRes.status !== 200) return found;
  const items = json(treeRes.text) as Array<{ type?: string; path?: string }>;
  if (!Array.isArray(items)) return found;
  const blobs = items
    .filter((item) => item.type === "blob" && item.path && shouldScanGitHubBlob(item.path, 0))
    .sort((a, b) => blobScore(a.path ?? "") - blobScore(b.path ?? ""));
  for (const item of blobs) {
    if (found.length >= remaining) break;
    const file = await fetchGitLabFile(http, headers, base, fullName, item.path ?? "");
    if (file) found.push(file);
  }
  return found;
}

async function fetchGitLabFile(
  http: IHttpClient,
  headers: Record<string, string>,
  base: string,
  fullName: string,
  filePath: string,
): Promise<HarvestedGitFile | null> {
  const id = encodeURIComponent(fullName);
  const encoded = encodeURIComponent(filePath);
  for (const ref of GITLAB_BRANCHES) {
    let res;
    try {
      res = await http.get(`${base}/api/v4/projects/${id}/repository/files/${encoded}/raw?ref=${ref}`, {
        budget: "httpRequest",
        headers,
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
      forge: "gitlab",
    };
  }
  return null;
}

const BB_CANDIDATES = [
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
  "application.properties",
];

export async function harvestBitbucketRepos(
  http: IHttpClient,
  headers: Record<string, string>,
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
  let reposRes;
  try {
    reposRes = await http.get("https://api.bitbucket.org/2.0/repositories?role=member&pagelen=20", {
      budget: "httpRequest",
      headers,
    });
  } catch {
    return found;
  }
  if (reposRes.status !== 200) return found;
  const body = json(reposRes.text) as { values?: Array<{ full_name?: string; is_private?: boolean }> };
  const list = preferPrivate(body.values ?? [], (r) => Boolean(r.is_private));
  for (const repo of list) {
    if (found.length >= MAX_CREDS) break;
    const fullName = repo.full_name?.trim() ?? "";
    if (!fullName) continue;
    found.push(...(await crawlBitbucketRepo(http, headers, fullName, MAX_CREDS - found.length)));
  }
  return found;
}

async function crawlBitbucketRepo(
  http: IHttpClient,
  headers: Record<string, string>,
  fullName: string,
  remaining: number,
): Promise<HarvestedGitFile[]> {
  const found: HarvestedGitFile[] = [];
  const listed = await listBitbucketSrc(http, headers, fullName);
  const paths = listed.length
    ? listed.filter((p) => shouldScanGitHubBlob(p, 0)).sort((a, b) => blobScore(a) - blobScore(b))
    : BB_CANDIDATES;
  for (const filePath of paths) {
    if (found.length >= remaining) break;
    const file = await fetchBitbucketFile(http, headers, fullName, filePath);
    if (file) found.push(file);
  }
  return found;
}

async function listBitbucketSrc(
  http: IHttpClient,
  headers: Record<string, string>,
  fullName: string,
): Promise<string[]> {
  for (const rev of ["HEAD", "main", "master"]) {
    let res;
    try {
      res = await http.get(
        `https://api.bitbucket.org/2.0/repositories/${fullName}/src/${rev}/?max_depth=6&pagelen=100`,
        { budget: "httpRequest", headers },
      );
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    const body = json(res.text) as { values?: Array<{ path?: string; type?: string }> };
    const files = (body.values ?? [])
      .filter((v) => v.path && (v.type === "commit_file" || v.type === "file"))
      .map((v) => v.path as string);
    if (files.length) return files;
  }
  return [];
}

async function fetchBitbucketFile(
  http: IHttpClient,
  headers: Record<string, string>,
  fullName: string,
  filePath: string,
): Promise<HarvestedGitFile | null> {
  for (const rev of ["HEAD", "main", "master"]) {
    let res;
    try {
      res = await http.get(`https://api.bitbucket.org/2.0/repositories/${fullName}/src/${rev}/${filePath}`, {
        budget: "httpRequest",
        headers,
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
      forge: "bitbucket",
    };
  }
  return null;
}

