import type { PatternMatch, RawHit } from "@scanner/core";

const REFRESH_RE = /\b(1000\.[a-zA-Z0-9]{20,40}\.[a-zA-Z0-9]{20,40})\b/;
const CLIENT_RE = /\b(1000\.[A-Za-z0-9]{20,40})(?!\.[A-Za-z0-9])/;

const ALIASES: Record<string, string> = {
  ZOHO_CRM_CLIENT_ID: "ZOHO_CLIENT_ID",
  ZOHO_CRM_CLIENT_SECRET: "ZOHO_CLIENT_SECRET",
  ZOHO_SECRET: "ZOHO_CLIENT_SECRET",
  ZOHO_AUTH_TOKEN: "ZOHO_REFRESH_TOKEN",
  ZOHO_CRM_REFRESH_TOKEN: "ZOHO_REFRESH_TOKEN",
  ZOHO_DC: "ZOHO_DC",
  ZOHO_REGION: "ZOHO_DC",
  ZOHO_ACCOUNTS_URL: "ZOHO_ACCOUNTS_URL",
};

const KEY_RE = /\b(ZOHO_[A-Z0-9_]+)\s*[=:][ \t]*/gi;

export function parseZohoAssignments(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  KEY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = KEY_RE.exec(text))) {
    const canon = ALIASES[m[1].toUpperCase()] ?? m[1].toUpperCase();
    const start = m.index + m[0].length;
    const rest = text.slice(start);
    const quote = rest[0];
    let value = "";
    if (quote === '"' || quote === "'") {
      const end = rest.indexOf(quote, 1);
      value = (end >= 0 ? rest.slice(1, end) : rest.slice(1).split(/\s/, 1)[0] ?? "").trim();
    } else {
      value = (rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
    }
    if (value) env[canon] = value;
  }
  const refresh = text.match(REFRESH_RE);
  if (refresh && !env.ZOHO_REFRESH_TOKEN) env.ZOHO_REFRESH_TOKEN = refresh[1];
  if (!env.ZOHO_CLIENT_ID) {
    const c = text.match(CLIENT_RE);
    if (c?.[1]) env.ZOHO_CLIENT_ID = c[1];
  }
  const dc = text.match(/accounts\.zoho\.([a-z.]+)/i) ?? text.match(/zohoapis\.([a-z.]+)/i);
  if (dc && !env.ZOHO_DC) env.ZOHO_DC = dc[1].replace(/\/$/, "");
  return env;
}

export function collectZohoEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string> {
  const blob = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}\n${s.value}`)].join(
    "\n",
  );
  const env = parseZohoAssignments(blob);
  for (const s of [match, ...siblings]) {
    if (s.service !== "zoho") continue;
    const v = s.value.trim();
    if (REFRESH_RE.test(v) && !env.ZOHO_REFRESH_TOKEN) env.ZOHO_REFRESH_TOKEN = v.match(REFRESH_RE)![1];
    else if (CLIENT_RE.test(v) && v.split(".").length === 2 && !env.ZOHO_CLIENT_ID) env.ZOHO_CLIENT_ID = v;
    else if (v.length >= 32 && !v.startsWith("1000.") && !env.ZOHO_CLIENT_SECRET) env.ZOHO_CLIENT_SECRET = v;
  }
  return env;
}

export function formatZohoBlock(env: Record<string, string>): string {
  const keys = ["ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REFRESH_TOKEN", "ZOHO_ACCESS_TOKEN", "ZOHO_DC"];
  return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}

export function isUsableZoho(env: Record<string, string>): boolean {
  return !!(env.ZOHO_CLIENT_ID && env.ZOHO_CLIENT_SECRET && env.ZOHO_REFRESH_TOKEN);
}

export function zohoFingerprint(env: Record<string, string>): string {
  if (env.ZOHO_REFRESH_TOKEN) return `zoho:${env.ZOHO_REFRESH_TOKEN}`;
  if (env.ZOHO_ACCESS_TOKEN) return `zoho:at:${env.ZOHO_ACCESS_TOKEN}`;
  return "";
}

export function zohoDcHosts(env: Record<string, string>): { accounts: string; api: string; dc: string }[] {
  const ordered = ["com", "eu", "in", "com.au", "jp"];
  const preferred = (env.ZOHO_DC ?? "").replace(/^zoho\.?/i, "").replace(/^\./, "") || domainFromUrl(env.ZOHO_ACCOUNTS_URL);
  const dcs = preferred ? [preferred, ...ordered.filter((d) => d !== preferred)] : ordered;
  return dcs.map((dc) => ({
    dc,
    accounts: `https://accounts.zoho.${dc}`,
    api: `https://www.zohoapis.${dc}`,
  }));
}

function domainFromUrl(url?: string): string {
  if (!url) return "";
  const m = url.match(/zoho\.([a-z.]+)/i);
  return m?.[1] ?? "";
}
