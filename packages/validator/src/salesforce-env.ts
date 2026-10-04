import type { PatternMatch, RawHit } from "@scanner/core";

const ALIASES: Record<string, string> = {
  SALESFORCE_USERNAME: "SF_USERNAME",
  SFDC_USERNAME: "SF_USERNAME",
  SF_USER: "SF_USERNAME",
  SALESFORCE_USER: "SF_USERNAME",
  SALESFORCE_PASSWORD: "SF_PASSWORD",
  SFDC_PASSWORD: "SF_PASSWORD",
  SALESFORCE_SECURITY_TOKEN: "SF_SECURITY_TOKEN",
  SFDC_SECURITY_TOKEN: "SF_SECURITY_TOKEN",
  SF_TOKEN: "SF_SECURITY_TOKEN",
  SALESFORCE_ACCESS_TOKEN: "SF_ACCESS_TOKEN",
  SF_SESSION_ID: "SF_SESSION_ID",
  SALESFORCE_SESSION_ID: "SF_SESSION_ID",
  SALESFORCE_CLIENT_ID: "SF_CLIENT_ID",
  SF_CONSUMER_KEY: "SF_CLIENT_ID",
  SALESFORCE_CONSUMER_KEY: "SF_CLIENT_ID",
  SALESFORCE_CLIENT_SECRET: "SF_CLIENT_SECRET",
  SALESFORCE_CONSUMER_SECRET: "SF_CLIENT_SECRET",
  SF_CONSUMER_SECRET: "SF_CLIENT_SECRET",
  SALESFORCE_INSTANCE_URL: "SF_INSTANCE_URL",
  SF_URL: "SF_INSTANCE_URL",
  SALESFORCE_LOGIN_URL: "SF_LOGIN_URL",
  SF_LOGIN_URL: "SF_LOGIN_URL",
};

const KEY_RE =
  /\b(SALESFORCE_[A-Z0-9_]+|SFDC_[A-Z0-9_]+|SF_[A-Z0-9_]+)\s*=[ \t]*/gi;

const SESSION_RE = /\b(00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{50,})\b/g;
const INSTANCE_RE = /https:\/\/[a-z0-9.-]+\.(?:my\.)?salesforce\.com(?:\/[^\s"'<>]*)?/i;

export function canonicalSfKey(raw: string): string {
  const key = raw.toUpperCase();
  return ALIASES[key] ?? key;
}

export function parseSalesforceAssignments(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  KEY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = KEY_RE.exec(text))) {
    const canon = canonicalSfKey(m[1]);
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
  SESSION_RE.lastIndex = 0;
  const sid = SESSION_RE.exec(text);
  if (sid && !env.SF_SESSION_ID) env.SF_SESSION_ID = sid[1];
  const inst = text.match(INSTANCE_RE);
  if (inst && !env.SF_INSTANCE_URL) env.SF_INSTANCE_URL = inst[0].replace(/\/+$/, "");
  return env;
}

export function collectSalesforceEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string> {
  const blob = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}\n${s.value}`)].join(
    "\n",
  );
  const env = parseSalesforceAssignments(blob);
  for (const s of [match, ...siblings]) {
    if (s.service !== "salesforce") continue;
    const v = s.value.trim();
    if (!v) continue;
    if (/^00D[A-Za-z0-9]{12,15}!/.test(v) && !env.SF_SESSION_ID) env.SF_SESSION_ID = v;
    else if (/^https:\/\//i.test(v) && !env.SF_INSTANCE_URL) env.SF_INSTANCE_URL = v;
  }
  return env;
}

export function formatSalesforceBlock(env: Record<string, string>): string {
  const keys = [
    "SF_USERNAME",
    "SF_PASSWORD",
    "SF_SECURITY_TOKEN",
    "SF_SESSION_ID",
    "SF_ACCESS_TOKEN",
    "SF_CLIENT_ID",
    "SF_CLIENT_SECRET",
    "SF_INSTANCE_URL",
    "SF_LOGIN_URL",
  ];
  return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}

export function isUsableSalesforce(env: Record<string, string>): boolean {
  if (env.SF_SESSION_ID && env.SF_SESSION_ID.length > 40) return true;
  if (env.SF_ACCESS_TOKEN && env.SF_ACCESS_TOKEN.length > 20) return true;
  if (env.SF_USERNAME && env.SF_PASSWORD) return true;
  if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET && env.SF_CLIENT_SECRET.length >= 8) return true;
  return false;
}

export function salesforceFingerprint(env: Record<string, string>): string {
  if (env.SF_SESSION_ID) return `sf:sid:${env.SF_SESSION_ID}`;
  if (env.SF_ACCESS_TOKEN) return `sf:at:${env.SF_ACCESS_TOKEN}`;
  if (env.SF_USERNAME && env.SF_PASSWORD) {
    return `sf:up:${env.SF_USERNAME}:${env.SF_PASSWORD}:${env.SF_SECURITY_TOKEN ?? ""}`;
  }
  if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET) return `sf:oauth:${env.SF_CLIENT_ID}:${env.SF_CLIENT_SECRET}`;
  return "";
}
