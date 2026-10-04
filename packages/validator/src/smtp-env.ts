import { isAwsAccessKey, isValidAwsSecretKey } from "@scanner/core";
import type { PatternMatch, RawHit } from "@scanner/core";

const SENDGRID_KEY = /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

const KEY_START =
  /\b(MAIL_[A-Z0-9_]+|SMTP_[A-Z0-9_]+|EMAIL_HOST(?:_USER|_PASSWORD)?|MAILER_[A-Z_]+|DEFAULT_FROM_EMAIL|SENDER_EMAIL|FROM_EMAIL|FROM_ADDRESS|NOREPLY_EMAIL|NO_REPLY_EMAIL|WP_MAIL_FROM|WORDPRESS_SMTP_FROM|EMAIL_FROM)\s*=[ \t]*/gi;

const ALIASES: Record<string, string> = {
  SMTP_HOST: "MAIL_HOST",
  SMTP_SERVER: "MAIL_HOST",
  EMAIL_HOST: "MAIL_HOST",
  MAILER_HOST: "MAIL_HOST",
  MAIL_SMTP_HOST: "MAIL_HOST",
  MAIL_SERVER: "MAIL_HOST",
  SMTP_PORT: "MAIL_PORT",
  EMAIL_PORT: "MAIL_PORT",
  SMTP_USERNAME: "MAIL_USERNAME",
  SMTP_USER: "MAIL_USERNAME",
  MAIL_USER: "MAIL_USERNAME",
  EMAIL_HOST_USER: "MAIL_USERNAME",
  SMTP_PASSWORD: "MAIL_PASSWORD",
  SMTP_PASS: "MAIL_PASSWORD",
  MAIL_PASS: "MAIL_PASSWORD",
  EMAIL_HOST_PASSWORD: "MAIL_PASSWORD",
  SMTP_ENCRYPTION: "MAIL_ENCRYPTION",
  MAIL_FROM: "MAIL_FROM_ADDRESS",
  MAIL_FROM_ADDR: "MAIL_FROM_ADDRESS",
  MAIL_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  MAIL_SENDER: "MAIL_FROM_ADDRESS",
  MAIL_SEND_FROM: "MAIL_FROM_ADDRESS",
  SMTP_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  SMTP_FROM: "MAIL_FROM_ADDRESS",
  SMTP_SENDER: "MAIL_FROM_ADDRESS",
  EMAIL_FROM: "MAIL_FROM_ADDRESS",
  DEFAULT_FROM_EMAIL: "MAIL_FROM_ADDRESS",
  SENDER_EMAIL: "MAIL_FROM_ADDRESS",
  FROM_EMAIL: "MAIL_FROM_ADDRESS",
  FROM_ADDRESS: "MAIL_FROM_ADDRESS",
  NOREPLY_EMAIL: "MAIL_FROM_ADDRESS",
  NO_REPLY_EMAIL: "MAIL_FROM_ADDRESS",
  WP_MAIL_FROM: "MAIL_FROM_ADDRESS",
  WORDPRESS_SMTP_FROM: "MAIL_FROM_ADDRESS",
  SMTP_FROM_NAME: "MAIL_FROM_NAME",
  MAIL_SENDER_NAME: "MAIL_FROM_NAME",
  EMAIL_FROM_NAME: "MAIL_FROM_NAME",
};

export function isFullSendGridKey(value: string): boolean {
  return SENDGRID_KEY.test(value.trim());
}

export function canonicalMailKey(raw: string): string {
  const key = raw.toUpperCase();
  return ALIASES[key] ?? key;
}

export function parseMailAssignments(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  const blob = sanitizeMailBlob(text);
  KEY_START.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = KEY_START.exec(blob))) {
    const canon = canonicalMailKey(m[1]);
    const start = m.index + m[0].length;
    const { value, consumed } = readMailValue(blob, start, canon);
    KEY_START.lastIndex = start + Math.max(consumed, 1);
    if (value) env[canon] = preferMailValue(canon, env[canon], value);
  }
  if (env.MAIL_USERNAME) env.MAIL_USERNAME = cleanMailUser(env.MAIL_USERNAME);
  if (env.MAIL_FROM_ADDRESS) {
    const email = env.MAIL_FROM_ADDRESS.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
    if (email) env.MAIL_FROM_ADDRESS = email[0];
  }
  if (env.MAIL_ENCRYPTION && !/^(ssl|tls|starttls|none)$/i.test(env.MAIL_ENCRYPTION)) {
    delete env.MAIL_ENCRYPTION;
  }
  return env;
}

/** Vim .swp / git blobs: NULs and control bytes glue MAIL_* into one token. */
function sanitizeMailBlob(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ");
}

function cleanMailUser(user: string): string {
  const first = user.trim().split(/\s+/)[0] ?? "";
  const glued = first.search(/(?:MAIL_|SMTP_|MAILER_|EMAIL_HOST)/);
  return (glued > 0 ? first.slice(0, glued) : first).trim();
}

/** Truncated ±80 match windows must not win over a later full password (SES 44-char + `/`). */
function preferMailValue(key: string, current: string | undefined, next: string): string {
  if (!next) return current ?? "";
  if (!current) return next;
  if (key === "MAIL_PASSWORD" || /PASS/i.test(key)) {
    if (next.startsWith(current) && next.length > current.length) return next;
    if (current.startsWith(next)) return current;
    return next.length > current.length ? next : current;
  }
  return current;
}

function readMailValue(text: string, start: number, key: string): { value: string; consumed: number } {
  const rest = text.slice(start);
  if (!rest) return { value: "", consumed: 0 };
  const quote = rest[0];
  if (quote === '"' || quote === "'") {
    const end = rest.indexOf(quote, 1);
    if (end >= 0) return { value: rest.slice(1, end).trim(), consumed: end + 1 };
    const cut = nextAssignmentIndex(rest.slice(1));
    const raw = (cut >= 0 ? rest.slice(1, 1 + cut) : rest.slice(1).split(/\r?\n/, 1)[0] ?? "").trim();
    return { value: raw, consumed: cut >= 0 ? 1 + cut : 1 + raw.length };
  }
  if (key === "MAIL_FROM_NAME") {
    if (/^(?:\r?\n|(?:MAIL_|SMTP_|EMAIL_HOST))/.test(rest)) {
      return { value: "", consumed: rest.startsWith("\r\n") ? 2 : rest.startsWith("\n") || rest.startsWith("\r") ? 1 : 0 };
    }
    const cut = rest.search(/\s+(?:MAIL_|SMTP_|EMAIL_HOST)|[\r\n;#]/);
    const value = (cut >= 0 ? rest.slice(0, cut) : rest).trim();
    return { value, consumed: cut >= 0 ? cut : rest.length };
  }
  if (/PASS/i.test(key)) {
    const grouped = rest.match(/^[A-Za-z0-9]{4}(?:[ \t]+[A-Za-z0-9]{4}){3}(?=[\s#;\r\n]|$)/);
    if (grouped) return { value: grouped[0].replace(/\s+/g, " ").trim(), consumed: grouped[0].length };
    const cut = nextAssignmentIndex(rest);
    const raw = cut >= 0 ? rest.slice(0, cut) : rest.match(/^[^\s#;]+/)?.[0] ?? "";
    const split = cutGluedAssignment(raw.trim());
    return {
      value: split.value,
      consumed: split.gluedAt >= 0 ? split.gluedAt : cut >= 0 ? cut : raw.length || 1,
    };
  }
  const cut = nextAssignmentIndex(rest);
  let value = (cut >= 0 ? rest.slice(0, cut) : rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
  const split = cutGluedAssignment(value);
  value = split.value.split(/\s+/)[0] ?? "";
  return {
    value,
    consumed: split.gluedAt >= 0 ? split.gluedAt : cut >= 0 ? cut : (rest.match(/^[^\s#;]+/)?.[0]?.length ?? 1),
  };
}

/** `COMMON_MAIL_FROM=` / `COMMON_LOG_EMAIL_TO=` — next key glued without space. */
function cutGluedAssignment(value: string): { value: string; gluedAt: number } {
  const glued = value.search(/(?:MAIL_|SMTP_|EMAIL_HOST|MAILER_|LOG_EMAIL_)[A-Z0-9_]*=/);
  if (glued > 0) return { value: value.slice(0, glued), gluedAt: glued };
  return { value, gluedAt: -1 };
}

/** Cut before the next ENV assignment (` MAIL_FROM_NAME=` / ` APP_KEY=`). */
function nextAssignmentIndex(rest: string): number {
  const cut = rest.search(/\s+[A-Z][A-Z0-9_]{2,64}=/);
  return cut;
}

export function collectMailEnv(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Record<string, string> {
  const blob = [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context)].join("\n");
  const env = parseMailAssignments(blob);

  const all = [match, ...siblings].filter((s) =>
    s.service === "smtp" || s.service === "smtp.host" || s.service === "xsmtp" || s.service === "emailsmtp",
  );
  for (const s of all) {
    const name = canonicalMailKey(s.patternName);
    const value = firstToken(sanitizeMailBlob(s.value));
    if (!value) continue;
    if (!env.MAIL_HOST && (name === "MAIL_HOST" || /HOST|SERVER|RELAY/.test(name) || isHost(value))) {
      env.MAIL_HOST = value;
    } else if (!env.MAIL_USERNAME && (name === "MAIL_USERNAME" || /USER|LOGIN/.test(name) || value.includes("@"))) {
      env.MAIL_USERNAME = cleanMailUser(value);
    } else if (name === "MAIL_PASSWORD" || /PASS|SECRET/.test(name)) {
      env.MAIL_PASSWORD = preferMailValue("MAIL_PASSWORD", env.MAIL_PASSWORD, value);
    } else if (!env.MAIL_FROM_ADDRESS && /FROM/.test(name) && value.includes("@")) {
      env.MAIL_FROM_ADDRESS = value;
    } else if (!env.MAIL_PORT && /PORT/.test(name) && /^\d{2,5}$/.test(value)) {
      env.MAIL_PORT = value;
    }
  }
  if (!env.MAIL_PORT) env.MAIL_PORT = "587";
  if (!env.MAIL_ENCRYPTION) env.MAIL_ENCRYPTION = env.MAIL_PORT === "465" ? "ssl" : "tls";
  if (
    !env.MAIL_FROM_ADDRESS &&
    env.MAIL_USERNAME?.includes("@") &&
    !looksLikeJsSmtpValue(env.MAIL_USERNAME)
  ) {
    env.MAIL_FROM_ADDRESS = env.MAIL_USERNAME;
  }
  return env;
}

function firstToken(v: string): string {
  return v.trim().split(/\s+/)[0] ?? "";
}

function isHost(v: string): boolean {
  return /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v) && !v.includes("@");
}

function looksLikeJsSmtpValue(v: string): boolean {
  const s = v.trim();
  if (!s) return true;
  if (JS_SMTP_JUNK.test(s)) return true;
  if (/\.env\./i.test(s)) return true;
  if (/^\(?n?\s*==null/.test(s) || /^\(n==null/.test(s)) return true;
  if (/[)}\]]{2,}/.test(s) && /[()]/.test(s)) return true;
  return false;
}

function isPlausibleMailHost(host: string): boolean {
  if (!isHost(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
  if (PLACEHOLDER_HOST.test(host)) return false;
  if (looksLikeJsSmtpValue(host)) return false;
  if (FAKE_SMTP_TLD.test(host)) return false;
  return true;
}

export function formatMailBlock(env: Record<string, string>): string {
  const keys = [
    "MAIL_HOST",
    "MAIL_PORT",
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "MAIL_ENCRYPTION",
    "MAIL_FROM_ADDRESS",
    "MAIL_FROM_NAME",
  ];
  const lines: string[] = [];
  for (const k of keys) {
    if (env[k]) lines.push(`${k}=${env[k]}`);
  }
  return lines.join("\n");
}

/** Same mailbox: host + username, password ignored (rotated .env.save vs .save.1). */
export function smtpAccountKey(env: Record<string, string>): string {
  const host = (env.MAIL_HOST ?? "").trim().toLowerCase();
  const user = (env.MAIL_USERNAME ?? "").trim();
  return `${host}:${user}`;
}

/** Hold AUTH-fail until sibling dumps AUTH, then skip if that mailbox is already valid. */
export function shouldHoldSmtpInvalid(opts: {
  alreadyValid: boolean;
  alreadyNotifiedAccount: boolean;
  otherPending: number;
  alreadyDeferred: boolean;
}): "skip" | "defer" | "emit" {
  if (opts.alreadyValid || opts.alreadyNotifiedAccount) return "skip";
  if (!opts.alreadyDeferred && opts.otherPending > 1) return "defer";
  return "emit";
}

export type SmtpApiRoute = "sendgrid" | "mailgun" | "brevo" | null;

export function smtpApiRoute(env: Record<string, string>): SmtpApiRoute {
  const pass = env.MAIL_PASSWORD?.trim() ?? "";
  const host = (env.MAIL_HOST ?? "").toLowerCase();
  if (pass.startsWith("SG.")) return "sendgrid";
  if ((pass.startsWith("key-") || pass.startsWith("pubkey-")) && host.includes("mailgun")) return "mailgun";
  if (pass.startsWith("xkeysib-")) return "brevo";
  return null;
}

export function smtpBrand(host: string): string {
  const h = host.toLowerCase();
  if (h.includes("gmail") || h.includes("google")) return "📧 SMTP Gmail";
  if (h.includes("zoho")) return "📧 SMTP Zoho";
  if (h.includes("zeptomail")) return "📧 SMTP ZeptoMail";
  if (h.includes("outlook") || h.includes("office365") || h.includes("microsoft")) return "📧 SMTP Microsoft";
  if (h.includes("sendgrid")) return "📧 SMTP SendGrid";
  return "📧 SMTP Générique";
}

const PLACEHOLDER_HOST =
  /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$|mail\.mailers\.smtp\.host|(^|\.)(smtp|mail)\.(example|provider|test|localhost)\.(com|org|net)$|\.example\.(com|org|net)$|mailhog|mailpit|mailcatcher|^smtp\.host$|^mail\.server$/i;

/** Next/Zod bundles + minified forms: `P.target.value`, `smtp_pass:m.password`, `parseInt(...)`. */
const JS_SMTP_JUNK =
  /\.optional\s*\(|\.min\s*\(\d+\)|\.email\s*\(|Yj\s*\(|\.pipe\s*\(|\.default\s*\(|\.coerce|z\.string|z\.literal|\.z\.string|process\.env|os\.environ|os\.getenv|getenv\s*\(|\$_ENV|System\.getenv|\.env\.(?:SMTP|MAIL|EMAIL)|SMTP_PASSWORD:|SMTP_FROM_|SMTP_HOST:|SMTP_PORT:|SMTP_AUTH_|smtp_pass:|poll_interval|\bparseInt\s*\(|\bString\s*\(|\.type===|==null|\?void|void\s*0/i;

const FAKE_SMTP_TLD =
  /\.(smtp|mail|env|user|pass|password|host|username|string|value|target|type|current|length|props|state|form|input|event|optional|literal|interval)$/i;

const PLACEHOLDER_VALUE =
  /^(null|undefined|none|nil|changeme|change_me|changemeplease|password|secret|smtp_password|your-?password|your_password|xxxxx+|\*+|placeholder|insert_.*|replace_.*|common_?)$/i;

const PLACEHOLDER_USER =
  /^(null|undefined|none|username|user|mailer|your-?email@.*|user@example\.com|email@example\.com)$/i;

const TUTORIAL_SMTP =
  /your|example|dummy|placeholder|changeme|sample|insert|replace|generatedfrom|apppassword|gmailemail|username|password/i;

const DOCS_SMTP_URL =
  /\/posts\/|\/blog\/|\/tutorials?\/|\/docs\/|laravel|send-an-email|using-gmail|stackoverflow|medium\.com|dev\.to/i;

const API_SMTP_USER = /^(emailapikey|apikey)$/i;

function looksLikeTutorialToken(v: string): boolean {
  const s = v.trim().replace(/^["']|["']$/g, "");
  if (!s) return true;
  if (API_SMTP_USER.test(s)) return false;
  if (PLACEHOLDER_VALUE.test(s) || PLACEHOLDER_USER.test(s)) return true;
  if (/^(COMMON|SAMPLE|DUMMY|DEFAULT)_[A-Z0-9_]*$/i.test(s)) return true;
  if (/=/.test(s) && /(?:MAIL_|SMTP_|EMAIL_|LOG_EMAIL_)/.test(s)) return true;
  if (/your[A-Z]/.test(s)) return true;
  if (/^your[-_]?/i.test(s) && !/@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s)) return true;
  if (s.includes("@")) {
    return /@(?:example|test|localhost)\.(?:com|org|net)$/i.test(s);
  }
  if (TUTORIAL_SMTP.test(s) && /gmail|email|password|user|secret|token|example|dummy/i.test(s) && s.length < 64) {
    return true;
  }
  return false;
}

export function isTutorialSmtpHit(hit: RawHit): boolean {
  const u = `${hit.url} ${hit.path ?? ""}`;
  if (hit.source === "recon" || hit.source === "homepage" || hit.source === "js") {
    if (DOCS_SMTP_URL.test(u)) return true;
  }
  return false;
}

export function isUsableSmtp(env: Record<string, string>): boolean {
  const host = (env.MAIL_HOST ?? "").trim();
  const user = (env.MAIL_USERNAME ?? "").trim();
  const pass = (env.MAIL_PASSWORD ?? "").trim();
  if (!host || !user || !pass) return false;
  if (pass.length < 4) return false;
  if (!isPlausibleMailHost(host)) return false;
  if (looksLikeJsSmtpValue(user) || looksLikeJsSmtpValue(pass)) return false;
  if (looksLikeTutorialToken(user) || looksLikeTutorialToken(pass)) return false;
  return true;
}

export function isStripeSecret(v: string): boolean {
  return /^(sk_|rk_)(live|test)_/.test(v.trim());
}

function smtpFamily(service: string): boolean {
  const s = service.endsWith(".host") ? service.slice(0, -5) : service;
  return s === "smtp" || s === "xsmtp" || s === "emailsmtp";
}

export function credentialFingerprints(hit: RawHit): string[] {
  const keys = new Set<string>();
  const dummy: PatternMatch = hit.matches[0] ?? {
    service: "smtp",
    value: "",
    context: "",
    lineNumber: 0,
    patternName: "",
  };
  const env = collectMailEnv(hit, dummy, hit.matches);
  const route = smtpApiRoute(env);

  const byService = new Map<string, PatternMatch[]>();
  for (const m of hit.matches) {
    const service = m.service.endsWith(".host") ? m.service.slice(0, -5) : m.service;
    const list = byService.get(service) ?? [];
    list.push(m);
    byService.set(service, list);
  }

  for (const [service, matches] of byService) {
    if (smtpFamily(service)) {
      if (isTutorialSmtpHit(hit)) continue;
      if (route === "sendgrid") {
        if (isFullSendGridKey(env.MAIL_PASSWORD ?? "")) keys.add(`sg:${env.MAIL_PASSWORD!.trim()}`);
        continue;
      }
      if (route === "mailgun" && env.MAIL_PASSWORD) {
        keys.add(`mg:${env.MAIL_PASSWORD}`);
        continue;
      }
      if (route === "brevo" && env.MAIL_PASSWORD) {
        keys.add(`brevo:${env.MAIL_PASSWORD}`);
        continue;
      }
      if (env.MAIL_HOST && isUsableSmtp(env)) {
        keys.add(`smtp:${env.MAIL_HOST}:${env.MAIL_USERNAME ?? ""}:${env.MAIL_PASSWORD ?? ""}`);
      }
      continue;
    }
    if (service === "sendgrid") {
      for (const m of matches) {
        if (isFullSendGridKey(m.value)) keys.add(`sg:${m.value.trim()}`);
      }
      continue;
    }
    if (service === "aws") {
      const akia = matches.find((m) => isAwsAccessKey(m.value))?.value;
      const secret = matches.find((m) => isValidAwsSecretKey(m.value))?.value;
      if (akia && secret) keys.add(`aws:${akia}:${secret}`);
      continue;
    }
    if (service === "stripe") {
      for (const m of matches) {
        if (isStripeSecret(m.value)) keys.add(`stripe:${m.value.trim()}`);
      }
      continue;
    }
    if (service === "twilio") {
      const credsSid = matches.find((m) => /^AC[0-9a-fA-F]{32}$/.test(m.value))?.value;
      const credsTok = matches.find((m) => /^[0-9a-fA-F]{32}$/.test(m.value) && !/^AC/.test(m.value) && !/^SK/.test(m.value))?.value;
      const blobSid = (hit.contentSnippet ?? "").match(/\b(AC[0-9a-fA-F]{32})\b/)?.[1];
      const sid = credsSid || blobSid;
      const tok = credsTok;
      if (sid && tok) keys.add(`twilio:${sid}:${tok}`);
      continue;
    }
    for (const m of matches) {
      if (m.value) keys.add(`${service}:${m.value}`);
    }
  }

  if (route === "sendgrid" && isFullSendGridKey(env.MAIL_PASSWORD ?? "")) {
    keys.add(`sg:${env.MAIL_PASSWORD!.trim()}`);
  }
  return [...keys];
}
