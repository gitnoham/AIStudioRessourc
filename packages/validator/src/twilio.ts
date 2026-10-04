import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";

const SID_RE = /\b(AC[0-9a-fA-F]{32})\b/;
const SK_RE = /\b(SK[0-9a-fA-F]{32})\b/;
const TOKEN_RE = /\b([0-9a-fA-F]{32})\b/;
const TWILIO_HINT = /twilio|accountsid|account_sid|authtoken|auth_token/i;

export interface TwilioCreds {
  sid: string;
  token: string;
  apiKey: string;
  encoded: string;
}

export function collectTwilioCreds(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): TwilioCreds {
  const blob = [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context), ...[match, ...siblings].map((s) => s.value)].join(
    "\n",
  );
  let sid = [match, ...siblings].find((s) => SID_RE.test(s.value))?.value.match(SID_RE)?.[1] ?? "";
  let apiKey = [match, ...siblings].find((s) => SK_RE.test(s.value))?.value.match(SK_RE)?.[1] ?? "";
  const used = new Set([sid.slice(2).toLowerCase(), apiKey.slice(2).toLowerCase()].filter(Boolean));
  let token = "";
  for (const s of [match, ...siblings]) {
    const m = s.value.match(TOKEN_RE);
    if (!m) continue;
    const hex = m[1];
    if (used.has(hex.toLowerCase())) continue;
    if (SID_RE.test(s.value) || SK_RE.test(s.value)) continue;
    token = hex;
    break;
  }
  if (!sid) sid = blob.match(SID_RE)?.[1] ?? "";
  if (!apiKey) apiKey = blob.match(SK_RE)?.[1] ?? "";
  if (!token) {
    for (const m of blob.matchAll(new RegExp(TOKEN_RE.source, "g"))) {
      const hex = m[1];
      if (used.has(hex.toLowerCase())) continue;
      if (hex === sid.slice(2) || hex === apiKey.slice(2)) continue;
      token = hex;
      break;
    }
  }
  let encoded = "";
  const b64 = blob.match(/\b([A-Za-z0-9+/]{40,}={0,2})\b/);
  if (b64) {
    try {
      const decoded = Buffer.from(b64[1], "base64").toString("utf8");
      const parts = decoded.split(":");
      if (parts.length >= 2 && SID_RE.test(parts[0]) && TOKEN_RE.test(parts[1])) {
        encoded = b64[1];
        sid = sid || parts[0].match(SID_RE)![1];
        token = token || parts[1].match(TOKEN_RE)![1];
      }
    } catch {
      /* ignore */
    }
  }
  return { sid, token, apiKey, encoded };
}

export function looksLikeTwilio(hit: RawHit, match: PatternMatch, creds: TwilioCreds): boolean {
  if (creds.sid && creds.token) return true;
  if (creds.apiKey && creds.token) return true;
  if (creds.encoded) return true;
  const blob = `${match.context} ${hit.contentSnippet ?? ""} ${match.patternName}`;
  return TWILIO_HINT.test(blob);
}

function json(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {};
  }
}

function basic(user: string, pass: string): Record<string, string> {
  return { authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` };
}

export class TwilioHandler implements ValidationHandler {
  readonly service = "twilio";
  constructor(private readonly http: IHttpClient) {}

  async validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const creds = collectTwilioCreds(hit, match, siblings);
    if (!creds.sid || !creds.token) {
      return { service: "twilio", valid: false, raw: true, details: "pas une paire Twilio", meta: { skipNotify: "1" } };
    }
    const user = creds.apiKey || creds.sid;
    const headers = basic(user, creds.token);
    try {
      const acct = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${creds.sid}.json`, {
        budget: "httpRequest",
        headers,
      });
      if (acct.status === 401 || acct.status === 403) {
        return {
          service: "twilio",
          valid: false,
          details: `HTTP ${acct.status}`,
          error: acct.text.slice(0, 120),
          meta: { accountSid: creds.sid, authToken: creds.token },
        };
      }
      if (acct.status !== 200) {
        return {
          service: "twilio",
          valid: false,
          raw: true,
          details: `HTTP ${acct.status}`,
          meta: { accountSid: creds.sid, authToken: creds.token },
        };
      }
      const a = json(acct.text) as { friendly_name?: string; status?: string; type?: string };
      const extra = await this.balanceAndNumbers(creds.sid, headers);
      return {
        service: "twilio",
        valid: true,
        details: `Nom: ${a.friendly_name ?? "N/A"} | Solde: ${extra.balance} | Numéros: ${extra.numbers}`,
        meta: {
          accountSid: creds.sid,
          authToken: creds.token,
          encoded: creds.encoded,
          friendlyName: a.friendly_name ?? "N/A",
          accountStatus: a.status ?? "N/A",
          accountType: a.type ?? "N/A",
          balance: extra.balance,
          numbers: extra.numbers,
        },
      };
    } catch (err) {
      return {
        service: "twilio",
        valid: false,
        details: "request failed",
        error: (err as Error).message,
        meta: { statusKind: "unverified-network", accountSid: creds.sid, authToken: creds.token },
      };
    }
  }

  private async balanceAndNumbers(
    sid: string,
    headers: Record<string, string>,
  ): Promise<{ balance: string; numbers: string }> {
    let balance = "N/A";
    let numbers = "Aucun";
    try {
      const bal = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Balance.json`, {
        budget: "httpRequest",
        headers,
      });
      if (bal.status === 200) {
        const b = json(bal.text) as { balance?: string; currency?: string };
        balance = `${b.balance ?? "0"} ${b.currency ?? "USD"}`;
      }
    } catch {
      /* ignore */
    }
    try {
      const num = await this.http.get(`https://api.twilio.com/2010-04-01/Accounts/${sid}/IncomingPhoneNumbers.json`, {
        budget: "httpRequest",
        headers,
      });
      if (num.status === 200) {
        const n = json(num.text) as { incoming_phone_numbers?: Array<{ phone_number?: string }> };
        const list = (n.incoming_phone_numbers ?? []).map((x) => x.phone_number).filter(Boolean) as string[];
        if (list.length) numbers = list.slice(0, 5).join(", ");
      }
    } catch {
      /* ignore */
    }
    return { balance, numbers };
  }
}
