import type { IHttpClient, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";
import {
  collectSalesforceEnv,
  formatSalesforceBlock,
  isUsableSalesforce,
} from "./salesforce-env.js";
import { collectAzureEnv, formatAzureBlock, isUsableAzure } from "./azure-env.js";
import { collectZohoEnv, formatZohoBlock, isUsableZoho, zohoDcHosts } from "./zoho-env.js";

function json(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {};
  }
}

function xmlEsc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function xmlTag(xml: string, tag: string): string {
  const m = xml.match(new RegExp(`<(?:[\\w]+:)?${tag}>([^<]*)</(?:[\\w]+:)?${tag}>`, "i"));
  return (m?.[1] ?? "").trim();
}

function form(data: Record<string, string>): string {
  return Object.entries(data)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

function skip(service: string, details: string): ValidationResult {
  return { service, valid: false, raw: true, details, meta: { skipNotify: "1" } };
}

function netSkip(service: string, err: unknown): ValidationResult {
  return skip(service, (err as Error).message || "réseau");
}

export class SalesforceHandler implements ValidationHandler {
  readonly service = "salesforce";
  constructor(private readonly http: IHttpClient) {}

  async validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const env = collectSalesforceEnv(hit, match, siblings);
    const block = formatSalesforceBlock(env);
    if (!isUsableSalesforce(env)) return skip(this.service, "salesforce incomplet — skip");
    try {
      const token = env.SF_SESSION_ID || env.SF_ACCESS_TOKEN || "";
      if (token) {
        const info = await this.userinfo(token, env.SF_INSTANCE_URL);
        if (info) return this.ok(block, info, env);
        return {
          service: this.service,
          valid: false,
          details: "session rejetée",
          meta: { envBlock: block },
        };
      }
      if (env.SF_USERNAME && env.SF_PASSWORD) {
        const login = await this.soapLogin(env);
        if (login.ok) return this.ok(block, login.info, env);
        if (login.invalid && !(env.SF_CLIENT_ID && env.SF_CLIENT_SECRET)) {
          return { service: this.service, valid: false, details: login.details, meta: { envBlock: block } };
        }
      }
      if (env.SF_CLIENT_ID && env.SF_CLIENT_SECRET) {
        const oauth = await this.oauthClient(env);
        if (oauth.ok) return this.ok(block, oauth.info, env);
        if (oauth.invalid) {
          return { service: this.service, valid: false, details: oauth.details, meta: { envBlock: block } };
        }
        return skip(this.service, oauth.details);
      }
      return skip(this.service, "salesforce incomplet — skip");
    } catch (err) {
      return netSkip(this.service, err);
    }
  }

  private ok(block: string, info: SfInfo, env: Record<string, string>): ValidationResult {
    const instance = info.instance || env.SF_INSTANCE_URL || "";
    return {
      service: this.service,
      valid: true,
      details: `org ${info.org || "N/A"}`,
      meta: {
        envBlock: block,
        org: info.org || "N/A",
        user: info.user || env.SF_USERNAME || "N/A",
        email: info.email || "N/A",
        instance: instance || "N/A",
        orgId: info.orgId || "",
        edition: info.edition || "",
        sandbox: info.sandbox || "",
      },
    };
  }

  private async userinfo(token: string, instance?: string): Promise<SfInfo | null> {
    const bases = [
      instance?.replace(/\/+$/, ""),
      "https://login.salesforce.com",
      "https://test.salesforce.com",
    ].filter((u): u is string => !!u);
    for (const base of [...new Set(bases)]) {
      try {
        const res = await this.http.get(`${base}/services/oauth2/userinfo`, {
          budget: "httpRequest",
          headers: { authorization: `Bearer ${token}`, accept: "application/json" },
        });
        if (res.status === 401 || res.status === 403) continue;
        if (res.status !== 200) continue;
        const body = json(res.text) as {
          name?: string;
          email?: string;
          preferred_username?: string;
          organization_id?: string;
          nickname?: string;
          urls?: { custom_domain?: string };
        };
        return {
          user: body.name || body.preferred_username || body.nickname || "",
          email: body.email || "",
          orgId: body.organization_id || "",
          instance: body.urls?.custom_domain || base,
        };
      } catch {
        /* try next host */
      }
    }
    return null;
  }

  private async soapLogin(env: Record<string, string>): Promise<{ ok: true; info: SfInfo } | { ok: false; invalid: boolean; details: string }> {
    const user = env.SF_USERNAME ?? "";
    const pass = `${env.SF_PASSWORD ?? ""}${env.SF_SECURITY_TOKEN ?? ""}`;
    const hosts = [
      env.SF_LOGIN_URL?.replace(/\/+$/, ""),
      /test|sandbox/i.test(env.SF_LOGIN_URL ?? env.SF_INSTANCE_URL ?? user ?? "")
        ? "https://test.salesforce.com"
        : "https://login.salesforce.com",
      "https://test.salesforce.com",
      "https://login.salesforce.com",
    ].filter((u, i, a): u is string => !!u && a.indexOf(u) === i);
    const body = `<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:partner.soap.sforce.com">
  <env:Body>
    <urn:login>
      <urn:username>${xmlEsc(user)}</urn:username>
      <urn:password>${xmlEsc(pass)}</urn:password>
    </urn:login>
  </env:Body>
</env:Envelope>`;
    let last = "login failed";
    for (const host of hosts) {
      const res = await this.http.post(`${host}/services/Soap/u/59.0`, {
        budget: "httpRequest",
        headers: { "content-type": "text/xml; charset=UTF-8", SOAPAction: "login" },
        body,
      });
      const xml = res.text;
      const fault = xmlTag(xml, "faultstring") || xmlTag(xml, "exceptionMessage");
      if (/INVALID_LOGIN|INVALID_PASSWORD|locked|invalid username/i.test(xml + fault)) {
        return { ok: false, invalid: true, details: fault || "INVALID_LOGIN" };
      }
      const session = xmlTag(xml, "sessionId");
      if (res.status === 200 && session) {
        const server = xmlTag(xml, "serverUrl");
        const instance = server.replace(/\/services\/.*/, "") || env.SF_INSTANCE_URL || host;
        return {
          ok: true,
          info: {
            user: xmlTag(xml, "userFullName") || user,
            email: xmlTag(xml, "userEmail"),
            org: xmlTag(xml, "organizationName"),
            orgId: xmlTag(xml, "organizationId"),
            instance,
            edition: "",
            sandbox: /test\.salesforce/.test(host) ? "sandbox" : "",
          },
        };
      }
      last = fault || `HTTP ${res.status}`;
    }
    return { ok: false, invalid: false, details: last };
  }

  private async oauthClient(
    env: Record<string, string>,
  ): Promise<{ ok: true; info: SfInfo } | { ok: false; invalid: boolean; details: string }> {
    const hosts = [
      env.SF_LOGIN_URL?.replace(/\/+$/, ""),
      env.SF_INSTANCE_URL?.replace(/\/+$/, ""),
      "https://login.salesforce.com",
      "https://test.salesforce.com",
    ].filter((u, i, a): u is string => !!u && /^https:\/\//i.test(u) && a.indexOf(u) === i);
    let last = "oauth failed";
    let sawInvalid = false;
    for (const host of hosts) {
      const res = await this.http.post(`${host}/services/oauth2/token`, {
        budget: "httpRequest",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: form({
          grant_type: "client_credentials",
          client_id: env.SF_CLIENT_ID,
          client_secret: env.SF_CLIENT_SECRET,
        }),
      });
      const body = json(res.text) as {
        access_token?: string;
        instance_url?: string;
        id?: string;
        error?: string;
        error_description?: string;
      };
      const desc = body.error_description || body.error || `HTTP ${res.status}`;
      if (body.access_token) {
        const instance = (body.instance_url || env.SF_INSTANCE_URL || host).replace(/\/+$/, "");
        const info = (await this.identity(body.access_token, body.id, instance)) ?? {
          user: "connected-app",
          email: "",
          instance,
        };
        info.instance = info.instance || instance;
        info.sandbox = /test\.salesforce/.test(host) ? "sandbox" : info.sandbox;
        if (info.orgId && instance) {
          const org = await this.orgMeta(body.access_token, instance, info.orgId);
          if (org) {
            info.org = org.name || info.org;
            info.edition = org.edition || info.edition;
            if (org.sandbox) info.sandbox = org.sandbox;
          }
        }
        return { ok: true, info };
      }
      if (/invalid_client|invalid_client_id|invalid_client_secret|invalid consumer/i.test(desc)) {
        sawInvalid = true;
        last = desc;
        continue;
      }
      last = desc;
    }
    return { ok: false, invalid: sawInvalid, details: last.slice(0, 180) };
  }

  private async identity(token: string, idUrl?: string, instance?: string): Promise<SfInfo | null> {
    const urls = [idUrl, instance ? `${instance}/services/oauth2/userinfo` : ""].filter(Boolean) as string[];
    const fromUserinfo = await this.userinfo(token, instance);
    for (const url of urls) {
      try {
        const res = await this.http.get(url, {
          budget: "httpRequest",
          headers: { authorization: `Bearer ${token}`, accept: "application/json" },
        });
        if (res.status !== 200) continue;
        const body = json(res.text) as {
          display_name?: string;
          username?: string;
          email?: string;
          organization_id?: string;
          user_id?: string;
          urls?: { custom_domain?: string };
        };
        return {
          user: body.display_name || body.username || fromUserinfo?.user || "connected-app",
          email: body.email || fromUserinfo?.email || "",
          orgId: body.organization_id || fromUserinfo?.orgId || "",
          instance: body.urls?.custom_domain || instance || fromUserinfo?.instance,
        };
      } catch {
        /* try userinfo */
      }
    }
    return fromUserinfo;
  }

  private async orgMeta(
    token: string,
    instance: string,
    orgId: string,
  ): Promise<{ name: string; edition: string; sandbox: string } | null> {
    try {
      const res = await this.http.get(
        `${instance.replace(/\/+$/, "")}/services/data/v59.0/sobjects/Organization/${encodeURIComponent(orgId)}`,
        { budget: "httpRequest", headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
      );
      if (res.status !== 200) return null;
      const body = json(res.text) as {
        Name?: string;
        OrganizationType?: string;
        IsSandbox?: boolean;
        InstanceName?: string;
      };
      return {
        name: body.Name || "",
        edition: body.OrganizationType || "",
        sandbox: body.IsSandbox ? `sandbox ${body.InstanceName ?? ""}`.trim() : "",
      };
    } catch {
      return null;
    }
  }
}

type SfInfo = {
  user: string;
  email: string;
  org?: string;
  orgId?: string;
  instance?: string;
  edition?: string;
  sandbox?: string;
};

export class AzureHandler implements ValidationHandler {
  readonly service = "azure";
  constructor(private readonly http: IHttpClient) {}

  async validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const env = collectAzureEnv(hit, match, siblings);
    const block = formatAzureBlock(env);
    if (!isUsableAzure(env)) return skip(this.service, "azure incomplet — skip");
    try {
      const tokenRes = await this.http.post(
        `https://login.microsoftonline.com/${env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
        {
          budget: "httpRequest",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form({
            client_id: env.AZURE_CLIENT_ID,
            client_secret: env.AZURE_CLIENT_SECRET,
            grant_type: "client_credentials",
            scope: "https://graph.microsoft.com/.default",
          }),
        },
      );
      const tok = json(tokenRes.text) as { access_token?: string; error?: string; error_description?: string };
      if (tokenRes.status !== 200 || !tok.access_token) {
        const desc = tok.error_description || tok.error || `HTTP ${tokenRes.status}`;
        if (/AADSTS700016|AADSTS70011|AADSTS7000215|AADSTS7000222|invalid_client|unauthorized_client/i.test(desc)) {
          return { service: this.service, valid: false, details: desc.slice(0, 180), meta: { envBlock: block } };
        }
        if (tokenRes.status === 400 || tokenRes.status === 401 || tokenRes.status === 403) {
          return { service: this.service, valid: false, details: desc.slice(0, 180), meta: { envBlock: block } };
        }
        return skip(this.service, desc.slice(0, 120));
      }
      const orgRes = await this.http.get("https://graph.microsoft.com/v1.0/organization", {
        budget: "httpRequest",
        headers: { authorization: `Bearer ${tok.access_token}`, accept: "application/json" },
      });
      const orgBody = json(orgRes.text) as {
        value?: Array<{
          displayName?: string;
          id?: string;
          verifiedDomains?: Array<{ name?: string; isDefault?: boolean }>;
        }>;
      };
      const org = orgBody.value?.[0];
      const domains = (org?.verifiedDomains ?? []).map((d) => d.name).filter((n): n is string => !!n);
      const def = org?.verifiedDomains?.find((d) => d.isDefault)?.name;
      return {
        service: this.service,
        valid: true,
        details: `tenant ${org?.displayName || env.AZURE_TENANT_ID}`,
        meta: {
          envBlock: block,
          org: org?.displayName || "N/A",
          tenantId: org?.id || env.AZURE_TENANT_ID,
          clientId: env.AZURE_CLIENT_ID,
          domains: domains.join(", ") || def || "N/A",
          graph: orgRes.status === 200 ? "OK" : `HTTP ${orgRes.status}`,
        },
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
}

export class ZohoHandler implements ValidationHandler {
  readonly service = "zoho";
  constructor(private readonly http: IHttpClient) {}

  async validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult> {
    const env = collectZohoEnv(hit, match, siblings);
    if (!env.ZOHO_REFRESH_TOKEN && REFRESH_FALLBACK.test(match.value)) env.ZOHO_REFRESH_TOKEN = match.value.trim();
    const block = formatZohoBlock(env);
    if (!isUsableZoho(env)) return skip(this.service, "zoho incomplet — skip");
    try {
      let last = "token failed";
      for (const host of zohoDcHosts(env)) {
        const tokenRes = await this.http.post(
          `${host.accounts}/oauth/v2/token`,
          {
            budget: "httpRequest",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: form({
              refresh_token: env.ZOHO_REFRESH_TOKEN,
              client_id: env.ZOHO_CLIENT_ID,
              client_secret: env.ZOHO_CLIENT_SECRET,
              grant_type: "refresh_token",
            }),
          },
        );
        const tok = json(tokenRes.text) as { access_token?: string; error?: string; error_description?: string };
        if (!tok.access_token) {
          last = tok.error_description || tok.error || `HTTP ${tokenRes.status}`;
          continue;
        }
        const orgRes = await this.http.get(`${host.api}/crm/v2/org`, {
          budget: "httpRequest",
          headers: { authorization: `Zoho-oauthtoken ${tok.access_token}`, accept: "application/json" },
        });
        const userRes = await this.http.get(`${host.api}/crm/v2/users?type=CurrentUser`, {
          budget: "httpRequest",
          headers: { authorization: `Zoho-oauthtoken ${tok.access_token}`, accept: "application/json" },
        });
        const orgJson = json(orgRes.text) as {
          org?: Array<{
            company_name?: string;
            primary_email?: string;
            phone?: string;
            country?: string;
            license_details?: { paid?: boolean; paid_type?: string; users_license_purchased?: number };
          }>;
        };
        const usersJson = json(userRes.text) as {
          users?: Array<{ full_name?: string; email?: string; role?: { name?: string }; status?: string }>;
        };
        const org = orgJson.org?.[0];
        const user = usersJson.users?.[0];
        const license = org?.license_details;
        return {
          service: this.service,
          valid: true,
          details: `org ${org?.company_name || "N/A"}`,
          meta: {
            envBlock: block,
            token: env.ZOHO_REFRESH_TOKEN,
            org: org?.company_name || "N/A",
            email: user?.email || org?.primary_email || "N/A",
            user: user?.full_name || "N/A",
            role: user?.role?.name || "",
            country: org?.country || "",
            license: license
              ? `${license.paid ? "paid" : "free"} ${license.paid_type ?? ""} (${license.users_license_purchased ?? "?"} users)`.trim()
              : "N/A",
            dc: host.dc,
          },
        };
      }
      if (/invalid_code|invalid_client|invalid_client_secret/i.test(last)) {
        return { service: this.service, valid: false, details: last.slice(0, 180), meta: { envBlock: block } };
      }
      return skip(this.service, last);
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
}

const REFRESH_FALLBACK = /\b1000\.[a-zA-Z0-9]{20,40}\.[a-zA-Z0-9]{20,40}\b/;

export class MondayHandler implements ValidationHandler {
  readonly service = "monday";
  constructor(private readonly http: IHttpClient) {}

  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const token = match.value.trim();
    if (token.length < 20) return skip(this.service, "monday token court");
    try {
      const res = await this.http.post("https://api.monday.com/v2", {
        budget: "httpRequest",
        headers: {
          authorization: token,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ query: "{ me { name email account { name id slug } } }" }),
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      const body = json(res.text) as {
        data?: { me?: { name?: string; email?: string; account?: { name?: string; id?: string; slug?: string } } };
        errors?: Array<{ message?: string }>;
      };
      if (body.errors?.length && !body.data?.me) {
        return { service: this.service, valid: false, details: body.errors[0]?.message ?? "graphql error" };
      }
      if (res.status !== 200 || !body.data?.me) {
        if (res.status >= 500) return skip(this.service, `HTTP ${res.status}`);
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      const me = body.data.me;
      return {
        service: this.service,
        valid: true,
        details: `account ${me.account?.name || "N/A"}`,
        meta: {
          org: me.account?.name || "N/A",
          user: me.name || "N/A",
          email: me.email || "N/A",
          accountId: me.account?.id || "",
          slug: me.account?.slug || "",
        },
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
}

export class MailtrapHandler implements ValidationHandler {
  readonly service = "mailtrap";
  constructor(private readonly http: IHttpClient) {}

  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    try {
      const res = await this.http.get("https://mailtrap.io/api/accounts", {
        budget: "httpRequest",
        headers: { "Api-Token": match.value, accept: "application/json" },
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      if (res.status !== 200) return skip(this.service, `HTTP ${res.status}`);
      const accounts = json(res.text) as Array<{ id?: number; name?: string }>;
      const names = (Array.isArray(accounts) ? accounts : []).map((a) => a.name).filter((n): n is string => !!n);
      return {
        service: this.service,
        valid: true,
        details: `${names.length} account(s)`,
        meta: { org: names[0] || "N/A", accounts: names.join(", ") || "N/A" },
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
}

export class ElasticEmailHandler implements ValidationHandler {
  readonly service = "elasticemail";
  constructor(private readonly http: IHttpClient) {}

  async validate(_hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    try {
      const res = await this.http.get("https://api.elasticemail.com/v4/account", {
        budget: "httpRequest",
        headers: { "X-ElasticEmail-ApiKey": match.value, accept: "application/json" },
      });
      if (res.status === 401 || res.status === 403) {
        return { service: this.service, valid: false, details: `HTTP ${res.status}` };
      }
      if (res.status !== 200) return skip(this.service, `HTTP ${res.status}`);
      const acc = json(res.text) as {
        Email?: string;
        Company?: string;
        Reputation?: number;
        DailySendLimit?: number;
      };
      return {
        service: this.service,
        valid: true,
        details: acc.Email || "account ok",
        meta: {
          email: acc.Email || "N/A",
          org: acc.Company || "N/A",
          reputation: String(acc.Reputation ?? "N/A"),
          dailyLimit: String(acc.DailySendLimit ?? "N/A"),
        },
      };
    } catch (err) {
      return netSkip(this.service, err);
    }
  }
}
