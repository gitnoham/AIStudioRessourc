import { modelsMeta, parseModelIds } from "./ai-models.js";
function json(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return {};
    }
}
function skip(service, details) {
    return { service, valid: false, raw: true, details, meta: { skipNotify: "1" } };
}
function replicateToken(raw) {
    const key = String(raw ?? "").trim().replace(/^["']|["']$/g, "");
    if (key.startsWith("r8_") && key.length > 40)
        return key.slice(0, 40);
    return key;
}
function orgFrom(siblings) {
    return siblings.find((s) => /^org-[A-Za-z0-9]{8,}$/.test(s.value.trim()))?.value.trim() ?? "";
}
const SPECS = [
    {
        service: "openai",
        key: (raw, siblings) => {
            const k = siblings.find((s) => s.value.startsWith("sk-"))?.value ?? raw;
            return k.startsWith("sk-") ? k : null;
        },
        headers: (key, siblings) => {
            const h = { authorization: `Bearer ${key}` };
            const org = orgFrom(siblings);
            if (org)
                h["openai-organization"] = org;
            return h;
        },
        check: "https://api.openai.com/v1/models",
        extras: [
            "https://api.openai.com/v1/dashboard/billing/subscription",
            "https://api.openai.com/v1/dashboard/billing/credit_grants",
            "https://api.openai.com/v1/organization",
        ],
    },
    {
        service: "anthropic",
        key: (raw) => (raw.startsWith("sk-ant-") ? raw : null),
        headers: (key) => ({ "x-api-key": key, "anthropic-version": "2023-06-01" }),
        check: "https://api.anthropic.com/v1/models",
    },
    {
        service: "groq",
        key: (raw) => (raw.startsWith("gsk_") ? raw : raw.length > 20 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.groq.com/openai/v1/models",
    },
    {
        service: "huggingface",
        key: (raw) => (raw.startsWith("hf_") ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://huggingface.co/api/whoami-v2",
    },
    {
        service: "openrouter",
        key: (raw) => (raw.startsWith("sk-or-") || raw.length > 20 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://openrouter.ai/api/v1/models",
        extras: ["https://openrouter.ai/api/v1/key"],
    },
    {
        service: "perplexity",
        key: (raw) => (raw.startsWith("pplx-") || raw.length > 20 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.perplexity.ai/models",
    },
    {
        service: "xai",
        key: (raw) => (raw.startsWith("xai-") ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.x.ai/v1/models",
        extras: ["https://api.x.ai/v1/api-key"],
    },
    {
        service: "mistral",
        key: (raw) => (raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.mistral.ai/v1/models",
    },
    {
        service: "together",
        key: (raw) => (raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.together.xyz/v1/models",
    },
    {
        service: "fireworks",
        key: (raw) => (raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.fireworks.ai/inference/v1/models",
    },
    {
        service: "deepseek",
        key: (raw) => (raw.startsWith("sk-") || raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.deepseek.com/models",
        extras: ["https://api.deepseek.com/user/balance"],
    },
    {
        service: "cohere",
        key: (raw) => (raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.cohere.com/v1/models",
        extras: ["https://api.cohere.com/v1/check-api-key"],
    },
    {
        service: "voyage",
        key: (raw) => (raw.startsWith("pa-") || raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.voyageai.com/v1/models",
    },
    {
        service: "replicate",
        key: (raw) => {
            const k = replicateToken(raw);
            return k.startsWith("r8_") ? k : k.length > 16 ? k : null;
        },
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://api.replicate.com/v1/account",
    },
    {
        service: "nvidia",
        key: (raw) => (raw.startsWith("nvapi-") || raw.length > 16 ? raw : null),
        headers: (key) => ({ authorization: `Bearer ${key}` }),
        check: "https://integrate.api.nvidia.com/v1/models",
    },
];
export class AiHandler {
    http;
    spec;
    service;
    constructor(http, spec) {
        this.http = http;
        this.spec = spec;
        this.service = spec.service;
    }
    async validate(hit, match, siblings) {
        const key = this.spec.key(match.value, [match, ...siblings, ...orgMatches(hit)]);
        if (!key)
            return skip(this.service, "clé incomplète / format non testable");
        const headers = this.spec.headers(key, [match, ...siblings, ...orgMatches(hit)]);
        try {
            const res = await this.http.get(this.spec.check, { budget: "httpRequest", headers });
            if (res.status === 401 || res.status === 403) {
                return { service: this.service, valid: false, details: `HTTP ${res.status}`, error: res.text.slice(0, 120) };
            }
            if (res.status !== 200 && res.status !== 201) {
                return { service: this.service, valid: false, raw: true, details: `HTTP ${res.status}` };
            }
            const meta = {
                ...parseCheck(this.service, this.spec.check, res.text),
            };
            for (const url of this.spec.extras ?? []) {
                try {
                    const extra = url.includes("check-api-key")
                        ? await this.http.post(url, {
                            budget: "httpRequest",
                            headers: { ...headers, "content-type": "application/json" },
                            body: JSON.stringify({ api_key: key }),
                        })
                        : await this.http.get(url, { budget: "httpRequest", headers });
                    if (extra.status === 200 || extra.status === 201) {
                        Object.assign(meta, parseExtra(this.service, url, extra.text));
                    }
                }
                catch {
                    /* extra info is optional */
                }
            }
            const n = meta.modelCount ? `${meta.modelCount} modèle(s)` : meta.identity || "ok";
            return { service: this.service, valid: true, details: n, meta };
        }
        catch (err) {
            return { service: this.service, valid: false, details: "request failed", error: err.message };
        }
    }
}
function orgMatches(hit) {
    const blob = hit.contentSnippet ?? "";
    const m = blob.match(/\borg-[A-Za-z0-9]{8,}\b/);
    if (!m)
        return [];
    return [{ service: "openai", value: m[0], context: blob, lineNumber: 0, patternName: "org" }];
}
function parseCheck(service, url, text) {
    if (service === "huggingface")
        return parseHuggingFace(text);
    if (service === "replicate")
        return parseReplicate(text);
    if (/\/models(?:\?|$)/i.test(url) || /\/models$/i.test(url)) {
        return modelsMeta(parseModelIds(text));
    }
    return {};
}
function parseExtra(service, url, text) {
    const body = json(text);
    if (service === "openai") {
        if (url.includes("subscription")) {
            const plan = body.plan ?? {};
            const out = {};
            const title = plan.title || plan.id;
            if (title)
                out.plan = String(title);
            if (body.hard_limit_usd != null)
                out.quota = `${body.hard_limit_usd} USD`;
            if (body.has_payment_method != null)
                out.accountType = body.has_payment_method ? "paid" : "no-card";
            return out;
        }
        if (url.includes("credit_grants")) {
            const avail = body.total_available ?? body.total_granted;
            const used = body.total_used;
            if (avail == null && used == null)
                return {};
            return { balance: `${used ?? "?"}/${avail ?? "?"} USD` };
        }
        if (url.includes("organization")) {
            const name = (body.name ?? body.title ?? body.organization?.name);
            if (name)
                return { org: String(name) };
        }
    }
    if (service === "openrouter") {
        const data = (body.data ?? body);
        const out = {};
        if (data.label)
            out.identity = data.label;
        if (data.is_free_tier != null)
            out.accountType = data.is_free_tier ? "free" : "paid";
        if (data.usage != null || data.limit != null) {
            out.usage = `${data.usage ?? 0}${data.limit != null ? ` / ${data.limit}` : ""}`;
        }
        if (data.limit_remaining != null)
            out.balance = String(data.limit_remaining);
        return out;
    }
    if (service === "xai" && url.includes("api-key")) {
        const out = {};
        if (typeof body.name === "string")
            out.identity = body.name;
        if (typeof body.team_id === "string")
            out.org = body.team_id;
        if (body.blocked != null)
            out.accountType = body.blocked ? "blocked" : "active";
        return out;
    }
    if (service === "deepseek" && url.includes("balance")) {
        const infos = body.balance_infos;
        const first = infos?.[0];
        if (first)
            return { balance: `${first.total_balance ?? "?"} ${first.currency ?? ""}`.trim() };
    }
    if (service === "cohere" && url.includes("check-api-key")) {
        if (typeof body.organization_id === "string")
            return { org: body.organization_id };
    }
    return {};
}
function parseHuggingFace(text) {
    const acc = json(text);
    const orgs = (acc.orgs ?? []).map((o) => o.name).filter((n) => !!n);
    const out = {
        identity: acc.name || acc.fullname || "",
        accountType: acc.type || acc.auth?.accessToken?.role || "",
    };
    if (acc.email)
        out.email = acc.email;
    if (acc.plan)
        out.plan = acc.plan;
    if (orgs.length)
        out.org = orgs.join(", ");
    if (acc.canPay != null)
        out.quota = acc.canPay ? "canPay" : "no-pay";
    return out;
}
function parseReplicate(text) {
    const acc = json(text);
    return {
        identity: acc.username || acc.name || "",
        accountType: acc.type ?? "",
    };
}
export function aiHandlers(http) {
    return SPECS.map((spec) => new AiHandler(http, spec));
}
