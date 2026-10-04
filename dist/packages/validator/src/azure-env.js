const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const ALIASES = {
    AZURE_TENANT: "AZURE_TENANT_ID",
    AZURE_TENANTID: "AZURE_TENANT_ID",
    TENANT_ID: "AZURE_TENANT_ID",
    AZURE_CLIENT: "AZURE_CLIENT_ID",
    AZURE_CLIENTID: "AZURE_CLIENT_ID",
    AZURE_APP_ID: "AZURE_CLIENT_ID",
    APPLICATION_ID: "AZURE_CLIENT_ID",
    AZURE_SECRET: "AZURE_CLIENT_SECRET",
    AZURE_CLIENTSECRET: "AZURE_CLIENT_SECRET",
    CLIENT_SECRET: "AZURE_CLIENT_SECRET",
    AZURE_STORAGE_KEY: "AZURE_ACCOUNT_KEY",
    AZURE_STORAGE_ACCOUNT_KEY: "AZURE_ACCOUNT_KEY",
    ACCOUNTKEY: "AZURE_ACCOUNT_KEY",
    AZURE_STORAGE_ACCOUNT: "AZURE_STORAGE_ACCOUNT",
    ACCOUNTNAME: "AZURE_STORAGE_ACCOUNT",
    AZURE_ACCOUNT_NAME: "AZURE_STORAGE_ACCOUNT",
};
const KEY_RE = /\b(AZURE_[A-Z0-9_]+|TENANT_ID|CLIENT_SECRET|APPLICATION_ID|ACCOUNTNAME|ACCOUNTKEY|AZURE_STORAGE_ACCOUNT|AZURE_STORAGE_KEY)\s*[=:][ \t]*/gi;
export function parseAzureAssignments(text) {
    const env = {};
    KEY_RE.lastIndex = 0;
    let m;
    while ((m = KEY_RE.exec(text))) {
        const canon = ALIASES[m[1].toUpperCase()] ?? m[1].toUpperCase();
        const start = m.index + m[0].length;
        const rest = text.slice(start);
        const quote = rest[0];
        let value = "";
        if (quote === '"' || quote === "'") {
            const end = rest.indexOf(quote, 1);
            value = (end >= 0 ? rest.slice(1, end) : rest.slice(1).split(/\s/, 1)[0] ?? "").trim();
        }
        else {
            value = (rest.match(/^[^\s#;]+/)?.[0] ?? "").trim();
        }
        if (value)
            env[canon] = value;
    }
    const conn = text.match(/AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{40,})/i);
    if (conn) {
        if (!env.AZURE_STORAGE_ACCOUNT)
            env.AZURE_STORAGE_ACCOUNT = conn[1];
        if (!env.AZURE_ACCOUNT_KEY)
            env.AZURE_ACCOUNT_KEY = conn[2];
    }
    const shared = text.match(/SharedAccessKey=([A-Za-z0-9+/=]{40,})/);
    if (shared && !env.AZURE_ACCOUNT_KEY)
        env.AZURE_ACCOUNT_KEY = shared[1];
    return env;
}
export function collectAzureEnv(hit, match, siblings) {
    const blob = [hit.contentSnippet ?? "", match.context, match.value, ...siblings.map((s) => `${s.context}\n${s.value}`)].join("\n");
    const env = parseAzureAssignments(blob);
    for (const s of [match, ...siblings]) {
        if (s.service !== "azure")
            continue;
        const v = s.value.trim();
        if (GUID.test(v) && /tenant/i.test(s.patternName + s.context) && !env.AZURE_TENANT_ID)
            env.AZURE_TENANT_ID = v;
        else if (GUID.test(v) && /client|app/i.test(s.patternName + s.context) && !env.AZURE_CLIENT_ID)
            env.AZURE_CLIENT_ID = v;
        else if (v.length >= 34 && !GUID.test(v) && !env.AZURE_CLIENT_SECRET)
            env.AZURE_CLIENT_SECRET = v;
    }
    if (!env.AZURE_TENANT_ID) {
        const t = blob.match(/(?:AZURE_TENANT_ID|TENANT_ID)\s*[=:]\s*['"]?([0-9a-f-]{36})/i);
        if (t)
            env.AZURE_TENANT_ID = t[1];
    }
    if (!env.AZURE_CLIENT_ID) {
        const c = blob.match(/(?:AZURE_CLIENT_ID|AZURE_APP_ID|APPLICATION_ID)\s*[=:]\s*['"]?([0-9a-f-]{36})/i);
        if (c)
            env.AZURE_CLIENT_ID = c[1];
    }
    return env;
}
export function formatAzureBlock(env) {
    const keys = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_STORAGE_ACCOUNT",
        "AZURE_ACCOUNT_KEY",
    ];
    return keys.filter((k) => env[k]).map((k) => `${k}=${env[k]}`).join("\n");
}
export function isUsableAzure(env) {
    return !!(env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && env.AZURE_CLIENT_SECRET && env.AZURE_CLIENT_SECRET.length >= 8);
}
export function azureFingerprint(env) {
    if (env.AZURE_TENANT_ID && env.AZURE_CLIENT_ID && env.AZURE_CLIENT_SECRET) {
        return `azure:${env.AZURE_TENANT_ID}:${env.AZURE_CLIENT_ID}:${env.AZURE_CLIENT_SECRET}`;
    }
    if (env.AZURE_STORAGE_ACCOUNT && env.AZURE_ACCOUNT_KEY) {
        return `azure:stor:${env.AZURE_STORAGE_ACCOUNT}:${env.AZURE_ACCOUNT_KEY}`;
    }
    return "";
}
