import { harvestBitbucketRepos, harvestGitLabRepos } from "./github-harvest.js";
const PLACEHOLDER = /^(null|undefined|none|changeme|your-?token|your_token|xxxxx+|\*+|placeholder)$/i;
function json(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return {};
    }
}
function blob(hit, match, siblings) {
    return [hit.contentSnippet ?? "", match.context, ...siblings.map((s) => s.context)].join("\n");
}
function envVal(text, names) {
    for (const name of names) {
        const re = new RegExp(`\\b${name}\\s*[=:]\\s*["']?([^\\s#;"']+)`, "i");
        const m = text.match(re);
        const v = m?.[1]?.trim() ?? "";
        if (v && !PLACEHOLDER.test(v))
            return v.replace(/\/+$/, "");
    }
    return "";
}
function forgeHost(raw) {
    const v = raw.trim();
    if (!v)
        return "";
    try {
        const u = new URL(v.includes("://") ? v : `https://${v}`);
        if (!u.hostname || u.hostname === "localhost")
            return "";
        return `${u.protocol}//${u.host}`;
    }
    catch {
        return "";
    }
}
function usableToken(value) {
    const v = value.trim();
    if (v.length < 16)
        return false;
    if (PLACEHOLDER.test(v))
        return false;
    return true;
}
function identity(login, name, email) {
    if (!login)
        return "?";
    let out = name?.trim() ? `${login} (${name.trim()})` : login;
    if (email?.trim())
        out += ` | ${email.trim()}`;
    return out;
}
export class GitLabHandler {
    http;
    service = "gitlab";
    constructor(http) {
        this.http = http;
    }
    async validate(hit, match, siblings) {
        const token = match.value.trim();
        if (!usableToken(token)) {
            return { service: "gitlab", valid: false, raw: true, details: "token placeholder — skip", meta: { skipNotify: "1" } };
        }
        const text = blob(hit, match, siblings);
        const custom = forgeHost(envVal(text, ["GITLAB_URL", "GITLAB_HOST", "CI_SERVER_URL", "GITLAB_HOST_URL"]));
        const origin = hit.origin?.replace(/\/+$/, "") ?? "";
        const originLooksGitlab = /gitlab/i.test(hit.path ?? "") || /gitlab/i.test(hit.url ?? "") || /gitlab/i.test(origin);
        const bases = [...new Set([custom, originLooksGitlab ? origin : "", "https://gitlab.com"].filter(Boolean))];
        let last = "request failed";
        for (const base of bases) {
            const tried = await this.probe(base, token, hit);
            if (tried)
                return tried;
            last = `HTTP on ${base}`;
        }
        return { service: "gitlab", valid: false, details: last };
    }
    async probe(base, token, hit) {
        const headersList = [{ "private-token": token }, { authorization: `Bearer ${token}` }];
        for (const headers of headersList) {
            try {
                const res = await this.http.get(`${base}/api/v4/user`, { budget: "httpRequest", headers });
                if (res.status === 404 || res.status === 0)
                    return null;
                if (res.status !== 200)
                    continue;
                const user = json(res.text);
                const login = user.username ?? "?";
                let publicRepos = "0";
                let privateRepos = "0";
                let recent = "";
                try {
                    const proj = await this.http.get(`${base}/api/v4/projects?membership=true&simple=true&per_page=10&order_by=last_activity_at`, {
                        budget: "httpRequest",
                        headers,
                    });
                    if (proj.status === 200) {
                        const list = json(proj.text);
                        if (Array.isArray(list)) {
                            const listedPub = list.filter((p) => p.visibility === "public").length;
                            const listedPriv = list.filter((p) => p.visibility !== "public").length;
                            const total = Number(resHeader(proj.headers, "x-total") || list.length);
                            publicRepos = String(listedPub);
                            privateRepos = String(Math.max(listedPriv, Math.max(0, total - listedPub)));
                            recent = list
                                .slice(0, 8)
                                .map((p) => p.path_with_namespace)
                                .filter(Boolean)
                                .join(", ");
                        }
                    }
                }
                catch {
                    /* listing optional */
                }
                const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "")
                    ? []
                    : await harvestGitLabRepos(this.http, headers, base);
                return {
                    service: "gitlab",
                    valid: true,
                    details: `user ${login} @ ${base}`,
                    meta: {
                        identity: identity(login, user.name, user.email),
                        publicRepos,
                        privateRepos,
                        host: base.replace(/^https?:\/\//, ""),
                        admin: user.is_admin ? "oui" : "non",
                        ...(recent ? { recentRepos: recent } : {}),
                        ...(harvested.length ? { crawled: String(harvested.length) } : {}),
                    },
                    harvested,
                };
            }
            catch {
                /* next */
            }
        }
        return null;
    }
}
function resHeader(headers, name) {
    return headers[name] ?? headers[name.toLowerCase()] ?? "";
}
export class BitbucketHandler {
    http;
    service = "bitbucket";
    constructor(http) {
        this.http = http;
    }
    async validate(hit, match, siblings) {
        const token = match.value.trim();
        if (!usableToken(token)) {
            return { service: "bitbucket", valid: false, raw: true, details: "token placeholder — skip", meta: { skipNotify: "1" } };
        }
        const text = blob(hit, match, siblings);
        const userName = envVal(text, ["BITBUCKET_USERNAME", "BITBUCKET_USER", "BB_USERNAME", "BITBUCKET_EMAIL"]);
        const auths = [{ authorization: `Bearer ${token}` }];
        if (userName) {
            auths.push({ authorization: `Basic ${Buffer.from(`${userName}:${token}`).toString("base64")}` });
        }
        let last = "request failed";
        for (const headers of auths) {
            try {
                const res = await this.http.get("https://api.bitbucket.org/2.0/user", { budget: "httpRequest", headers });
                if (res.status === 401 || res.status === 403) {
                    last = `HTTP ${res.status}`;
                    continue;
                }
                if (res.status !== 200)
                    return { service: "bitbucket", valid: false, details: `HTTP ${res.status}` };
                const user = json(res.text);
                const login = user.username || user.display_name || "?";
                let publicRepos = "0";
                let privateRepos = "0";
                let recent = "";
                try {
                    const repos = await this.http.get("https://api.bitbucket.org/2.0/repositories?role=member&pagelen=10", {
                        budget: "httpRequest",
                        headers,
                    });
                    if (repos.status === 200) {
                        const body = json(repos.text);
                        const list = body.values ?? [];
                        publicRepos = String(list.filter((r) => !r.is_private).length);
                        privateRepos = String(list.filter((r) => r.is_private).length);
                        if (typeof body.size === "number" && body.size > list.length) {
                            privateRepos = String(Math.max(Number(privateRepos), body.size - Number(publicRepos)));
                        }
                        recent = list
                            .slice(0, 8)
                            .map((r) => `${r.full_name ?? r.slug ?? "?"}${r.is_private ? " 🔒" : ""}`)
                            .join(", ");
                    }
                }
                catch {
                    /* optional */
                }
                const harvested = /^(gh|gl|bb)-harvest:/.test(hit.path ?? "")
                    ? []
                    : await harvestBitbucketRepos(this.http, headers);
                return {
                    service: "bitbucket",
                    valid: true,
                    details: `user ${login}`,
                    meta: {
                        identity: identity(login, user.display_name),
                        publicRepos,
                        privateRepos,
                        ...(recent ? { recentRepos: recent } : {}),
                        ...(harvested.length ? { crawled: String(harvested.length) } : {}),
                    },
                    harvested,
                };
            }
            catch (err) {
                last = err.message;
            }
        }
        return { service: "bitbucket", valid: false, details: last };
    }
}
export class GitBucketHandler {
    http;
    service = "gitbucket";
    constructor(http) {
        this.http = http;
    }
    async validate(hit, match, siblings) {
        const token = match.value.trim();
        if (!usableToken(token)) {
            return { service: "gitbucket", valid: false, raw: true, details: "token placeholder — skip", meta: { skipNotify: "1" } };
        }
        const text = blob(hit, match, siblings);
        const custom = forgeHost(envVal(text, ["GITBUCKET_URL", "GITBUCKET_HOST", "GITBUCKET_HOST_URL"]));
        const origin = hit.origin?.replace(/\/+$/, "") ?? "";
        const bases = [...new Set([custom, origin].filter(Boolean))];
        if (!bases.length) {
            return { service: "gitbucket", valid: false, raw: true, details: "pas de host GitBucket — skip", meta: { skipNotify: "1" } };
        }
        for (const base of bases) {
            for (const headers of [{ authorization: `token ${token}` }, { authorization: `Bearer ${token}` }]) {
                try {
                    const res = await this.http.get(`${base}/api/v3/user`, { budget: "httpRequest", headers });
                    if (res.status === 404)
                        break;
                    if (res.status !== 200)
                        continue;
                    const user = json(res.text);
                    const login = user.login ?? "?";
                    if (login === "?" && !user.name)
                        continue;
                    return {
                        service: "gitbucket",
                        valid: true,
                        details: `user ${login} @ ${base}`,
                        meta: {
                            identity: identity(login, user.name, user.email),
                            publicRepos: String(user.public_repos ?? 0),
                            privateRepos: String(user.total_private_repos ?? 0),
                            followers: String(user.followers ?? 0),
                            host: base.replace(/^https?:\/\//, ""),
                        },
                    };
                }
                catch {
                    /* next */
                }
            }
        }
        return { service: "gitbucket", valid: false, raw: true, details: "GitBucket injoignable — skip", meta: { skipNotify: "1" } };
    }
}
