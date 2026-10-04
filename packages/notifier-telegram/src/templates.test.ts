import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { formatHit, formatStats, safeHtmlTruncate } from "./templates.js";
import type { ValidatedHit } from "@scanner/core";

const now = new Date("2026-08-27T12:40:45Z");

function hit(over: Partial<ValidatedHit> & Pick<ValidatedHit, "matches">): ValidatedHit {
  return {
    source: "path",
    url: "https://aguyfrommelbourne.com",
    origin: "https://aguyfrommelbourne.com",
    path: "/.git/config",
    validationStatus: "valid",
    validationDetails: "ok",
    ...over,
  };
}

describe("formatHit", () => {
  it("renders a GitHub valid card as HTML like the old scanner", () => {
    const text = formatHit(
      hit({
        matches: [{ service: "github", value: "ghp_abc", context: "", lineNumber: 1, patternName: "github.pat" }],
        validationMeta: {
          identity: "dudaptyltd (dudaz)",
          publicRepos: "47",
          privateRepos: "0",
          followers: "0",
          scopes: "repo",
        },
      }),
      1,
      now,
    );
    assert.match(text, /^<b>Dreks<\/b>$/m);
    assert.match(text, /🟢 <b>HIT #1 │ 🐙 GITHUB 🐙<\/b>/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /🔗 <b>URL:<\/b> <code>https:\/\/aguyfrommelbourne.com<\/code>/);
    assert.match(text, /📂 <b>Path:<\/b> <code>\/\.git\/config<\/code>/);
    assert.match(text, /🔎 <b>Méthode:<\/b> Path probe/);
    assert.match(text, /🔑 <b>Token:<\/b>\n<code>ghp_abc<\/code>/);
    assert.match(text, /👤 <b>Identité:<\/b> dudaptyltd \(dudaz\)/);
    assert.match(text, /📁 <b>Repos publics:<\/b> 47 \| 🔒 Privés: 0/);
    assert.match(text, /🛡️ <b>Scopes:<\/b> repo/);
    assert.doesNotMatch(text, /CREDENTIALS TROUVÉS/);
  });

  it("renders a GitLab valid card", () => {
    const text = formatHit(
      hit({
        matches: [{ service: "gitlab", value: "glpat-abcdefghijklmnopqrstuv", context: "", lineNumber: 1, patternName: "glpat" }],
        validationMeta: {
          identity: "alice (Alice)",
          publicRepos: "2",
          privateRepos: "5",
          host: "gitlab.com",
          admin: "non",
          recentRepos: "acme/app, acme/api",
        },
      }),
      8,
      now,
    );
    assert.match(text, /🦊 GITLAB 🦊/);
    assert.match(text, /👤 <b>Identité:<\/b> alice \(Alice\)/);
    assert.match(text, /🖥️ <b>Host:<\/b> gitlab.com/);
  });

  it("renders GitHub harvest path and method", () => {
    const text = formatHit(
      hit({
        source: "git",
        url: "https://github.com/makethunder/awsudo/blob/abc/README.md",
        origin: "https://github.com",
        path: "gh-harvest:makethunder/awsudo/README.md",
        matches: [{ service: "aws", value: "AKIAAAAAAAAAAAAAAAAA", context: "", lineNumber: 1, patternName: "harvest.AKIA" }],
        validationMeta: { identity: "n/a" },
      }),
      3,
      now,
    );
    assert.match(text, /📂 <b>Path:<\/b> <code>gh-harvest:makethunder\/awsudo\/README.md<\/code>/);
    assert.match(text, /🔎 <b>Méthode:<\/b> GitHub harvest/);
  });

  it("renders GitLab harvest method", () => {
    const text = formatHit(
      hit({
        source: "git",
        url: "https://gitlab.com/acme/app/-/blob/HEAD/.env",
        origin: "https://gitlab.com",
        path: "gl-harvest:acme/app/.env",
        matches: [{ service: "aws", value: "AKIAAAAAAAAAAAAAAAAA", context: "", lineNumber: 1, patternName: "harvest.AKIA" }],
        validationMeta: { identity: "n/a" },
      }),
      4,
      now,
    );
    assert.match(text, /🔎 <b>Méthode:<\/b> GitLab harvest/);
  });

  it("renders an AWS SES card with permissions like the old scanner", () => {
    const text = formatHit(
      hit({
        matches: [
          { service: "aws", value: "AKIAAAAAAAAAAAAAAAAA", context: "", lineNumber: 1, patternName: "aws.AKIA" },
          { service: "aws", value: "abcdefghijklmnopqrstuvwxyz0123456789+/AB", context: "", lineNumber: 2, patternName: "aws.secret.env" },
        ],
        validationMeta: {
          account: "123456789012",
          arn: "arn:aws:iam::123456789012:user/ses",
          region: "us-east-1",
          statusKind: "ses",
          sesQuota: "200",
          sesBlock: "SES QUOTAS:\n📧 Total: 200 emails/day\n🌍 Active regions: 1\n📬 Verified senders: 1\n\n🔘 us-east-1 — 200/day | Rate: 1/s | Sent24h: 0",
          permBlock: "Permissions Actives:\n✅ SES (RÉSUMÉ): 🟢 ACTIVÉ | 1 région(s)\n✅ S3 (ListBuckets): 0 bucket existant\n\nPermissions Inaccessibles / Non Configurées:\n❌ EC2 (DescribeInstances)",
        },
      }),
      3,
      now,
    );
    assert.match(text, /🟢 <b>HIT #3 │ ☁️ AWS SES ☁️<\/b>/);
    assert.match(text, /SES ACTIF — 200 EMAILS\/JOUR/);
    assert.match(text, /🏛️ <b>Account:<\/b> 123456789012/);
    assert.match(text, /🔐 <b>RÉSULTATS DES PERMISSIONS:<\/b>/);
    assert.match(text, /✅ SES \(RÉSUMÉ\)/);
  });

  it("renders AWS zero-perm on the warning banner", () => {
    const text = formatHit(
      hit({
        validationStatus: "invalid",
        validationDetails: "Clé authentique mais 0 permission active",
        matches: [{ service: "aws", value: "AKIAAAAAAAAAAAAAAAAA", context: "", lineNumber: 1, patternName: "aws.AKIA" }],
        validationMeta: {
          account: "123",
          arn: "arn:aws:iam::123:user/x",
          region: "us-east-1",
          statusKind: "zero-perm",
          permBlock: "Aucune permission active détectée parmi les services testés :\n❌ S3 (ListBuckets)",
        },
      }),
      4,
      now,
    );
    assert.match(text, /🟠 <b>HIT #4 │ ☁️ AWS \(0 PERMISSION\) ☁️<\/b>/);
    assert.match(text, /AUCUNE PERMISSION ACTIVE/);
    assert.match(text, /❌ S3 \(ListBuckets\)/);
    assert.doesNotMatch(text, /❌ <b>Erreur:<\/b>/);
  });

  it("renders a SendGrid invalid card without N/A extras", () => {
    const text = formatHit(
      hit({
        validationStatus: "invalid",
        validationDetails: "HTTP 400",
        matches: [{ service: "sendgrid", value: "SG.aaa.bbb", context: "", lineNumber: 1, patternName: "sg" }],
      }),
      1,
      now,
    );
    assert.match(text, /🔴 <b>HIT #1 │ 💌 SENDGRID 💌<\/b>/);
    assert.match(text, /<b>❌ INVALIDE ❌<\/b>/);
    assert.match(text, /🌐 <code>https:\/\/aguyfrommelbourne.com<\/code>/);
    assert.match(text, /❌ HTTP 400/);
    assert.doesNotMatch(text, /Type compte/);
    assert.doesNotMatch(text, /Quota: N\/A/);
  });

  it("renders a SendGrid valid card", () => {
    const text = formatHit(
      hit({
        url: "http://34.255.92.13",
        path: "/.env",
        matches: [{ service: "sendgrid", value: "SG.aaa.bbb", context: "", lineNumber: 1, patternName: "sg" }],
        validationMeta: {
          accountType: "free",
          quota: "0 used / 0 total (0 remaining)",
          from: "a@x.com, b@y.com",
          smtp: "Disponible",
        },
      }),
      286,
      now,
    );
    assert.match(text, /🟢 <b>HIT #286 │ 💌 SENDGRID 💌<\/b>/);
    assert.match(text, /🔑 <b>API Key:<\/b>\n<code>SG\.aaa\.bbb<\/code>/);
    assert.match(text, /💼 <b>Type compte:<\/b> free/);
    assert.match(text, /✅ SMTP: Disponible/);
  });

  it("renders a Stripe valid card with public key", () => {
    const text = formatHit(
      hit({
        url: "https://143.110.150.223",
        path: "/.env",
        matches: [
          { service: "stripe", value: "pk_live_AAA", context: "", lineNumber: 1, patternName: "pk" },
          { service: "stripe", value: "sk_live_BBB", context: "", lineNumber: 2, patternName: "sk" },
        ],
        validationMeta: {
          publicKey: "pk_live_AAA",
          company: "N/A",
          country: "US",
          balance: "28.32 USD",
          permBlock: "✅ balance_read\n✅ charges_read\n❌ payouts_read",
        },
      }),
      264,
      now,
    );
    assert.match(text, /🟢 <b>HIT #264 │ 💎 STRIPE 💎<\/b>/);
    assert.match(text, /🔑 <b>Secret Key:<\/b>\n<code>sk_live_BBB<\/code>/);
    assert.match(text, /🔓 Public Key:<\/b>\n<code>pk_live_AAA<\/code>/);
    assert.match(text, /💰 <b>Solde:<\/b> 28.32 USD/);
    assert.match(text, /🔐 <b>Permissions:<\/b>/);
    assert.match(text, /✅ balance_read/);
    assert.match(text, /❌ payouts_read/);
  });

  it("renders an SMTP unverified card with one <code> line per MAIL field", () => {
    const text = formatHit(
      hit({
        url: "https://ajl976.com",
        path: "/.env",
        validationStatus: "raw",
        matches: [{ service: "smtp", value: "mail3.alter6.com", context: "", lineNumber: 1, patternName: "MAIL_HOST" }],
        validationMeta: {
          statusKind: "unverified-network",
          envBlock:
            "MAIL_HOST=mail3.alter6.com\nMAIL_PORT=587\nMAIL_USERNAME=bruno@alter6.com\nMAIL_PASSWORD=secret\nMAIL_ENCRYPTION=tls",
          smtpBrand: "📧 SMTP Générique",
          portWarn: "⚠️ Ports 587/465/25 injoignables (firewall?)",
          dialError: "dial tcp 1.2.3.4:25: i/o timeout",
        },
      }),
      1,
      now,
    );
    assert.match(text, /^<b>Dreks<\/b>$/m);
    assert.match(text, /🟡 <b>HIT #1 │ ✉️ SMTP ✉️<\/b>/);
    assert.match(text, /<b>⚠️ NON VÉRIFIÉ \(réseau\)<\/b>/);
    assert.match(text, /MAIL_HOST=<code>mail3\.alter6\.com<\/code>/);
    assert.match(text, /MAIL_PORT=<code>587<\/code>/);
    assert.match(text, /MAIL_USERNAME=<code>bruno@alter6\.com<\/code>/);
    assert.match(text, /MAIL_PASSWORD=<code>secret<\/code>/);
    assert.doesNotMatch(text, /<code>MAIL_HOST=/);
    assert.match(text, /🏷️ <b>Service:<\/b> 📧 SMTP Générique/);
    assert.match(text, /📵 <i>dial tcp/);
  });

  it("renders a valid SMTP AUTH card", () => {
    const text = formatHit(
      hit({
        url: "https://ajl976.com",
        path: "/.env",
        validationStatus: "valid",
        matches: [{ service: "smtp", value: "smtp.postmarkapp.com", context: "", lineNumber: 1, patternName: "MAIL_HOST" }],
        validationMeta: {
          envBlock:
            "MAIL_HOST=smtp.postmarkapp.com\nMAIL_PORT=587\nMAIL_USERNAME=token\nMAIL_PASSWORD=secret\nMAIL_ENCRYPTION=tls",
          smtpBrand: "📧 SMTP Générique",
          portWarn: "✅ AUTH OK (port 587)",
        },
      }),
      2,
      now,
    );
    assert.match(text, /🟢 <b>HIT #2 │ ✉️ SMTP ✉️<\/b>/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /MAIL_HOST=<code>smtp\.postmarkapp\.com<\/code>/);
    assert.match(text, /✅ AUTH OK \(port 587\)/);
    assert.doesNotMatch(text, /NON VÉRIFIÉ/);
  });

  it("renders a Zoho CRM card after OAuth", () => {
    const text = formatHit(
      hit({
        url: "https://vrz-gn.ru",
        path: "/.env",
        validationStatus: "valid",
        matches: [{ service: "zoho", value: "1000.aaa.bbbcccccccccccccccc.ddddeeeeeeeeeeeeeeeeeeee", context: "", lineNumber: 1, patternName: "zoho" }],
        validationMeta: {
          envBlock: "ZOHO_CLIENT_ID=1000.aaaaaaaaaaaaaaaaaaaa\nZOHO_REFRESH_TOKEN=1000.aaa.bbb",
          org: "Acme CRM",
          user: "Ops",
          email: "ops@acme.example",
          dc: "eu",
          license: "paid enterprise (12 users)",
        },
      }),
      1,
      now,
    );
    assert.match(text, /🟢 <b>HIT #1 │ 🔴 ZOHO CRM 🔴<\/b>/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /🏢 <b>Org:<\/b> Acme CRM/);
    assert.doesNotMatch(text, /IDENTIFIANTS EXTRAITS/);
  });

  it("renders Azure and Salesforce identity cards", () => {
    const azure = formatHit(
      hit({
        validationStatus: "valid",
        matches: [{ service: "azure", value: "secretsecretsecretsecretsecretsecret12", context: "", lineNumber: 1, patternName: "azure" }],
        validationMeta: {
          envBlock: "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111\nAZURE_CLIENT_ID=22222222-2222-2222-2222-222222222222",
          org: "Contoso",
          tenantId: "11111111-1111-1111-1111-111111111111",
          clientId: "22222222-2222-2222-2222-222222222222",
          domains: "acme.com",
          graph: "OK",
        },
      }),
      3,
      now,
    );
    assert.match(azure, /🔑 AZURE/);
    assert.match(azure, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(azure, /🏢 <b>Tenant:<\/b> Contoso/);
    assert.doesNotMatch(azure, /IDENTIFIANTS EXTRAITS/);
    const sf = formatHit(
      hit({
        validationStatus: "valid",
        matches: [{ service: "salesforce", value: "00D000000000001!AQEAQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", context: "", lineNumber: 1, patternName: "session" }],
        validationMeta: {
          envBlock: "SF_USERNAME=ops@acme.example\nSF_SESSION_ID=00D000000000001!AQEAQaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          org: "Acme",
          user: "Ops User",
          email: "ops@acme.example",
          instance: "https://acme.my.salesforce.com",
        },
      }),
      4,
      now,
    );
    assert.match(sf, /☁️ SALESFORCE CRM ☁️/);
    assert.match(sf, /🏢 <b>Org:<\/b> Acme/);
    assert.doesNotMatch(sf, /IDENTIFIANTS EXTRAITS/);
  });

  it("renders OpenAI models after a valid key check", () => {
    const text = formatHit(
      hit({
        matches: [{ service: "openai", value: "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD", context: "", lineNumber: 1, patternName: "openai" }],
        validationDetails: "2 modèle(s)",
        validationMeta: {
          modelCount: "2",
          models: "gpt-4o\no3-mini",
        },
      }),
      1,
      now,
    );
    assert.match(text, /🤖 OPENAI 🤖/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /🧠 <b>Modèles disponibles \(2\) :<\/b>/);
    assert.match(text, /• <code>gpt-4o<\/code>/);
    assert.match(text, /• <code>o3-mini<\/code>/);
  });

  it("renders OpenAI account and models together", () => {
    const text = formatHit(
      hit({
        matches: [{ service: "openai", value: "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD", context: "", lineNumber: 1, patternName: "openai" }],
        validationMeta: {
          modelCount: "2",
          models: "gpt-4o\no3-mini",
          plan: "payg",
          quota: "120 USD",
          balance: "12/100 USD",
        },
      }),
      1,
      now,
    );
    assert.match(text, /📦 <b>Plan:<\/b> payg/);
    assert.match(text, /💰 <b>Solde:<\/b>/);
    assert.match(text, /🧠 <b>Modèles disponibles \(2\) :<\/b>/);
  });

  it("renders a Replicate account on a valid key", () => {
    const text = formatHit(
      hit({
        matches: [{ service: "replicate", value: `r8_${"A".repeat(37)}`, context: "", lineNumber: 1, patternName: "replicate" }],
        validationMeta: { identity: "acme", accountType: "user" },
      }),
      1,
      now,
    );
    assert.match(text, /🧪 REPLICATE 🧪/);
    assert.match(text, /👤 <b>Compte:<\/b> acme/);
  });

  it("renders a Mailgun valid card", () => {
    const text = formatHit(
      hit({
        url: "https://sealearning.ca",
        path: "/app/.env",
        matches: [{ service: "mailgun", value: "key-abc", context: "", lineNumber: 1, patternName: "mg" }],
        validationMeta: {
          region: "US",
          domainCount: "8",
          domains: "mg.heatlink.app, mg.tunnelto.me, sealearning.ca",
          from: "postmaster@mg.heatlink.app",
          quota: "12",
        },
      }),
      2,
      now,
    );
    assert.match(text, /🟢 <b>HIT #2 │ 🔫 MAILGUN 🔫<\/b>/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /🔑 <b>API Key:<\/b>\n<code>key-abc<\/code>/);
    assert.match(text, /🌍 <b>Région:<\/b> US/);
    assert.match(text, /🌐 <b>Domaines \(8\):<\/b> mg\.heatlink\.app/);
    assert.match(text, /📬 <b>From \/ SMTP login:<\/b> postmaster@mg\.heatlink\.app/);
    assert.match(text, /📊 <b>Accepted \(1m\):<\/b> 12/);
  });

  it("renders a Klaviyo valid card", () => {
    const text = formatHit(
      hit({
        url: "https://54.253.86.203",
        path: "/.env",
        matches: [{ service: "klaviyo", value: "pk_abc", context: "", lineNumber: 1, patternName: "pk" }],
        validationMeta: {
          org: "N/A",
          timezone: "N/A",
          currency: "N/A",
          fromEmails: "Non détecté",
          flowCount: "0",
          listCount: "10",
          listsBlock: "  • test\n  • WELCOME FLOW\n  ... et 5 autre(s) liste(s)",
        },
      }),
      124,
      now,
    );
    assert.match(text, /🟢 <b>HIT #124 │ ✉️ KLAVIYO CRM ✉️<\/b>/);
    assert.match(text, /🏢 <b>Organisation :<\/b> <code>N\/A<\/code>/);
    assert.match(text, /👥 <b>Listes d'abonnés \(10\) :<\/b>/);
    assert.match(text, /🔑 <b>API Key:<\/b> <code>pk_abc<\/code>/);
    assert.match(text, /🔗 <b>URL:<\/b> <code>https:\/\/54\.253\.86\.203<\/code>/);
  });

  it("renders a Twilio valid card with numbers", () => {
    const text = formatHit(
      hit({
        url: "https://water-science.com",
        path: "/js/xserverv3.js",
        source: "js",
        scriptUrl: "https://water-science.com/js/xserverv3.js",
        matches: [
          { service: "twilio", value: "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", context: "", lineNumber: 1, patternName: "sid" },
          { service: "twilio", value: "e38123f77e9d6dc18df78efa3e2dfa1f", context: "", lineNumber: 2, patternName: "authToken" },
        ],
        validationMeta: {
          accountSid: "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          authToken: "e38123f77e9d6dc18df78efa3e2dfa1f",
          friendlyName: "Water",
          accountStatus: "active",
          accountType: "Full",
          balance: "12.50 USD",
          numbers: "+15551234567",
        },
      }),
      16,
      now,
    );
    assert.match(text, /🟢 <b>HIT #16 │ 📱 TWILIO 📱<\/b>/);
    assert.match(text, /<b>✅ VÉRIFIÉ VALIDE ✅<\/b>/);
    assert.match(text, /🆔 <b>Account SID:<\/b>\n<code>ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<\/code>/);
    assert.match(text, /🔑 <b>Auth Token:<\/b>\n<code>e38123f77e9d6dc18df78efa3e2dfa1f<\/code>/);
    assert.match(text, /👤 <b>Nom:<\/b> Water/);
    assert.match(text, /📱 <b>Numéros:<\/b> \+15551234567/);
    assert.match(text, /💰 <b>Solde:<\/b> 12\.50 USD/);
  });

  it("renders a vulnerable react2shell card", () => {
    const text = formatHit(
      hit({
        source: "vuln",
        url: "https://next-shop.example/shop",
        origin: "https://next-shop.example",
        path: undefined,
        matches: [
          { service: "react2shell", value: "https://next-shop.example", context: "__NEXT_DATA__, next/static", lineNumber: 0, patternName: "nextjs" },
        ],
        validationMeta: {
          statusKind: "vulnerable",
          cve: "CVE-2025-55182",
          version: "19.0.0",
          flavor: "webpack",
          evidence: "react-server-dom-webpack@19.0.0",
          marker: "__NEXT_DATA__, next/static",
        },
      }),
      7,
      now,
    );
    assert.match(text, /🔴 <b>HIT #7 │ 💣 REACT2SHELL \(CVE-2025-55182\) 💣<\/b>/);
    assert.match(text, /<b>🚨 VULNÉRABLE — RCE POSSIBLE \(CVE-2025-55182\) 🚨<\/b>/);
    assert.match(text, /🎯 <b>CVE:<\/b> CVE-2025-55182/);
    assert.match(text, /🧩 <b>Runtime:<\/b> react-server-dom-webpack/);
    assert.match(text, /🔢 <b>Version:<\/b> 19\.0\.0/);
    assert.match(text, /🔗 <b>URL:<\/b>\n<code>https:\/\/next-shop\.example<\/code>/);
    assert.match(text, /🔎 <b>Méthode:<\/b> Vuln probe \(React2Shell\)/);
    assert.match(text, /🧾 <b>Preuve:<\/b> react-server-dom-webpack@19\.0\.0/);
    assert.match(text, /🕵️ <b>Détection Next\.js:<\/b> __NEXT_DATA__, next\/static/);
    assert.doesNotMatch(text, /VÉRIFIÉ VALIDE/);
  });

  it("renders a patched react2shell card", () => {
    const text = formatHit(
      hit({
        source: "vuln",
        validationStatus: "invalid",
        matches: [
          { service: "react2shell", value: "https://next-shop.example", context: "__NEXT_DATA__", lineNumber: 0, patternName: "nextjs" },
        ],
        validationMeta: {
          statusKind: "patched",
          cve: "CVE-2025-55182",
          version: "19.1.2",
          flavor: "turbopack",
        },
      }),
      8,
      now,
    );
    assert.match(text, /🟢 <b>HIT #8 │ 💣 REACT2SHELL \(CVE-2025-55182\) 💣<\/b>/);
    assert.match(text, /<b>✅ PATCHÉ — NON VULNÉRABLE ✅<\/b>/);
    assert.match(text, /🔢 <b>Version:<\/b> 19\.1\.2/);
    assert.doesNotMatch(text, /VULNÉRABLE — RCE/);
  });
});

describe("formatStats", () => {
  it("renders the live SCAN EN COURS card", () => {
    const text = formatStats(
      {
        fileName: "input_part1.txt",
        urlsProcessed: 1947977,
        urlsTotal: 1947977,
        hitsValid: 5,
        hitsInvalid: 0,
        hitsRaw: 2,
        byService: { aws: 1, sendgrid: 1, brevo: 2, smtp: 1, stripe: 2 },
        cpm: 10692,
        startedAt: new Date("2026-08-24T14:00:00Z").getTime(),
      },
      new Date("2026-08-24T17:02:11Z"),
    );
    assert.match(text, /^<b>Dreks<\/b>$/m);
    assert.match(text, /🏴 SCAN EN COURS 🏴/);
    assert.match(text, /📋 <i>Fichier:<\/i> <code>input_part1\.txt<\/code>/);
    assert.match(text, /🔢 <i>Traitées:<\/i> <code>1947977<\/code>/);
    assert.match(text, /⏳ <i>Restantes:<\/i> <code>0<\/code>/);
    assert.match(text, /📈 <i>Avancement:<\/i> <code>100\.0%<\/code>/);
    assert.match(text, /⚡ <i>CPM:<\/i> <code>10692<\/code>/);
    assert.match(text, /💠 <b>Total:<\/b> <code>7<\/code> <i>\(sans doublons\)<\/i>/);
    assert.match(text, /☁️ AWS: <code>1<\/code>/);
    assert.match(text, /💌 SendGrid: <code>1<\/code>/);
    assert.match(text, /📨 Brevo: <code>2<\/code>/);
    assert.match(text, /🕐 <i>Temps:<\/i> <code>03:02:11<\/code>/);
    assert.match(text, /🎯 <i>ETA:<\/i> <code>N\/A<\/code>/);
  });
});

describe("safeHtmlTruncate", () => {
  it("closes open tags when truncating", () => {
    const text = safeHtmlTruncate(`<b>Dreks</b>\n<code>${"A".repeat(5000)}</code>`, 80);
    assert.match(text, /<\/code>/);
    assert.match(text, /Message tronqué/);
  });
});
