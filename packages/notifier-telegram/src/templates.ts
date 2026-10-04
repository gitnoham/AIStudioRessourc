import type { ScanStats, ValidatedHit } from "@scanner/core";
import { isValidAwsSecretKey } from "@scanner/core";
import { isIaService } from "./channel.js";

const BRAND = "<b>Dreks</b>";
const SEP = "━━━━━━━━━━━━━━━━━";

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function code(s: string): string {
  return `<code>${esc(s)}</code>`;
}

function b(s: string): string {
  return `<b>${s}</b>`;
}

const SERVICE_UI: Record<string, { title: string; keyLabel: string }> = {
  github: { title: "🐙 GITHUB 🐙", keyLabel: "🔑 Token:" },
  gitlab: { title: "🦊 GITLAB 🦊", keyLabel: "🔑 Token:" },
  bitbucket: { title: "🪣 BITBUCKET 🪣", keyLabel: "🔑 Token:" },
  gitbucket: { title: "🪣 GITBUCKET 🪣", keyLabel: "🔑 Token:" },
  sendgrid: { title: "💌 SENDGRID 💌", keyLabel: "🔑 API Key:" },
  stripe: { title: "💎 STRIPE 💎", keyLabel: "🔑 Secret Key:" },
  aws: { title: "☁️ AWS ☁️", keyLabel: "🔑 AKIA:" },
  brevo: { title: "📨 BREVO 📨", keyLabel: "🔑 API Key:" },
  mailgun: { title: "🔫 MAILGUN 🔫", keyLabel: "🔑 API Key:" },
  newmailgun: { title: "🔫 MAILGUN 🔫", keyLabel: "🔑 API Key:" },
  smtp: { title: "✉️ SMTP ✉️", keyLabel: "🔑 Password:" },
  xsmtp: { title: "✉️ SMTP ✉️", keyLabel: "🔑 Password:" },
  emailsmtp: { title: "✉️ SMTP ✉️", keyLabel: "🔑 Password:" },
  klaviyo: { title: "✉️ KLAVIYO CRM ✉️", keyLabel: "🔑 API Key:" },
  zoho: { title: "🔴 ZOHO CRM 🔴", keyLabel: "🔄 Refresh Token:" },
  openai: { title: "🤖 OPENAI 🤖", keyLabel: "🔑 API Key:" },
  anthropic: { title: "🟣 ANTHROPIC 🟣", keyLabel: "🔑 API Key:" },
  groq: { title: "⚡ GROQ ⚡", keyLabel: "🔑 API Key:" },
  huggingface: { title: "🤗 HUGGINGFACE 🤗", keyLabel: "🔑 API Key:" },
  openrouter: { title: "🧭 OPENROUTER 🧭", keyLabel: "🔑 API Key:" },
  perplexity: { title: "🔮 PERPLEXITY 🔮", keyLabel: "🔑 API Key:" },
  xai: { title: "𝕏 XAI 𝕏", keyLabel: "🔑 API Key:" },
  mistral: { title: "🌬️ MISTRAL 🌬️", keyLabel: "🔑 API Key:" },
  together: { title: "🤝 TOGETHER 🤝", keyLabel: "🔑 API Key:" },
  fireworks: { title: "🎆 FIREWORKS 🎆", keyLabel: "🔑 API Key:" },
  deepseek: { title: "🐋 DEEPSEEK 🐋", keyLabel: "🔑 API Key:" },
  cohere: { title: "🟠 COHERE 🟠", keyLabel: "🔑 API Key:" },
  voyage: { title: "🧭 VOYAGE 🧭", keyLabel: "🔑 API Key:" },
  replicate: { title: "🧪 REPLICATE 🧪", keyLabel: "🔑 API Key:" },
  nvidia: { title: "🟢 NVIDIA 🟢", keyLabel: "🔑 API Key:" },
  twilio: { title: "📱 TWILIO 📱", keyLabel: "🔑 Auth Token:" },
  postmark: { title: "📮 POSTMARK 📮", keyLabel: "🔑 API Key:" },
  sparkpost: { title: "⚡ SPARKPOST ⚡", keyLabel: "🔑 API Key:" },
  resend: { title: "📨 RESEND 📨", keyLabel: "🔑 API Key:" },
  mandrill: { title: "📬 MANDRILL 📬", keyLabel: "🔑 API Key:" },
  mailersend: { title: "📤 MAILERSEND 📤", keyLabel: "🔑 API Key:" },
  hubspot: { title: "🟧 HUBSPOT CRM 🟧", keyLabel: "🔑 API Key:" },
  pipedrive: { title: "🟢 PIPEDRIVE CRM 🟢", keyLabel: "🔑 API Token:" },
  clickup: { title: "📋 CLICKUP 📋", keyLabel: "🔑 Token:" },
  close: { title: "🎯 CLOSE CRM 🎯", keyLabel: "🔑 API Key:" },
  salesforce: { title: "☁️ SALESFORCE CRM ☁️", keyLabel: "🔑 Token:" },
  azure: { title: "🔑 AZURE", keyLabel: "🔑 Client Secret:" },
  monday: { title: "📊 MONDAY.COM CRM 📊", keyLabel: "🔑 Token:" },
  highlevel: { title: "🚀 GOHIGHLEVEL CRM 🚀", keyLabel: "🔑 API Key:" },
  mailtrap: { title: "📥 MAILTRAP 📥", keyLabel: "🔑 API Key:" },
  elasticemail: { title: "⚡ ELASTICEMAIL ⚡", keyLabel: "🔑 API Key:" },
  socketlabs: { title: "🔌 SOCKETLABS 🔌", keyLabel: "🔑 API Key:" },
  react2shell: { title: "💣 REACT2SHELL (CVE-2025-55182) 💣", keyLabel: "🔗 URL:" },
};

function displayPath(hit: ValidatedHit): string {
  if (hit.path) return hit.path;
  if (hit.source === "git" && hit.blobPath) {
    return hit.blobPath.startsWith("/") ? hit.blobPath : `/.git/${hit.blobPath}`;
  }
  if (hit.scriptUrl) return pathnameOf(hit.scriptUrl);
  if (hit.mapUrl) return pathnameOf(hit.mapUrl);
  return "/";
}

function methodLabel(hit: ValidatedHit): string {
  switch (hit.source) {
    case "path":
      return "Path probe";
    case "js":
      return hit.scriptUrl ? `JS crawl (${pathnameOf(hit.scriptUrl)})` : "JS crawl";
    case "sourcemap":
      return hit.mapUrl ? `Source map (${pathnameOf(hit.mapUrl)})` : "Source map";
    case "git":
      if (hit.path?.startsWith("gh-harvest:")) return "GitHub harvest";
      if (hit.path?.startsWith("gl-harvest:")) return "GitLab harvest";
      if (hit.path?.startsWith("bb-harvest:")) return "Bitbucket harvest";
      return "Git dump";
    case "recon": {
      const kind = hit.payloadType ?? "";
      if (kind === "guidance-rescan") return "Recon (robots/sitemap)";
      if (kind === "robots.txt") return "Recon (robots.txt)";
      if (kind === "sitemap.xml") return "Recon (sitemap)";
      if (kind) return `Recon (${kind})`;
      return "Recon";
    }
    case "homepage":
      return "Homepage HTML";
    case "vuln":
      return "Vuln probe (React2Shell)";
    default:
      return hit.source;
  }
}

function pathnameOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function primaryValue(hit: ValidatedHit): string {
  const svc = hit.matches[0]?.service;
  if (svc === "stripe") {
    return hit.matches.find((m) => m.value.startsWith("sk_"))?.value ?? hit.matches[0]?.value ?? "";
  }
  if (svc === "aws") {
    return hit.matches.find((m) => /^A[KS]IA[A-Z0-9]{16}$/.test(m.value))?.value ?? hit.matches[0]?.value ?? "";
  }
  return hit.matches[0]?.value ?? "";
}

function awsSecret(hit: ValidatedHit): string {
  const akia = primaryValue(hit);
  return (
    hit.matches.find((m) => m.value !== akia && isValidAwsSecretKey(m.value))?.value ?? ""
  );
}

export function stamp(now = new Date()): string {
  return new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Paris",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })
    .format(now)
    .replace("T", " ");
}

function serviceTitle(hit: ValidatedHit): string {
  const svc = hit.matches[0]?.service ?? "unknown";
  const kind = hit.validationMeta?.statusKind;
  if (svc === "sendgrid" && hit.validationMeta?.envBlock) return "💌 SENDGRID SMTP 💌";
  if (svc === "stripe" && hit.validationMeta?.testKey === "1") return "💎 STRIPE ⚗️ [TEST KEY] 💎";
  if (svc === "smtp" && kind === "extracted") return "✉️ SMTP PARTIEL ✉️";
  if (svc === "aws" && kind === "ses") return "☁️ AWS SES ☁️";
  if (svc === "aws" && kind === "zero-perm") return "☁️ AWS (0 PERMISSION) ☁️";
  return SERVICE_UI[svc]?.title ?? `🔑 ${svc.toUpperCase()}`;
}

function statusBanner(hit: ValidatedHit): { light: string; line: string } {
  const kind = hit.validationMeta?.statusKind;
  if (kind === "unverified-network") return { light: "🟡", line: "⚠️ NON VÉRIFIÉ (réseau)" };
  if (kind === "extracted") {
    if (hit.matches[0]?.service === "smtp") return { light: "🟡", line: "⚠️ CONFIGURATION EXTRAITE (Sans Mot de Passe)" };
    return { light: "🟢", line: "✅ IDENTIFIANTS EXTRAITS ✅" };
  }
  if (kind === "test-key") return { light: "🟡", line: "⚗️ CLÉ DE TEST — DRAIN IMPOSSIBLE" };
  if (kind === "zero-perm") return { light: "🟠", line: "⚠️ CLÉ AUTHENTIQUE MAIS AUCUNE PERMISSION ACTIVE (0 PERM) ⚠️" };
  if (kind === "ses") {
    const q = hit.validationMeta?.sesQuota ?? "?";
    return { light: "🟢", line: `✅ VÉRIFIÉ VALIDE (SES ACTIF — ${esc(q)} EMAILS/JOUR) ✅` };
  }
  if (hit.matches[0]?.service === "react2shell") {
    if (hit.validationStatus === "valid") {
      return { light: "🔴", line: "🚨 VULNÉRABLE — RCE POSSIBLE (CVE-2025-55182) 🚨" };
    }
    return { light: "🟢", line: "✅ PATCHÉ — NON VULNÉRABLE ✅" };
  }
  if (hit.validationStatus === "valid") return { light: "🟢", line: "✅ VÉRIFIÉ VALIDE ✅" };
  if (hit.validationStatus === "invalid") return { light: "🔴", line: "❌ INVALIDE ❌" };
  return { light: "🟡", line: "non validé" };
}

function isRawGeneric(hit: ValidatedHit): boolean {
  const svc = hit.matches[0]?.service ?? "";
  if (SERVICE_UI[svc] && ["smtp", "xsmtp", "emailsmtp", "zoho", "klaviyo", "sendgrid", "stripe", "aws", "github", "gitlab", "bitbucket", "gitbucket", "mailgun", "newmailgun", "brevo", "mandrill", "postmark", "sparkpost", "resend", "mailersend", "twilio", "salesforce", "azure", "monday", "mailtrap", "elasticemail"].includes(svc)) {
    return false;
  }
  return hit.validationStatus === "raw" && hit.validationMeta?.statusKind !== "extracted";
}

function urlBlock(hit: ValidatedHit, compact: boolean): string[] {
  const path = displayPath(hit);
  if (compact) {
    return [`🌐 ${code(hit.url)}`, `📁 ${code(path)}`, `🔎 ${b("Méthode:")} ${esc(methodLabel(hit))}`, ""];
  }
  return [
    `🔗 ${b("URL:")} ${code(hit.url)}`,
    `📂 ${b("Path:")} ${code(path)}`,
    `🔎 ${b("Méthode:")} ${esc(methodLabel(hit))}`,
    "",
  ];
}

function envBlockLines(block: string): string {
  return block
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => {
      const eq = l.indexOf("=");
      if (eq <= 0) return code(l);
      return `${esc(l.slice(0, eq))}=${code(l.slice(eq + 1))}`;
    })
    .join("\n");
}

function extraBlock(hit: ValidatedHit): string[] {
  const m = hit.validationMeta ?? {};
  const svc = hit.matches[0]?.service;
  if (svc === "github") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `👤 ${b("Identité:")} ${esc(m.identity ?? "N/A")}`,
      `📁 ${b("Repos publics:")} ${esc(m.publicRepos ?? "0")} | 🔒 Privés: ${esc(m.privateRepos ?? "0")}`,
      `👥 ${b("Followers:")} ${esc(m.followers ?? "0")}`,
      `🛡️ ${b("Scopes:")} ${esc(m.scopes ?? "N/A")}`,
      ...(m.recentRepos ? [`📂 ${b("Repos récents:")} ${esc(m.recentRepos)}`] : []),
      ...(m.crawled ? [`🔎 ${b("Crawlés:")} ${esc(m.crawled)} repo(s)`] : []),
      "",
    ];
  }
  if (svc === "gitlab" || svc === "bitbucket" || svc === "gitbucket") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `👤 ${b("Identité:")} ${esc(m.identity ?? "N/A")}`,
      `📁 ${b("Repos publics:")} ${esc(m.publicRepos ?? "0")} | 🔒 Privés: ${esc(m.privateRepos ?? "0")}`,
      ...(m.followers ? [`👥 ${b("Followers:")} ${esc(m.followers)}`] : []),
      ...(m.host ? [`🖥️ ${b("Host:")} ${esc(m.host)}`] : []),
      ...(m.admin ? [`🛡️ ${b("Admin:")} ${esc(m.admin)}`] : []),
      ...(m.recentRepos ? [`📂 ${b("Repos récents:")} ${esc(m.recentRepos)}`] : []),
      ...(m.crawled ? [`🔎 ${b("Crawlés:")} ${esc(m.crawled)} fichier(s)`] : []),
      "",
    ];
  }
  if (svc === "sendgrid") {
    const lines: string[] = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (m.accountType) {
      lines.push(
        `💼 ${b("Type compte:")} ${esc(m.accountType)}`,
        `📊 ${b("Quota:")} ${esc(m.quota ?? "N/A")}`,
        `📬 ${b(m.envBlock ? "Senders vérifiés:" : "From:")} ${esc(m.from && m.from !== "N/A" ? m.from : "Aucun")}`,
        "",
      );
      if (!m.envBlock) lines.push("✅ SMTP: Disponible", "");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "stripe") {
    if (hit.validationStatus === "invalid" && m.statusKind !== "test-key") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const lines: string[] = [];
    if (m.publicKey) {
      lines.push(`${b("🔓 Public Key:")}`, code(m.publicKey), "");
    }
    lines.push(
      `🏢 ${b("Société:")} ${esc(m.company ?? "N/A")}`,
      `🌍 ${b("Pays:")} ${esc(m.country ?? "N/A")}`,
      `💰 ${b("Solde:")} ${esc(m.balance ?? "N/A")}`,
    );
    if (m.permBlock) {
      lines.push("", `🔐 ${b("Permissions:")}`, esc(m.permBlock));
    }
    if (m.statusKind === "test-key") {
      lines.push("", "⚠️ <b>ATTENTION:</b> Clé de test uniquement. Aucun drain réel possible.");
    }
    lines.push("");
    return lines;
  }
  if (svc === "aws") {
    const lines: string[] = [];
    if (m.account) lines.push(`🏛️ ${b("Account:")} ${esc(m.account)}`);
    if (m.arn) lines.push(`👤 ${b("ARN:")} ${esc(m.arn)}`);
    if (m.region) lines.push(`🌍 ${b("Region:")} ${esc(m.region)}`);
    if (m.sesBlock) {
      lines.push("", `📊 ${b("SES QUOTAS:")}`);
      for (const line of m.sesBlock.split("\n")) {
        if (line === "SES QUOTAS:" || !line) continue;
        lines.push(esc(line));
      }
    }
    if (m.permBlock) {
      lines.push("", `🔐 ${b("RÉSULTATS DES PERMISSIONS:")}`, esc(m.permBlock));
    }
    if (hit.validationStatus === "invalid" && m.statusKind !== "zero-perm") {
      lines.push(`❌ ${b("Erreur:")} ${esc(hit.validationDetails || hit.validationError || "invalide")}`);
    }
    lines.push("");
    return lines;
  }
  if (svc === "mailgun" || svc === "newmailgun") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const n = m.domainCount ?? "0";
    return [
      `🌍 ${b("Région:")} ${esc(m.region ?? "N/A")}`,
      `🌐 ${b(`Domaines (${esc(n)}):`)} ${esc(m.domains ?? "Aucun")}`,
      `📬 ${b("From / SMTP login:")} ${esc(m.from ?? "Aucun")}`,
      `📊 ${b("Accepted (1m):")} ${esc(m.quota ?? "N/A")}`,
      "",
    ];
  }
  if (svc === "brevo") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🏢 ${b("Société:")} ${esc(m.company ?? "N/A")}`,
      `📧 ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      `📊 ${b("Crédits:")} ${esc(m.credits ?? "N/A")}`,
      `📈 ${b("Envoyés aujourd'hui:")} ${esc(m.sentToday ?? "0")}`,
      `📬 ${b("From / Senders:")} ${esc(m.from ?? "Aucun")}`,
      "",
    ];
  }
  if (svc === "mandrill") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `👤 ${b("Username:")} ${esc(m.username ?? "N/A")}`,
      `📊 ${b("Hourly Quota:")} ${esc(m.quota ?? "N/A")}`,
      `⭐ ${b("Reputation:")} ${esc(m.reputation ?? "0")}`,
      `📈 ${b("Sent Today:")} ${esc(m.sentToday ?? "0")} | ${b("All Time:")} ${esc(m.sentAll ?? "0")}`,
      "",
    ];
  }
  if (svc === "postmark") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🖥️ ${b("Serveur:")} ${esc(m.server ?? "N/A")}`,
      `📬 ${b("Inbound / From:")} ${esc(m.from ?? "N/A")}`,
      `✅ ${b("SMTP:")} ${esc(m.smtp ?? "N/A")}`,
      "",
    ];
  }
  if (svc === "sparkpost") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🏢 ${b("Société:")} ${esc(m.company ?? "N/A")}`,
      `📬 ${b("Sending domains:")} ${esc(m.from ?? "Aucun")}`,
      `📊 ${b("Plan:")} ${esc(m.plan ?? "N/A")}`,
      "",
    ];
  }
  if (svc === "resend" || svc === "mailersend") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🌐 ${b("Domaines:")} ${esc(m.domains ?? "Aucun")}`,
      `📬 ${b("From:")} ${esc(m.from ?? "Aucun")}`,
      ...(m.region ? [`🌍 ${b("Région:")} ${esc(m.region)}`] : []),
      "",
    ];
  }
  if (svc === "smtp" || svc === "xsmtp" || svc === "emailsmtp") {
    const lines: string[] = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    lines.push(`🏷️ ${b("Service:")} ${esc(m.smtpBrand ?? "📧 SMTP Générique")}`, "");
    if (m.portWarn) lines.push(esc(m.portWarn));
    if (m.dialError) lines.push(`📵 <i>${esc(m.dialError)}</i>`);
    return lines;
  }
  if (svc === "salesforce") {
    const lines: string[] = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    else if (hit.matches[0]?.value) lines.push(`${b("🔑 Session:")} ${code(hit.matches[0].value)}`, "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `🏢 ${b("Org:")} ${esc(m.org ?? "N/A")}`,
        `👤 ${b("User:")} ${esc(m.user ?? "N/A")}`,
        `✉️ ${b("Email:")} ${esc(m.email ?? "N/A")}`,
        `🌍 ${b("Instance:")} ${esc(m.instance ?? "N/A")}`,
      );
      if (m.edition) lines.push(`🏷️ ${b("Edition:")} ${esc(m.edition)}`);
      if (m.sandbox) lines.push(`🧪 ${b("Sandbox:")} ${esc(m.sandbox)}`);
      lines.push("");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "azure") {
    const lines: string[] = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `🏢 ${b("Tenant:")} ${esc(m.org ?? "N/A")}`,
        `🆔 ${b("Tenant ID:")} ${code(m.tenantId ?? "N/A")}`,
        `🆔 ${b("Client ID:")} ${code(m.clientId ?? "N/A")}`,
        `🌐 ${b("Domaines:")} ${esc(m.domains ?? "N/A")}`,
        `📡 ${b("Graph:")} ${esc(m.graph ?? "OK")}`,
        "",
      );
    } else if (hit.validationStatus === "invalid") {
      lines.push(`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "zoho") {
    const lines: string[] = [];
    if (m.envBlock) lines.push(envBlockLines(m.envBlock), "");
    if (hit.validationStatus === "valid") {
      lines.push(
        `🏢 ${b("Org:")} ${esc(m.org ?? "N/A")}`,
        `👤 ${b("User:")} ${esc(m.user ?? "N/A")}`,
        `✉️ ${b("Email:")} ${esc(m.email ?? "N/A")}`,
        `🌍 ${b("DC:")} ${esc(m.dc ?? "com")}`,
        `📦 ${b("Licence:")} ${esc(m.license ?? "N/A")}`,
      );
      if (m.role) lines.push(`🏷️ ${b("Rôle:")} ${esc(m.role)}`);
      lines.push("");
    } else if (hit.validationStatus === "invalid") {
      lines.push(`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, "");
    }
    return lines;
  }
  if (svc === "monday") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🏢 ${b("Account:")} ${esc(m.org ?? "N/A")}`,
      `👤 ${b("User:")} ${esc(m.user ?? "N/A")}`,
      `✉️ ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      ...(m.slug ? [`🔗 ${b("Slug:")} ${esc(m.slug)}`] : []),
      "",
    ];
  }
  if (svc === "mailtrap") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [`🏢 ${b("Accounts:")} ${esc(m.accounts ?? m.org ?? "N/A")}`, ""];
  }
  if (svc === "elasticemail") {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    return [
      `🏢 ${b("Société:")} ${esc(m.org ?? "N/A")}`,
      `✉️ ${b("Email:")} ${esc(m.email ?? "N/A")}`,
      `⭐ ${b("Réputation:")} ${esc(m.reputation ?? "N/A")}`,
      `📊 ${b("Quota jour:")} ${esc(m.dailyLimit ?? "N/A")}`,
      "",
    ];
  }
  if (svc === "klaviyo") {
    const lists = m.listsBlock ? `\n${esc(m.listsBlock)}` : "\n  • N/A";
    return [
      `🏢 ${b("Organisation :")} ${code(m.org ?? "N/A")}`,
      `🌐 ${b("Timezone / Devise :")} ${esc(m.timezone ?? "N/A")} (${esc(m.currency ?? "N/A")})`,
      `✉️ ${b("From Email(s) :")} ${esc(m.fromEmails ?? "Non détecté")}`,
      `⚙️ ${b("Flows Automatisés :")} ${esc(m.flowCount ?? "0")} flux`,
      "",
      `👥 ${b(`Listes d'abonnés (${esc(m.listCount ?? "0")}) :`)}${lists}`,
      "",
      `📈 ${b("Capacité d'envois :")} ~10× le total de profils du forfait / mois`,
      "",
    ];
  }
  if (svc === "twilio") {
    if (hit.validationStatus === "invalid" && m.statusKind !== "unverified-network") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    if (m.statusKind === "extracted" || !m.friendlyName) {
      return [`ℹ️ ${esc(hit.validationDetails || "Account SID manquant — numéros indisponibles")}`, ""];
    }
    return [
      `👤 ${b("Nom:")} ${esc(m.friendlyName)}`,
      `📊 ${b("Status:")} ${esc(m.accountStatus ?? "N/A")} | ${b("Type:")} ${esc(m.accountType ?? "N/A")}`,
      `💰 ${b("Solde:")} ${esc(m.balance ?? "N/A")}`,
      `📱 ${b("Numéros:")} ${esc(m.numbers ?? "Aucun")}`,
      "",
    ];
  }
  if (svc === "react2shell") {
    const lines: string[] = [
      `🎯 ${b("CVE:")} CVE-2025-55182 — React Server Components RCE (Server Actions)`,
      `🧩 ${b("Runtime:")} react-server-dom-${esc(m.flavor ?? "N/A")}`,
      `🔢 ${b("Version:")} ${esc(m.version ?? "N/A")}`,
    ];
    if (m.evidence) lines.push(`🧾 ${b("Preuve:")} ${esc(m.evidence)}`);
    if (m.marker) lines.push(`🕵️ ${b("Détection Next.js:")} ${esc(m.marker)}`);
    lines.push("", "⚠️ <b>Exploit:</b> multipart forgé `$ACTION_REF_0` → exécution de code sur le serveur.");
    lines.push("");
    return lines;
  }
  if (isIaService(svc)) {
    if (hit.validationStatus !== "valid") {
      return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
    }
    const lines: string[] = [];
    if (m.identity) lines.push(`👤 ${b("Compte:")} ${esc(m.identity)}`);
    if (m.accountType) lines.push(`🏷️ ${b("Type:")} ${esc(m.accountType)}`);
    if (m.email) lines.push(`✉️ ${b("Email:")} ${esc(m.email)}`);
    if (m.org) lines.push(`🏢 ${b("Org:")} ${esc(m.org)}`);
    if (m.plan) lines.push(`📦 ${b("Plan:")} ${esc(m.plan)}`);
    if (m.quota) lines.push(`📊 ${b("Quota:")} ${esc(m.quota)}`);
    if (m.balance) lines.push(`💰 ${b("Solde:")} ${esc(m.balance)}`);
    if (m.usage) lines.push(`📈 ${b("Usage:")} ${esc(m.usage)}`);
    if (m.modelCount != null || m.models) {
      const names = (m.models ?? "").split("\n").filter(Boolean);
      const count = Number(m.modelCount || names.length);
      const extra = Number.isFinite(count) ? Math.max(0, count - names.length) : 0;
      const modelLines = names.map((id) => `  • ${code(id)}`);
      if (extra > 0) modelLines.push(`  … et ${extra} autre(s)`);
      if (!modelLines.length) modelLines.push("  • (aucun id dans la réponse)");
      const shown = Number.isFinite(count) ? count : names.length;
      if (lines.length) lines.push("");
      lines.push(`🧠 ${b(`Modèles disponibles (${esc(String(shown))}) :`)}`, ...modelLines);
    } else if (!lines.length && hit.validationDetails) {
      lines.push(`ℹ️ ${esc(hit.validationDetails)}`);
    }
    lines.push("");
    return lines;
  }
  if (m.statusKind === "extracted") return [""];
  if (hit.validationStatus === "invalid") {
    return [`❌ ${esc(hit.validationDetails || hit.validationError || "invalide")}`, ""];
  }
  if (hit.validationDetails && hit.validationStatus !== "valid") {
    return [`ℹ️ ${esc(hit.validationDetails)}`, ""];
  }
  return [""];
}

function credentialBlock(hit: ValidatedHit): string[] {
  const svc = hit.matches[0]?.service ?? "";
  if (svc === "smtp" || svc === "xsmtp" || svc === "emailsmtp") return [];
  if (svc === "salesforce" && hit.validationMeta?.envBlock) return [];
  if (svc === "azure" && hit.validationMeta?.envBlock) return [];
  if (svc === "zoho" && hit.validationMeta?.envBlock) return [];
  if (svc === "sendgrid" && hit.validationMeta?.envBlock) return [];
  const ui = SERVICE_UI[svc] ?? { title: "", keyLabel: "🔑 Token:" };
  if (svc === "aws") {
    const secret = awsSecret(hit);
    const lines = [`🔑 ${b("AKIA:")} ${code(primaryValue(hit))}`];
    if (secret) lines.push(`🔐 ${b("Secret:")} ${code(secret)}`);
    lines.push("");
    return lines;
  }
  if (svc === "zoho") {
    const token = hit.validationMeta?.token ?? primaryValue(hit);
    return [`🔄 ${b("Refresh Token:")} ${code(token)}`, ""];
  }
  if (svc === "klaviyo") {
    return [`🔑 ${b("API Key:")} ${code(primaryValue(hit))}`, ""];
  }
  if (svc === "twilio") {
    const sid = hit.validationMeta?.accountSid || hit.matches.find((m) => /^AC[0-9a-fA-F]{32}$/.test(m.value))?.value || "";
    const tok = hit.validationMeta?.authToken || hit.matches.find((m) => /^[0-9a-fA-F]{32}$/.test(m.value) && !/^AC|^SK/.test(m.value))?.value || primaryValue(hit);
    const lines: string[] = [];
    if (sid) lines.push(`🆔 ${b("Account SID:")}`, code(sid));
    lines.push(`🔑 ${b("Auth Token:")}`, code(tok), "");
    return lines;
  }
  if (svc === "stripe") {
    return [`🔑 ${b("Secret Key:")}`, code(primaryValue(hit)), ""];
  }
  return [keyHeader(ui.keyLabel), code(primaryValue(hit)), ""];
}

function keyHeader(label: string): string {
  const m = label.match(/^(\S+)\s+(.+)$/);
  if (!m) return esc(label);
  return `${m[1]} ${b(m[2])}`;
}

export function formatHit(hit: ValidatedHit, n = 1, now = new Date()): string {
  const svc = hit.matches[0]?.service ?? "unknown";
  const { light, line } = statusBanner(hit);
  const compactInvalid =
    hit.validationStatus === "invalid" &&
    hit.validationMeta?.statusKind !== "test-key" &&
    hit.validationMeta?.statusKind !== "zero-perm";

  if (isRawGeneric(hit)) {
    const label = SERVICE_UI[svc]?.keyLabel ?? "🔑 Token:";
    const value = primaryValue(hit);
    return [
      BRAND,
      SEP,
      "",
      `🟡 ${b(`HIT #${n} — ${svc.toUpperCase()}`)} (non validé)`,
      "",
      ...urlBlock(hit, false),
      value ? `${esc(label)}\n${code(value)}` : "",
      `⏱️ ${stamp(now)}`,
    ]
      .filter((x) => x !== undefined)
      .join("\n");
  }

  const klaviyo = svc === "klaviyo" && hit.validationStatus === "valid";
  return [
    BRAND,
    SEP,
    "",
    `${light} ${b(`HIT #${n} │ ${serviceTitle(hit)}`)}`,
    b(line),
    "",
    ...(klaviyo ? extraBlock(hit) : urlBlock(hit, compactInvalid)),
    ...(klaviyo ? urlBlock(hit, false) : credentialBlock(hit)),
    ...(klaviyo ? credentialBlock(hit) : extraBlock(hit)),
    `⏱️ ${stamp(now)}`,
  ].join("\n");
}

export function formatStats(stats: ScanStats, now = new Date()): string {
  const total = stats.urlsTotal ?? 0;
  const done = stats.urlsProcessed;
  const remaining = Math.max(0, total - done);
  const pct = total > 0 ? (done / total) * 100 : stats.done ? 100 : 0;
  const elapsedMs = Math.max(0, now.getTime() - (stats.startedAt ?? now.getTime()));
  const cpm = Math.round(stats.cpm);
  const eta = remaining > 0 && cpm > 0 ? hms((remaining / cpm) * 60_000) : "N/A";
  const hits = stats.hitsValid + stats.hitsInvalid + stats.hitsRaw;
  const heading = stats.done ? "🏆 SCAN TERMINÉ 🏆" : "🏴 SCAN EN COURS 🏴";
  const breakdown = Object.entries(stats.byService)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${statLabel(k)}: ${code(String(v))}`)
    .join("\n");
  const clock = new Intl.DateTimeFormat("fr-FR", {
    timeZone: "Europe/Paris",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(now);
  const empty = breakdown || "<i>Aucun hit pour le moment...</i>";
  return [
    BRAND,
    heading,
    "",
    `📋 <i>Fichier:</i> ${code(stats.fileName ?? "scan")}`,
    "",
    b("📊 PROGRESSION"),
    `🔢 <i>Traitées:</i> ${code(String(done))}`,
    `⏳ <i>Restantes:</i> ${code(String(remaining))}`,
    `📈 <i>Avancement:</i> ${code(`${pct.toFixed(1)}%`)}`,
    `${progressBar(pct)} ${code(`${pct.toFixed(1)}%`)}`,
    "",
    b("⏱️ PERFORMANCE"),
    `🕐 <i>Temps:</i> ${code(hms(elapsedMs))}`,
    `🎯 <i>ETA:</i> ${code(eta)}`,
    `⚡ <i>CPM:</i> ${code(String(cpm))}`,
    "",
    b("🎯 HITS DÉTECTÉS"),
    `💠 ${b("Total:")} ${code(String(hits))} <i>(sans doublons)</i>`,
    "",
    breakdown ? `${b("📊 RÉPARTITION:")}\n${breakdown}` : empty,
    "",
    `⏱️ <i>Mise à jour:</i> ${code(clock)}`,
  ].join("\n");
}

function progressBar(pct: number): string {
  const filled = Math.round(Math.min(100, Math.max(0, pct)) / 5);
  return code("█".repeat(filled) + "░".repeat(20 - filled));
}

function hms(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(h)}:${p(m)}:${p(sec)}`;
}

function statLabel(service: string): string {
  const labels: Record<string, string> = {
    aws: "☁️ AWS",
    sendgrid: "💌 SendGrid",
    brevo: "📨 Brevo",
    smtp: "✉️ SMTP",
    stripe: "💎 Stripe",
    github: "🐙 GitHub",
    mailgun: "🔫 Mailgun",
    newmailgun: "🔫 Mailgun",
    zoho: "🔴 Zoho CRM",
    azure: "🔑 Azure",
    salesforce: "☁️ Salesforce",
    monday: "📊 Monday",
    klaviyo: "✉️ Klaviyo",
    gitlab: "🦊 GitLab",
    bitbucket: "🪣 Bitbucket",
    gitbucket: "🪣 GitBucket",
    openai: "🤖 OpenAI",
    anthropic: "🟣 Anthropic",
    groq: "⚡ Groq",
    huggingface: "🤗 HuggingFace",
    openrouter: "🧭 OpenRouter",
    perplexity: "🔮 Perplexity",
    xai: "𝕏 xAI",
    mistral: "🌬️ Mistral",
    together: "🤝 Together",
    fireworks: "🎆 Fireworks",
    deepseek: "🐋 DeepSeek",
    cohere: "🟠 Cohere",
    voyage: "🧭 Voyage",
    replicate: "🧪 Replicate",
    nvidia: "🟢 NVIDIA",
    twilio: "📱 Twilio",
    postmark: "📩 Postmark",
    sparkpost: "⚡ Sparkpost",
    react2shell: "💣 React2Shell",
  };
  return labels[service] ?? `🔑 ${service}`;
}

export function safeHtmlTruncate(msg: string, maxLen = 4000): string {
  if (msg.length <= maxLen) return msg;
  let truncated = msg.slice(0, maxLen);
  const openTags: string[] = [];
  let i = 0;
  while (i < truncated.length) {
    if (truncated[i] !== "<") {
      i++;
      continue;
    }
    const end = truncated.indexOf(">", i);
    if (end < 0) {
      truncated = truncated.slice(0, i);
      break;
    }
    const tag = truncated.slice(i + 1, end);
    if (tag.startsWith("/")) {
      openTags.pop();
    } else {
      const tagName = tag.split(/\s+/)[0];
      if (tagName && tagName !== "br" && tagName !== "hr") openTags.push(tagName);
    }
    i = end + 1;
  }
  for (let j = openTags.length - 1; j >= 0; j--) truncated += `</${openTags[j]}>`;
  return `${truncated}\n\n⚠️ [Message tronqué]`;
}
