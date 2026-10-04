import type { PatternMatch } from "@scanner/core";
import { isAwsAccessKey, isValidAwsSecretKey } from "@scanner/core";

const PLACEHOLDERS = [
  /^(xxx+|your[_-]?key|changeme|placeholder|example|sample|todo|insert|dummy)/i,
  /example\.com/i,
  /akidEXAMPLE/i,
  /wjalrXUtnFEMI\/K7MDENG/i,
  /^0+$/,
  /^[xX*]{8,}$/,
];

const SMTP_JS_PROP = /\b(?:this|window|module|exports|o|e|t|n|r|a|P|m)\.(smtp|host|user|pass|target|value|email|password)\b/i;
const SMTP_JS_HOST = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;

export function isFalsePositive(m: PatternMatch): boolean {
  const v = m.value.trim();
  if (v.length < 6 && m.service !== "aws") return true;
  for (const re of PLACEHOLDERS) {
    if (re.test(v)) return true;
  }
  if (/lorem ipsum/i.test(m.context)) return true;
  if (m.service === "smtp" && SMTP_JS_PROP.test(m.context) && !/=/.test(m.context)) return true;
  if (
    (m.service === "smtp" || m.service === "smtp.host") &&
    SMTP_JS_HOST.test(v) &&
    /\.(value|target|type|password|username|current|props|state)$/i.test(v)
  ) {
    return true;
  }
  if (m.service === "sendgrid" && !/^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(v)) return true;
  if (m.service === "aws" || m.service === "aws.secret") {
    if (isAwsAccessKey(v)) return false;
    if (!isValidAwsSecretKey(v)) return true;
  }
  if (m.service === "github" || m.service === "gitlab" || m.service === "bitbucket" || m.service === "gitbucket") {
    if (v.length < 16) return true;
    if (/^\$\{\{/.test(v) || /^secrets\./i.test(v)) return true;
    if (/^(null|changeme|your-?token|your_token|github_token)$/i.test(v)) return true;
  }
  if (m.service === "mandrill") {
    if (!/[0-9]/.test(v)) return true;
    if ((v.match(/-/g) ?? []).length >= 3) return true;
    if (/(flex|align|start|margin|padding|justify|hidden|block|grid)/i.test(v)) return true;
    if (/class\s*=/i.test(m.context)) return true;
  }
  if (/["']\s*:\s*["'][^"']{0,8}["']/.test(m.context) && v.length < 12) return true;
  return false;
}
