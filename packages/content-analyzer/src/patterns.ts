import type { PatternDef, PatternFile, PatternMatch } from "@scanner/core";
import { isAwsAccessKey, isValidAwsSecretKey } from "@scanner/core";

export interface CompiledPatterns {
  credentials: Array<{ service: string; name: string; re: RegExp }>;
  discovery: Record<string, RegExp[]>;
  awsSecretFinders: Array<{ kw: string; re: RegExp }>;
}

function toRegex(p: string | PatternDef): { re: RegExp; name: string } {
  if (typeof p === "string") {
    let source = p;
    let flags = "g";
    if (source.startsWith("(?i)")) {
      source = source.slice(4);
      flags = "gi";
    }
    return { re: new RegExp(source, flags), name: p.slice(0, 48) };
  }
  let source = p.source;
  let flags = p.flags ?? "g";
  if (source.startsWith("(?i)")) {
    source = source.slice(4);
    if (!flags.includes("i")) flags += "i";
    if (!flags.includes("g")) flags += "g";
  }
  return { re: new RegExp(source, flags), name: p.name ?? p.source.slice(0, 48) };
}

function compileAwsSecretFinders(keywords: string[]): Array<{ kw: string; re: RegExp }> {
  const out: Array<{ kw: string; re: RegExp }> = [];
  for (const raw of keywords) {
    const kw = raw.trim();
    if (!kw) continue;
    const lower = kw.toLowerCase();
    if (/(recaptcha|captcha|turnstile|sitekey|site_key|access_key_id)/.test(lower)) continue;
    if (lower === "accesskeyid" || lower === "access_key") continue;
    try {
      const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      out.push({
        kw,
        re: new RegExp(`${escaped}\\s*[:="']+\\s*["']?([A-Za-z0-9/+=]{40})["']?(?![A-Za-z0-9/+=])`, "gi"),
      });
    } catch {
      /* skip bad keyword */
    }
  }
  return out;
}

export function compilePatternSets(file: PatternFile): CompiledPatterns {
  const credentials: CompiledPatterns["credentials"] = [];
  const awsKeywords: string[] = [];
  for (const [service, group] of Object.entries(file.credentials ?? {})) {
    if (service === "aws" && group.proximityKeywords?.length) {
      awsKeywords.push(...group.proximityKeywords);
    }
    for (const p of group.patterns ?? []) {
      try {
        const { re, name } = toRegex(p);
        credentials.push({ service, name, re });
      } catch {
        /* skip invalid user regex */
      }
    }
    for (const p of group.hostPatterns ?? []) {
      try {
        const { re, name } = toRegex(p);
        credentials.push({ service: `${service}.host`, name, re });
      } catch {
        /* skip */
      }
    }
  }
  const discovery: Record<string, RegExp[]> = {};
  for (const [key, list] of Object.entries(file.discovery ?? {})) {
    discovery[key] = [];
    for (const p of list) {
      try {
        discovery[key].push(toRegex(p).re);
      } catch {
        /* skip */
      }
    }
  }
  return { credentials, discovery, awsSecretFinders: compileAwsSecretFinders(awsKeywords) };
}

export function extractWithCompiled(content: string, compiled: CompiledPatterns): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const seen = new Set<string>();
  for (const pat of compiled.credentials) {
    pat.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    const re = pat.re.global ? pat.re : new RegExp(pat.re.source, pat.re.flags.includes("g") ? pat.re.flags : pat.re.flags + "g");
    while ((m = re.exec(content))) {
      const value = (m[1] ?? m[0]).trim();
      if (!value || value.length < 4) continue;
      const key = `${pat.service}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const idx = m.index;
      const lineNumber = content.slice(0, idx).split("\n").length;
      const start = Math.max(0, idx - 80);
      const matchLen = m[0]?.length ?? value.length;
      const after = pat.service.split(".")[0] === "smtp" ? 2000 : 80;
      const context = content.slice(start, idx + matchLen + after).replace(/\s+/g, " ");
      matches.push({
        service: pat.service.split(".")[0],
        value,
        context,
        lineNumber,
        patternName: pat.name,
      });
      if (matches.length > 500) break;
    }
  }
  pairAwsSecrets(content, matches, seen, compiled.awsSecretFinders ?? []);
  return matches;
}

function searchSecretIn(text: string, finders: Array<{ kw: string; re: RegExp }>): { value: string; kw: string } | null {
  for (const f of finders) {
    f.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = f.re.exec(text))) {
      const candidate = (m[1] ?? "").trim();
      if (isValidAwsSecretKey(candidate)) return { value: candidate, kw: f.kw };
    }
  }
  return null;
}

function pairAwsSecrets(
  content: string,
  matches: PatternMatch[],
  seen: Set<string>,
  finders: Array<{ kw: string; re: RegExp }>,
): void {
  if (!finders.length) return;
  const akias = matches.filter((m) => m.service === "aws" && isAwsAccessKey(m.value));
  if (!akias.length) return;
  for (const akia of akias) {
    const pos = content.indexOf(akia.value);
    if (pos < 0) continue;
    const start = Math.max(0, pos - 500);
    const end = Math.min(content.length, pos + akia.value.length + 500);
    const found = searchSecretIn(content.slice(start, end), finders) ?? searchSecretIn(content, finders);
    if (!found) continue;
    const key = `aws:${found.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push({
      service: "aws",
      value: found.value,
      context: akia.context,
      lineNumber: akia.lineNumber,
      patternName: `aws.secret.near:${found.kw}`,
    });
  }
}

export function applyDiscovery(content: string, compiled: CompiledPatterns, key: string): string[] {
  const out: string[] = [];
  for (const re of compiled.discovery[key] ?? []) {
    re.lastIndex = 0;
    const g = re.global ? re : new RegExp(re.source, re.flags + "g");
    let m: RegExpExecArray | null;
    while ((m = g.exec(content))) {
      const v = (m[1] ?? m[0]).trim();
      if (v) out.push(v);
    }
  }
  return out;
}

export function compileDiscovery(file: PatternFile): CompiledPatterns {
  return compilePatternSets(file);
}
