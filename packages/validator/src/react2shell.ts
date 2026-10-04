import { extractNextActionIds } from "@scanner/core";
import type { IHttpClient, ILogger, PatternMatch, RawHit, ValidationHandler, ValidationResult } from "@scanner/core";

/**
 * React2Shell — CVE-2025-55182 (RCE React Server Components / Next.js
 * Server Actions).
 *
 * Confirmation ACTIVE, non destructive : on POSTe un multipart form-data
 * contenant `$ACTION_REF_0 = ["", null]` — une server reference vide qui ne
 * fait que forcer la désérialisation Flight, sans jamais invoquer une vraie
 * fonction de l'application. Les versions vulnérables plantent avec un
 * message qui divulgue le runtime `react-server-dom-*` et sa version ;
 * les versions patchées répondent avec une erreur propre.
 *
 * Ranges vulnérables (advisory React) :
 *   - tout < 19.0.1
 *   - 19.1.0 – 19.1.1
 *   - 19.2.0
 * Patché : 19.0.1+, 19.1.2+, 19.2.1+.
 */

export const CVE_REACT2SHELL = "CVE-2025-55182";

const BOUNDARY = "----DreksR2S8f3a1c9";
const NEXT_ACTION_ID = "r2s-probe";

/** Fuite de version : `react-server-dom-webpack@19.0.0` (aussi turbopack/esm). */
const RSD_VERSION = /react-server-dom-(webpack|turbopack|esm)[@/]v?(\d+\.\d+\.\d+)/i;

/** Signature du crash vulnérable historique (bindArgs/call sur undefined). */
const RSD_CRASH = /Cannot read properties of undefined \(reading ['"]?(?:call|then|apply|bind|id)['"]?\)/i;

export type React2ShellVerdict = "vulnerable" | "patched" | "inconclusive";

export interface React2ShellClassification {
  verdict: React2ShellVerdict;
  version?: string;
  flavor?: string;
  evidence?: string;
}

/** Vrai si la version de react-server-dom-* est dans un range CVE-2025-55182. */
export function isVulnerableReactServerDom(version: string): boolean {
  const m = version.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const maj = Number(m[1]);
  const min = Number(m[2]);
  const patch = Number(m[3]);
  if (maj < 19) return true; // Next 13/14 + React 18.x : toutes vulnérables
  if (maj > 19) return false;
  if (min === 0) return patch < 1; // 19.0.0 vulnérable, 19.0.1 patché
  if (min === 1) return patch < 2; // 19.1.0 / 19.1.1 vulnérables, 19.1.2 patché
  if (min === 2) return patch < 1; // 19.2.0 vulnérable, 19.2.1 patché
  return false; // 19.3+
}

/** Classification pure d'une réponse au probe (testable sans réseau). */
export function classifyReact2Shell(status: number, body: string): React2ShellClassification {
  if (status !== 500) {
    if (status === 400 && /invalid server action|action id/i.test(body)) {
      return { verdict: "inconclusive", evidence: "HTTP 400 — Server Actions présentes mais ID d'action invalide" };
    }
    return { verdict: "inconclusive", evidence: `HTTP ${status} — pas d'erreur Flight` };
  }
  const vm = RSD_VERSION.exec(body);
  if (vm) {
    const flavor = (vm[1] ?? "webpack").toLowerCase();
    const version = vm[2] ?? "";
    const verdict = isVulnerableReactServerDom(version) ? "vulnerable" : "patched";
    return { verdict, version, flavor, evidence: vm[0] };
  }
  if (/react-server-dom/i.test(body) && RSD_CRASH.test(body)) {
    return { verdict: "vulnerable", evidence: "crash signature (Cannot read properties of undefined)" };
  }
  return { verdict: "inconclusive", evidence: "500 sans fuite de version react-server-dom" };
}

/**
 * Construit la requête multipart du probe (exposée pour les tests).
 *
 * `actionId` : ID réel de Server Action extrait de la page. Sans ID valide,
 * Next.js répond 400 "Invalid Server Action" avant même de désérialiser le
 * Flight payload — le probe serait toujours inconclusif. `NEXT_ACTION_ID`
 * reste un fallback pour les versions qui n'exigent pas d'ID connu.
 */
export function buildReact2ShellProbe(url: string, actionId = NEXT_ACTION_ID): {
  url: string;
  headers: Record<string, string>;
  body: string;
} {
  const target = probeUrl(url);
  const body = [
    `--${BOUNDARY}`,
    `Content-Disposition: form-data; name="$ACTION_REF_0"`,
    "",
    '["", null]',
    `--${BOUNDARY}--`,
    "",
  ].join("\r\n");
  return {
    url: target,
    headers: {
      "content-type": `multipart/form-data; boundary=${BOUNDARY}`,
      "next-action": actionId,
    },
    body,
  };
}

function probeUrl(raw: string): string {
  try {
    const u = new URL(raw);
    if (!u.pathname || u.pathname === "/") return `${u.origin}/`;
    return u.href;
  } catch {
    return raw;
  }
}

export class React2ShellHandler implements ValidationHandler {
  readonly service = "react2shell";
  constructor(
    private readonly http: IHttpClient,
    private readonly logger?: ILogger,
  ) {}

  async validate(hit: RawHit, match: PatternMatch): Promise<ValidationResult> {
    const origin = match.value?.trim() || hit.origin;
    const marker = (match.context || hit.contentSnippet || "").slice(0, 200);
    try {
      const actionId =
        hit.extra?.nextActionId || (await this.lookupActionId(origin, hit.url)) || NEXT_ACTION_ID;
      const probe = buildReact2ShellProbe(origin, actionId);
      const res = await this.http.post(probe.url, {
        budget: "httpRequest",
        headers: probe.headers,
        body: probe.body,
      });
      const c = classifyReact2Shell(res.status, res.text);
      const baseMeta = {
        cve: CVE_REACT2SHELL,
        version: c.version ?? "N/A",
        flavor: c.flavor ?? "N/A",
        evidence: c.evidence ?? "",
        ...(marker ? { marker } : {}),
      };
      if (c.verdict === "vulnerable") {
        this.logger?.warn("VALIDATOR", `react2shell VULNÉRABLE ${origin} (${c.version ?? "version inconnue"})`);
        return {
          service: this.service,
          valid: true,
          details: `react-server-dom-${c.flavor ?? "?"}@${c.version ?? "?"} — VULNÉRABLE`,
          meta: { ...baseMeta, statusKind: "vulnerable" },
        };
      }
      if (c.verdict === "patched") {
        this.logger?.info("VALIDATOR", `react2shell patché ${origin} (${c.version})`);
        return {
          service: this.service,
          valid: false,
          details: `react-server-dom-${c.flavor}@${c.version} — patché (non vulnérable)`,
          meta: { ...baseMeta, statusKind: "patched" },
        };
      }
      // Inconclusif → pas de notification, mais on laisse une trace visible
      // dans les logs pour confirmer que le probe a bien tourné.
      this.logger?.info("VALIDATOR", `react2shell inconclusif ${origin}: ${c.evidence ?? ""}`);
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: c.evidence ?? "probe inconclusif",
        meta: { skipNotify: "1" },
      };
    } catch (err) {
      this.logger?.info("VALIDATOR", `react2shell probe failed ${origin}: ${(err as Error).message}`);
      return {
        service: this.service,
        valid: false,
        raw: true,
        details: "request failed",
        error: (err as Error).message,
        meta: { skipNotify: "1" },
      };
    }
  }

  /** Récupère un ID d'action réel depuis la page si l'engine n'en a pas fourni. */
  private async lookupActionId(origin: string, pageUrl?: string): Promise<string | undefined> {
    try {
      const target = pageUrl && /^https?:\/\//i.test(pageUrl) ? pageUrl : `${origin}/`;
      const res = await this.http.get(target, { budget: "pathProbe" });
      if (res.status < 200 || res.status >= 400 || !res.text) return undefined;
      return extractNextActionIds(res.text)[0];
    } catch {
      return undefined;
    }
  }
}
