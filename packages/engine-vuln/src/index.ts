import { extractNextActionIds } from "@scanner/core";
import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";

/**
 * engine-vuln — détection de vulnérabilités sur les sites scannés.
 *
 * Premier candidat : React2Shell (CVE-2025-55182), RCE dans React Server
 * Components / Next.js Server Actions via un multipart form-data forgé
 * ($ACTION_REF_0). Le module se contente de la détection STATIQUE
 * (fingerprints Next.js dans le HTML de la page) et émet un hit
 * `service: "react2shell"` ; la confirmation ACTIVE (probe multipart +
 * classification de version) est faite par React2ShellHandler côté
 * validator — même séparation que partout ailleurs dans le scanner :
 * les engines trouvent les candidats, les validators confirment.
 */

/** Fingerprints Next.js dans le HTML (SSR data, chunks, flight runtime, router). */
const NEXT_MARKERS: Array<{ name: string; re: RegExp }> = [
  { name: "__NEXT_DATA__", re: /__NEXT_DATA__/ },
  { name: "next/static", re: /\/_next\/static\// },
  { name: "__next_f", re: /(?:__next_f\.push|self\.__next_f)\s*\(/ },
  { name: "next-router", re: /data-next-router/ },
  { name: "buildManifest", re: /_buildManifest(?:\.js)?["']?/ },
];

/** Retourne la liste des marqueurs Next.js trouvés dans une page HTML. */
export function nextJsEvidence(html: string): string[] {
  if (!html) return [];
  const head = html.slice(0, 200_000);
  return NEXT_MARKERS.filter((m) => m.re.test(head)).map((m) => m.name);
}

export class VulnModule implements ScanModule {
  readonly name = "vuln";
  readonly phase = "content" as const;
  readonly requiresPage = true;

  constructor(deps: EngineDeps) {
    this.dedup = deps.dedup;
    this.config = deps.config;
    this.logger = deps.logger;
  }

  private readonly dedup: EngineDeps["dedup"];
  private readonly config: EngineDeps["config"];
  private readonly logger: EngineDeps["logger"];

  isEnabled(config: AppConfig): boolean {
    return config.modules.vuln !== false;
  }

  async *scan(ctx: ScanContext): AsyncGenerator<RawHit> {
    if (!ctx.pageContent) return;
    const markers = nextJsEvidence(ctx.pageContent);
    if (!markers.length) return;
    // Un seul hit par origine et par run (le HTML de la home est identique
    // pour toutes les URLs du même origin).
    if (!this.dedup.checkAndMark("vuln-origin", ctx.origin)) return;
    // Un vrai ID d'action permet au probe de passer la vérification
    // Next-Action côté serveur (sans ID valide → 400 → inconclusif).
    const actionIds = extractNextActionIds(ctx.pageContent);
    this.logger.info(
      "VULN",
      `Next.js detected on ${ctx.origin} (${markers.join(", ")}) — react2shell candidate${
        actionIds.length ? ` (actionId ${actionIds[0]})` : ""
      }`,
    );
    yield {
      source: "vuln",
      url: ctx.rawUrl,
      origin: ctx.origin,
      matches: [
        {
          service: "react2shell",
          value: ctx.origin,
          context: markers.join(", "),
          lineNumber: 0,
          patternName: "nextjs",
        },
      ],
      contentSnippet: markers.join(", "),
      ...(actionIds.length ? { extra: { nextActionId: actionIds[0] ?? "" } } : {}),
    };
  }
}

export default VulnModule;
