import { brotliDecompressSync, gunzipSync, inflateSync, inflateRawSync } from "node:zlib";
import AdmZip from "adm-zip";
import type {
  AnalyzeInput,
  AnalyzeResult,
  ExtractedFile,
  IContentAnalyzer,
  IConfigProvider,
  ParsedPayload,
  PatternMatch,
  SourceMapContent,
} from "@scanner/core";
import { compilePatternSets, extractWithCompiled, type CompiledPatterns } from "./patterns.js";
import { isWAFPage } from "./waf.js";
import { isFalsePositive } from "./false-positives.js";
import { extractJSONPayloads } from "./payloads.js";
import { extractSourceMapRefs, parseSourceMapV3 } from "./sourcemap.js";
import { extractArchives } from "./archives.js";
import { isVendorSecretPath } from "@scanner/core";

const HTML_HINT = /<!DOCTYPE\s+html|<html[\s>]|<head[\s>]|<body[\s>]/i;

/** /.env.local, /.env.example, wp-config.php.bak — not only files that *end* with .env/.php. */
export function isSecretishPath(path?: string): boolean {
  if (!path) return false;
  const p = path.toLowerCase();
  if (p.includes(".env")) return true;
  if (
    /(?:^|\/)(id_rsa|id_ed25519|kubeconfig|jenkinsfile|error_log|\.htpasswd|\.bash_history|\.mysql_history|\.ds_store|\.netrc|\.gitconfig|\.git-credentials|\.ftpconfig|\.firebaserc)(?:$|[.~/])/i.test(
      p,
    )
  ) {
    return true;
  }
  return (
    /\.(ini|yml|yaml|properties|cfg|conf|json|xml|pem|key|php|toml|sql|log|js|txt|lock|zip|tfvars|tfstate|pub|orig|bak|save|swp|dist|sample|template)(?:$|[.~])/i.test(
      p,
    ) ||
    /\.(php|env)~$/i.test(p) ||
    /\.php\.(bak|old|save|orig|txt|swp)$/i.test(p)
  );
}

export class ContentAnalyzer implements IContentAnalyzer {
  private readonly compiled: CompiledPatterns;

  constructor(config: IConfigProvider) {
    this.compiled = compilePatternSets(config.patterns());
  }

  analyze(input: AnalyzeInput): AnalyzeResult {
    let text: string;
    try {
      if (Buffer.isBuffer(input.content)) {
        text = this.decompress(input.content, input.contentEncoding);
      } else {
        text = this.normalizeText(input.content);
      }
    } catch {
      text = Buffer.isBuffer(input.content) ? input.content.toString("utf8") : String(input.content);
    }
    text = this.normalizeText(text);

    if (this.isWAFPage(text)) {
      return {
        text,
        rejected: true,
        rejectReason: "waf",
        matches: [],
        archives: [],
        payloads: [],
        sourceMapRefs: [],
      };
    }

    const archives = this.extractArchives(Buffer.isBuffer(input.content) ? input.content : Buffer.from(text));
    const payloads = this.isHTML(text) ? this.extractJSONPayloads(text) : [];
    const sourceMapRefs = this.extractSourceMapRefs(text);

    const bodies = [text, ...payloads.map((p) => p.raw), ...archives.map((a) => a.content.toString("utf8"))];
    let matches: PatternMatch[] = [];
    for (const body of bodies) {
      matches.push(...this.extractWithPatterns(body));
    }
    matches = this.filterFalsePositives(matches);
    if (isVendorSecretPath(input.path)) matches = [];

    return { text, rejected: false, matches, archives, payloads, sourceMapRefs };
  }

  detectEncoding(buffer: Buffer): string {
    if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) return "utf8-bom";
    if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) return "gzip";
    if (buffer.length >= 2 && buffer[0] === 0x78 && (buffer[1] === 0x01 || buffer[1] === 0x9c || buffer[1] === 0xda)) {
      return "zlib";
    }
    if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
      return "zip";
    }
    return "utf8";
  }

  decompress(input: Buffer, hint?: string): string {
    const enc = (hint ?? this.detectEncoding(input)).toLowerCase();
    try {
      if (enc.includes("gzip") || enc === "gzip") return gunzipSync(input).toString("utf8");
      if (enc.includes("br") || enc.includes("brotli")) return brotliDecompressSync(input).toString("utf8");
      if (enc.includes("deflate") || enc === "zlib") {
        try {
          return inflateSync(input).toString("utf8");
        } catch {
          return inflateRawSync(input).toString("utf8");
        }
      }
    } catch {
      /* fall through */
    }
    return input.toString("utf8");
  }

  extractArchives(content: string | Buffer): ExtractedFile[] {
    return extractArchives(content);
  }

  normalizeText(raw: string): string {
    return raw.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  }

  isWAFPage(content: string): boolean {
    return isWAFPage(content);
  }

  isHTML(content: string): boolean {
    const head = content.slice(0, 800);
    return HTML_HINT.test(head);
  }

  isLikelySecretFile(content: string, _path?: string): boolean {
    return !this.isHTML(content);
  }

  extractWithPatterns(content: string): PatternMatch[] {
    return extractWithCompiled(content, this.compiled);
  }

  extractEnvKeyValues(content: string): Record<string, string> {
    const out: Record<string, string> = {};
    const re = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content))) {
      let v = m[2].trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      out[m[1]] = v;
    }
    return out;
  }

  extractJSONPayloads(html: string): ParsedPayload[] {
    return extractJSONPayloads(html);
  }

  extractSourceMapRefs(jsContent: string): string[] {
    return extractSourceMapRefs(jsContent);
  }

  parseSourceMapV3(json: string): SourceMapContent[] {
    return parseSourceMapV3(json);
  }

  filterFalsePositives(matches: PatternMatch[]): PatternMatch[] {
    return matches.filter((m) => !isFalsePositive(m));
  }
}

export { isWAFPage } from "./waf.js";
export { extractArchives } from "./archives.js";
export { parseSourceMapV3, extractSourceMapRefs } from "./sourcemap.js";
export { extractJSONPayloads } from "./payloads.js";
