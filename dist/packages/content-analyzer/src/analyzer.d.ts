import type { AnalyzeInput, AnalyzeResult, ExtractedFile, IContentAnalyzer, IConfigProvider, ParsedPayload, PatternMatch, SourceMapContent } from "@scanner/core";
/** /.env.local, /.env.example, wp-config.php.bak — not only files that *end* with .env/.php. */
export declare function isSecretishPath(path?: string): boolean;
export declare class ContentAnalyzer implements IContentAnalyzer {
    private readonly compiled;
    constructor(config: IConfigProvider);
    analyze(input: AnalyzeInput): AnalyzeResult;
    detectEncoding(buffer: Buffer): string;
    decompress(input: Buffer, hint?: string): string;
    extractArchives(content: string | Buffer): ExtractedFile[];
    normalizeText(raw: string): string;
    isWAFPage(content: string): boolean;
    isHTML(content: string): boolean;
    isLikelySecretFile(content: string, _path?: string): boolean;
    extractWithPatterns(content: string): PatternMatch[];
    extractEnvKeyValues(content: string): Record<string, string>;
    extractJSONPayloads(html: string): ParsedPayload[];
    extractSourceMapRefs(jsContent: string): string[];
    parseSourceMapV3(json: string): SourceMapContent[];
    filterFalsePositives(matches: PatternMatch[]): PatternMatch[];
}
export { isWAFPage } from "./waf.js";
export { extractArchives } from "./archives.js";
export { parseSourceMapV3, extractSourceMapRefs } from "./sourcemap.js";
export { extractJSONPayloads } from "./payloads.js";
