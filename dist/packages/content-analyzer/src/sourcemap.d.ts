import type { SourceMapContent } from "@scanner/core";
export declare function extractSourceMapRefs(jsContent: string): string[];
export declare function parseSourceMapV3(json: string): SourceMapContent[];
