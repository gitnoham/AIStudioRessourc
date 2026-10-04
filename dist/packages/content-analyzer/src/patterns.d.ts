import type { PatternFile, PatternMatch } from "@scanner/core";
export interface CompiledPatterns {
    credentials: Array<{
        service: string;
        name: string;
        re: RegExp;
    }>;
    discovery: Record<string, RegExp[]>;
    awsSecretFinders: Array<{
        kw: string;
        re: RegExp;
    }>;
}
export declare function compilePatternSets(file: PatternFile): CompiledPatterns;
export declare function extractWithCompiled(content: string, compiled: CompiledPatterns): PatternMatch[];
export declare function applyDiscovery(content: string, compiled: CompiledPatterns, key: string): string[];
export declare function compileDiscovery(file: PatternFile): CompiledPatterns;
