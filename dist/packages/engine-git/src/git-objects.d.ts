export interface GitIndexEntry {
    path: string;
    sha: string;
    size: number;
}
export declare const GIT_META_SEEDS: string[];
/** Extra .git locations besides origin `/.git`. Bare repo: `/www.git`. */
export declare const GIT_ROOTS: string[];
export declare function isValidSha(s: string): boolean;
export declare function gitLooksExposed(path: string, body: string): boolean;
export declare function extractGitRefs(content: string): string[];
export declare function extractShas(content: string): string[];
export declare function extractGitHrefs(html: string): string[];
export declare function parseGitIndex(buf: Buffer): GitIndexEntry[];
export declare function inflateFrom(buf: Buffer, offset: number): {
    data: Buffer;
    consumed: number;
} | null;
export declare function parseGitObject(buf: Buffer): {
    type: string;
    content: Buffer;
} | null;
export declare function applyDelta(base: Buffer, delta: Buffer): Buffer | null;
export interface PackBlob {
    type: number;
    content: Buffer;
}
export declare function parsePackObjects(buf: Buffer, max?: number): Buffer[];
export declare function parsePack(buf: Buffer, max?: number): PackBlob[];
export declare function gitObjectUrl(site: string, sha: string): string;
export declare function priorityScore(path: string, hints: string[]): number;
export declare function shouldScanGitBlob(path: string, hints: string[]): boolean;
