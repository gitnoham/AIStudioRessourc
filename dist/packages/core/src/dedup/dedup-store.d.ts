import type { IDedupStore } from "../types.js";
export declare class DedupStore implements IDedupStore {
    private readonly scopes;
    checkAndMark(scope: string, key: string): boolean;
    reset(scope?: string): void;
    unmark(scope: string, key: string): void;
}
export declare function hashUrl(value: string): string;
