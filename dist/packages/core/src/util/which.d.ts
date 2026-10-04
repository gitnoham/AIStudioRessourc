/**
 * Resolve the full path of a binary in PATH.
 * Returns null if not found.
 *
 * Uses `where` on Windows, `which` on POSIX.
 */
export declare function which(name: string): Promise<string | null>;
