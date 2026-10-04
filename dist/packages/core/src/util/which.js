import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
/**
 * Resolve the full path of a binary in PATH.
 * Returns null if not found.
 *
 * Uses `where` on Windows, `which` on POSIX.
 */
export async function which(name) {
    const cmd = process.platform === "win32" ? "where" : "which";
    try {
        const { stdout } = await exec(cmd, [name], { timeout: 3000 });
        const first = stdout.trim().split(/\r?\n/)[0] ?? "";
        return first || null;
    }
    catch {
        return null;
    }
}
