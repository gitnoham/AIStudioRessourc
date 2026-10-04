import { createReadStream, existsSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { hashUrl, normalizeScanUrl } from "@scanner/core";
export async function* streamUrlFile(file, excluded, seen) {
    const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) {
        const norm = normalizeScanUrl(line);
        if (!norm)
            continue;
        if (excluded.has(norm) || excluded.has(line.trim()))
            continue;
        const h = hashUrl(norm);
        if (seen.has(h))
            continue;
        seen.add(h);
        yield norm;
    }
}
export async function countUrlFile(file, _excluded) {
    const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
    let n = 0;
    for await (const line of rl) {
        const s = line.trim();
        if (s && !s.startsWith("#"))
            n++;
    }
    return n;
}
export function loadExcluded(file) {
    if (!existsSync(file))
        return new Set();
    const set = new Set();
    for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
        const n = normalizeScanUrl(line);
        if (n)
            set.add(n);
        if (line.trim())
            set.add(line.trim());
    }
    return set;
}
