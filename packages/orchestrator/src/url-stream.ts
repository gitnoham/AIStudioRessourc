import { createReadStream, existsSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { hashUrl, normalizeScanUrl } from "@scanner/core";

export async function* streamUrlFile(
  file: string,
  excluded: Set<string>,
  seen: Set<string>,
): AsyncGenerator<string> {
  const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    const norm = normalizeScanUrl(line);
    if (!norm) continue;
    if (excluded.has(norm) || excluded.has(line.trim())) continue;
    const h = hashUrl(norm);
    if (seen.has(h)) continue;
    seen.add(h);
    yield norm;
  }
}

export async function countUrlFile(file: string, _excluded: Set<string>): Promise<number> {
  const rl = createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  let n = 0;
  for await (const line of rl) {
    const s = line.trim();
    if (s && !s.startsWith("#")) n++;
  }
  return n;
}

export function loadExcluded(file: string): Set<string> {
  if (!existsSync(file)) return new Set();
  const set = new Set<string>();
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const n = normalizeScanUrl(line);
    if (n) set.add(n);
    if (line.trim()) set.add(line.trim());
  }
  return set;
}
