/** Parse GET /models JSON (OpenAI-compatible, Anthropic, Cohere). */

export const MODEL_LIST_CAP = 40;

export function parseModelIds(text: string): string[] {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return [];
  }
  if (!body || typeof body !== "object") return [];
  const rec = body as Record<string, unknown>;
  const buckets: unknown[] = [];
  if (Array.isArray(rec.data)) buckets.push(...rec.data);
  if (Array.isArray(rec.models)) buckets.push(...rec.models);
  if (Array.isArray(rec.items)) buckets.push(...rec.items);
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const item of buckets) {
    let id = "";
    if (typeof item === "string") id = item;
    else if (item && typeof item === "object") {
      const o = item as Record<string, unknown>;
      const raw = o.id ?? o.name ?? o.model ?? o.slug;
      if (typeof raw === "string") id = raw;
    }
    id = id.trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

export function modelsMeta(ids: string[]): Record<string, string> {
  return {
    modelCount: String(ids.length),
    models: ids.slice(0, MODEL_LIST_CAP).join("\n"),
  };
}
