/** Parse GET /models JSON (OpenAI-compatible, Anthropic, Cohere). */
export const MODEL_LIST_CAP = 40;
export function parseModelIds(text) {
    let body;
    try {
        body = JSON.parse(text);
    }
    catch {
        return [];
    }
    if (!body || typeof body !== "object")
        return [];
    const rec = body;
    const buckets = [];
    if (Array.isArray(rec.data))
        buckets.push(...rec.data);
    if (Array.isArray(rec.models))
        buckets.push(...rec.models);
    if (Array.isArray(rec.items))
        buckets.push(...rec.items);
    const ids = [];
    const seen = new Set();
    for (const item of buckets) {
        let id = "";
        if (typeof item === "string")
            id = item;
        else if (item && typeof item === "object") {
            const o = item;
            const raw = o.id ?? o.name ?? o.model ?? o.slug;
            if (typeof raw === "string")
                id = raw;
        }
        id = id.trim();
        if (!id || seen.has(id))
            continue;
        seen.add(id);
        ids.push(id);
    }
    return ids;
}
export function modelsMeta(ids) {
    return {
        modelCount: String(ids.length),
        models: ids.slice(0, MODEL_LIST_CAP).join("\n"),
    };
}
