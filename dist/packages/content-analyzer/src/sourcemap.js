const MAP_REF = /(?:\/\/[#@]\s*sourceMappingURL\s*=\s*)(\S+)/g;
export function extractSourceMapRefs(jsContent) {
    const out = [];
    MAP_REF.lastIndex = 0;
    let m;
    while ((m = MAP_REF.exec(jsContent))) {
        const ref = m[1].trim().replace(/["']+$/, "");
        if (ref.startsWith("data:"))
            continue;
        out.push(ref);
    }
    return out;
}
export function parseSourceMapV3(json) {
    const trimmed = json.trim();
    if (!trimmed.startsWith("{"))
        return [];
    let parsed;
    try {
        parsed = JSON.parse(trimmed);
    }
    catch {
        return [];
    }
    if (parsed.version !== 3 || !Array.isArray(parsed.sourcesContent))
        return [];
    const files = parsed.sources ?? [];
    const out = [];
    for (let i = 0; i < parsed.sourcesContent.length; i++) {
        const content = parsed.sourcesContent[i];
        if (!content || content.length > 512 * 1024)
            continue;
        out.push({ file: files[i] ?? `source-${i}`, content });
    }
    return out;
}
