const SCRIPT_IDS = ["__NEXT_DATA__", "__NUXT_DATA__"];
const WINDOW_VARS = [
    "__NUXT__",
    "__APP_DATA__",
    "__INITIAL_STATE__",
    "__INITIAL_DATA__",
    "__PRELOADED_STATE__",
    "__RUNTIME_CONFIG__",
    "__ENV__",
    "__CONFIG__",
];
function extractScriptById(html, id) {
    for (const q of [`"`, `'`]) {
        const marker = `id=${q}${id}${q}`;
        const idx = html.indexOf(marker);
        if (idx < 0)
            continue;
        const openEnd = html.indexOf(">", idx);
        if (openEnd < 0)
            continue;
        const close = html.indexOf("</script>", openEnd);
        if (close < 0)
            continue;
        const raw = html.slice(openEnd + 1, close).trim();
        if (raw.startsWith("{") || raw.startsWith("["))
            return raw;
    }
    return null;
}
function extractWindowVar(html, name) {
    const re = new RegExp(`window\\.${name}\\s*=\\s*`, "g");
    const m = re.exec(html);
    if (!m)
        return null;
    const start = m.index + m[0].length;
    const slice = html.slice(start, start + 500_000);
    const first = slice.trim()[0];
    if (first !== "{" && first !== "[")
        return null;
    return takeJsonish(slice);
}
function takeJsonish(s) {
    const startChar = s.trim()[0];
    const open = startChar;
    const close = open === "{" ? "}" : "]";
    let depth = 0;
    let inStr = null;
    let esc = false;
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (inStr) {
            if (esc) {
                esc = false;
                continue;
            }
            if (c === "\\") {
                esc = true;
                continue;
            }
            if (c === inStr)
                inStr = null;
            continue;
        }
        if (c === '"' || c === "'") {
            inStr = c;
            continue;
        }
        if (c === open)
            depth++;
        else if (c === close) {
            depth--;
            if (depth === 0)
                return s.slice(0, i + 1);
        }
    }
    return null;
}
export function extractJSONPayloads(html) {
    const out = [];
    for (const id of SCRIPT_IDS) {
        const raw = extractScriptById(html, id);
        if (!raw)
            continue;
        try {
            out.push({ name: id, json: JSON.parse(raw), raw });
        }
        catch {
            out.push({ name: id, json: null, raw });
        }
    }
    for (const name of WINDOW_VARS) {
        const raw = extractWindowVar(html, name);
        if (!raw)
            continue;
        try {
            out.push({ name, json: JSON.parse(raw), raw });
        }
        catch {
            out.push({ name, json: null, raw });
        }
    }
    return out;
}
