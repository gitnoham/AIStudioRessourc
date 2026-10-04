import AdmZip from "adm-zip";
import { gunzipSync } from "node:zlib";
const MAX_FILES = 40;
const MAX_FILE_BYTES = 512 * 1024;
export function extractArchives(content) {
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const out = [];
    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
        try {
            const zip = new AdmZip(buf);
            for (const entry of zip.getEntries()) {
                if (entry.isDirectory)
                    continue;
                if (out.length >= MAX_FILES)
                    break;
                const data = entry.getData();
                if (data.length > MAX_FILE_BYTES)
                    continue;
                out.push({ name: entry.entryName, content: data });
            }
        }
        catch {
            /* not a valid zip */
        }
    }
    if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
        try {
            const inflated = gunzipSync(buf);
            if (inflated.length <= MAX_FILE_BYTES) {
                out.push({ name: "archive.gz", content: inflated });
            }
        }
        catch {
            /* ignore */
        }
    }
    return out;
}
