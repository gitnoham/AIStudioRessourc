/**
 * Extraction des IDs de Server Actions Next.js depuis le HTML d'une page.
 *
 * Pour que le probe React2Shell atteigne `decodeAction` côté serveur, le
 * header `Next-Action` doit porter un ID d'action valide (sinon Next.js
 * répond 400 "Invalid Server Action" et rien n'est détectable). Les IDs
 * apparaissent dans le HTML sous plusieurs formes :
 *
 *   1. `<input type="hidden" name="$ACTION_ID_<id>">` (forms à action serveur)
 *   2. Chunks Flight `self.__next_f.push([1,"<payload>"])` avec `"id":"<hex>"`
 *   3. JSON de page (`"id":"<hex>"` dans __NEXT_DATA__ / RSC payloads)
 *
 * Un mauvais candidat est sans danger : le serveur répond 400 et le probe
 * reste inconclusif — mais un bon ID est indispensable pour la détection.
 */

const ACTION_ID_REF = /\$ACTION_ID_([A-Za-z0-9_-]{8,64})/g;

/** Chunk Flight poussé par le runtime Next : `self.__next_f.push([1,"..."])`. */
const FLIGHT_PUSH = /self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)/g;

/** `"id":"<hex>"` échappé (les payloads Flight sont des littéraux JS string). */
const CHUNK_ID_ESCAPED = /\\"id\\"\s*:\s*\\"?([a-f0-9]{32,40})\\?"?/g;

/** `"id":"<hex>"` brut (JSON de page, __NEXT_DATA__, RSC inline). */
const CHUNK_ID_PLAIN = /"id"\s*:\s*"?([a-f0-9]{32,40})"?/g;

/** Retourne les IDs d'action uniques trouvés dans le HTML, dans l'ordre de confiance. */
export function extractNextActionIds(html: string): string[] {
  const out: string[] = [];
  if (!html) return out;
  const seen = new Set<string>();
  const push = (raw: string | undefined): void => {
    const id = (raw ?? "").toLowerCase();
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  };

  ACTION_ID_REF.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ACTION_ID_REF.exec(html))) push(m[1]);

  FLIGHT_PUSH.lastIndex = 0;
  while ((m = FLIGHT_PUSH.exec(html))) {
    const chunk = m[1] ?? "";
    for (const re of [CHUNK_ID_ESCAPED, CHUNK_ID_PLAIN]) {
      re.lastIndex = 0;
      let c: RegExpExecArray | null;
      while ((c = re.exec(chunk))) push(c[1]);
    }
  }

  // Dernier recours : tout le HTML (les IDs ne sont pas toujours dans un chunk).
  CHUNK_ID_PLAIN.lastIndex = 0;
  while ((m = CHUNK_ID_PLAIN.exec(html))) push(m[1]);

  return out;
}
