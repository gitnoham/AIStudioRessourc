import type { EngineDeps, RawHit, ScanContext } from "@scanner/core";
/** SVN + Mercurial metadata (no repo rebuild, no Index-of / .DS_Store crawl). */
export declare function scanSvnHg(deps: EngineDeps, ctx: ScanContext): AsyncGenerator<RawHit>;
