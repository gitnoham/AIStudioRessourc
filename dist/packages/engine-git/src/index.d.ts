import type { AppConfig, EngineDeps, PatternMatch, RawHit, ScanContext, ScanModule } from "@scanner/core";
import { parseGitIndex, parseGitObject } from "./git-objects.js";
export declare class GitModule implements ScanModule {
    readonly name = "git";
    readonly phase: "pre";
    readonly requiresPage = false;
    constructor(deps: EngineDeps);
    private readonly http;
    private readonly analyzer;
    private readonly config;
    private readonly dedup;
    private readonly logger;
    isEnabled(config: AppConfig): boolean;
    scan(ctx: ScanContext): AsyncGenerator<RawHit>;
    private scanDump;
    private detect;
    private reconstruct;
    private fetchMany;
    private analyzeBuf;
    private looksHtml;
    private safeGet;
}
/** Unpacked git blob: keep the whole object when small; else windows around SMTP + every MAIL_* / FROM. */
export declare function snippetAroundMatches(text: string, matches: PatternMatch[]): string;
export default GitModule;
export { parseGitIndex, parseGitObject };
