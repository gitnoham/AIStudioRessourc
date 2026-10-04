import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";
import { compilePatternSets } from "@scanner/content-analyzer";
export declare class JsModule implements ScanModule {
    readonly name = "js";
    readonly phase: "content";
    readonly requiresPage = true;
    constructor(deps: EngineDeps);
    private readonly http;
    private readonly analyzer;
    private readonly config;
    private readonly dedup;
    private readonly logger;
    private readonly compiled;
    isEnabled(config: AppConfig): boolean;
    scan(ctx: ScanContext): AsyncGenerator<RawHit>;
    private fetchScript;
    private scanMap;
}
export declare function extractPageScriptRefs(html: string, origin: string, compiled?: ReturnType<typeof compilePatternSets>): string[];
export default JsModule;
