import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";
export declare class PathsModule implements ScanModule {
    readonly name = "paths";
    readonly phase: "pre";
    readonly requiresPage = false;
    constructor(deps: EngineDeps);
    private readonly http;
    private readonly analyzer;
    private readonly config;
    private readonly dedup;
    private readonly logger;
    private readonly limiter?;
    isEnabled(config: AppConfig): boolean;
    scan(ctx: ScanContext): AsyncGenerator<RawHit>;
    private canary;
    private probe;
}
export default PathsModule;
