import type { AppConfig, EngineDeps, RawHit, ScanContext, ScanModule } from "@scanner/core";
export declare class ReconModule implements ScanModule {
    readonly name = "recon";
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
    private guidanceAndRescan;
    private fetchAndScan;
}
export default ReconModule;
