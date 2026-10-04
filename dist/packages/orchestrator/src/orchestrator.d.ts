import type { IConfigProvider, IContentAnalyzer, IDedupStore, IEventBus, IHttpClient, ILogger, INotifier, IValidator, ScanModule } from "@scanner/core";
export declare class Orchestrator {
    private readonly config;
    private readonly http;
    private readonly analyzer;
    private readonly modules;
    private readonly validator;
    private readonly notifier;
    private readonly dedup;
    private readonly bus;
    private readonly logger;
    private urlsProcessed;
    private startedAt;
    /** Per-file cache of origin probes: `${origin}/` is fetched once per origin, not once per URL. */
    private readonly originProbe;
    private stats;
    constructor(config: IConfigProvider, http: IHttpClient, analyzer: IContentAnalyzer, modules: ScanModule[], validator: IValidator, notifier: INotifier, dedup: IDedupStore, bus: IEventBus, logger: ILogger);
    scanCheckFolder(): Promise<void>;
    scanFile(file: string): Promise<void>;
    private processUrl;
    private runModule;
    private fetchHome;
    private probeOrigin;
    private tryOriginHome;
    private acceptHit;
    private snapshot;
    private persist;
}
