export type ScanPhase = "pre" | "content" | "post";
export type HitSource = "path" | "js" | "sourcemap" | "git" | "recon" | "homepage";
export type ValidationStatus = "valid" | "invalid" | "raw";
export interface PatternDef {
    source: string;
    flags?: string;
    name?: string;
}
export interface CredentialPatternGroup {
    patterns: Array<string | PatternDef>;
    proximityKeywords?: string[];
    hostPatterns?: Array<string | PatternDef>;
}
export interface PatternFile {
    _readme?: string;
    credentials: Record<string, CredentialPatternGroup>;
    discovery: Record<string, Array<string | PatternDef>>;
}
export interface TelegramConfig {
    botToken?: string;
    botTokens?: string[];
    statsChannelId: string;
    validHitsChannelId: string;
    invalidHitsChannelId: string;
    iaValidHitsChannelId?: string;
}
export interface AppConfig {
    modules: Record<string, boolean>;
    concurrency: {
        urlWorkers: number;
        pathProbesPerHost: number;
        /** Optional global cap on in-flight path probes across all hosts. */
        pathProbeGlobal?: number;
        jsCrawlDepth: number;
        jsMaxScripts: number;
        gitWorkers: number;
        gitMaxBlobs: number;
        gitMaxDownloads: number;
        validatorWorkers: number;
        queueCapacity: number;
        /** Max items in the URL pipeline queue before back-pressure kicks in. */
        pipelineQueueCap?: number;
    };
    budgets: Record<string, string>;
    budgetProfiles: Record<string, number>;
    pathsToCheck: string[];
    gitSecretHints: string[];
    excludedUrlsFile: string;
    telegram: TelegramConfig;
    patternsFile: string;
    checkDir: string;
    doneDir: string;
    dataDir: string;
}
export interface PatternMatch {
    service: string;
    value: string;
    context: string;
    lineNumber: number;
    patternName: string;
}
export interface RawHit {
    source: HitSource;
    url: string;
    origin: string;
    path?: string;
    scriptUrl?: string;
    mapUrl?: string;
    blobPath?: string;
    site?: string;
    payloadType?: string;
    statusCode?: number;
    contentSnippet?: string;
    matches: PatternMatch[];
}
export interface ValidatedHit extends RawHit {
    validationStatus: ValidationStatus;
    validationDetails: string;
    validationError?: string;
    validationMeta?: Record<string, string>;
}
export interface ScanContext {
    rawUrl: string;
    origin: string;
    pageContent?: string;
    signal: AbortSignal;
    emit(hit: RawHit): void;
    /** Fired once when ~half of pathsToCheck have been probed (git can start). */
    onPathsHalfway?: () => void;
}
export interface ISemaphore {
    acquire(signal?: AbortSignal): Promise<() => void>;
}
export interface EngineDeps {
    http: IHttpClient;
    analyzer: IContentAnalyzer;
    config: IConfigProvider;
    dedup: IDedupStore;
    logger: ILogger;
    /** Optional global limiter shared across modules (e.g. path probes). */
    pathLimiter?: ISemaphore;
}
export interface ScanModule {
    readonly name: string;
    readonly phase: ScanPhase;
    readonly requiresPage: boolean;
    isEnabled(config: AppConfig): boolean;
    scan(ctx: ScanContext): AsyncGenerator<RawHit> | Promise<void>;
}
export interface HttpResponse {
    url: string;
    status: number;
    headers: Record<string, string>;
    body: Buffer;
    text: string;
}
export interface IHttpClient {
    get(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
    post(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
}
export interface HttpRequestOptions {
    signal?: AbortSignal;
    budget?: string;
    headers?: Record<string, string>;
    maxBytes?: number;
    keepBody?: boolean;
    body?: string;
    /** Impersonate a real browser/curl TLS+HTTP fingerprint. Defaults to 'chrome'. */
    impersonate?: "chrome" | "firefox" | "curl";
}
export interface AnalyzeInput {
    url?: string;
    path?: string;
    content: string | Buffer;
    contentEncoding?: string;
    contentType?: string;
}
export interface ExtractedFile {
    name: string;
    content: Buffer;
}
export interface ParsedPayload {
    name: string;
    json: unknown;
    raw: string;
}
export interface SourceMapContent {
    file: string;
    content: string;
}
export interface AnalyzeResult {
    text: string;
    rejected: boolean;
    rejectReason?: string;
    matches: PatternMatch[];
    archives: ExtractedFile[];
    payloads: ParsedPayload[];
    sourceMapRefs: string[];
}
export interface IContentAnalyzer {
    analyze(input: AnalyzeInput): AnalyzeResult;
    detectEncoding(buffer: Buffer): string;
    decompress(input: Buffer, hint?: string): string;
    extractArchives(content: string | Buffer): ExtractedFile[];
    normalizeText(raw: string): string;
    isWAFPage(content: string): boolean;
    isHTML(content: string): boolean;
    isLikelySecretFile(content: string, path?: string): boolean;
    extractWithPatterns(content: string): PatternMatch[];
    extractEnvKeyValues(content: string): Record<string, string>;
    extractJSONPayloads(html: string): ParsedPayload[];
    extractSourceMapRefs(jsContent: string): string[];
    parseSourceMapV3(json: string): SourceMapContent[];
    filterFalsePositives(matches: PatternMatch[]): PatternMatch[];
}
export interface HarvestedGitFile {
    fullName: string;
    filePath: string;
    content: string;
    htmlUrl: string;
    matches: PatternMatch[];
    summary: string;
    forge?: "github" | "gitlab" | "bitbucket";
}
export interface ValidationResult {
    service: string;
    valid: boolean;
    raw?: boolean;
    details: string;
    error?: string;
    meta?: Record<string, string>;
    harvested?: HarvestedGitFile[];
}
export interface ValidationHandler {
    readonly service: string;
    validate(hit: RawHit, match: PatternMatch, siblings: PatternMatch[]): Promise<ValidationResult>;
}
export interface IValidator {
    submit(hit: RawHit): void;
    drain(): Promise<void>;
}
export interface INotifier {
    startScan(label: string): Promise<void>;
    updateProgress(stats: ScanStats): Promise<void>;
    sendHit(hit: ValidatedHit): Promise<void>;
    sendFinalStats(stats: ScanStats): Promise<void>;
}
export interface ScanStats {
    urlsProcessed: number;
    urlsTotal?: number;
    hitsValid: number;
    hitsInvalid: number;
    hitsRaw: number;
    byService: Record<string, number>;
    cpm: number;
    fileName?: string;
    startedAt?: number;
    done?: boolean;
}
export interface IEventBus {
    on<T>(event: string, handler: (payload: T) => void): () => void;
    emit<T>(event: string, payload: T): void;
}
export interface IDedupStore {
    checkAndMark(scope: string, key: string): boolean;
    reset(scope?: string): void;
    unmark?(scope: string, key: string): void;
}
export interface IConfigProvider {
    get(): AppConfig;
    patterns(): PatternFile;
    resolveBudget(name: string): number;
}
export interface ILogger {
    info(module: string, msg: string, ...args: unknown[]): void;
    warn(module: string, msg: string, ...args: unknown[]): void;
    error(module: string, msg: string, ...args: unknown[]): void;
}
