import type { IConfigProvider, IHttpClient, HttpRequestOptions, HttpResponse, ILogger } from "../types.js";
export declare class HttpClient implements IHttpClient {
    private readonly config;
    private readonly logger;
    private readonly pools;
    private readonly inFlight;
    /** HTTPS origins that answered with plaintext HTTP — later GETs use http://host:443. */
    private readonly plaintextHttps;
    constructor(config: IConfigProvider, logger: ILogger);
    get(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
    post(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
    private bump;
    private dropPool;
    private evictIdle;
    private markPlaintextHttps;
    private rewriteIfPlaintext;
    private abortFor;
    private dispatcherFor;
    private request;
}
