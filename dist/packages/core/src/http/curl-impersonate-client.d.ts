import type { IHttpClient, HttpRequestOptions, HttpResponse } from "../types.js";
export declare function hasCurlImpersonate(): Promise<boolean>;
export declare class CurlImpersonateClient implements IHttpClient {
    private readonly _timeout;
    private readonly _insecure;
    constructor(opts?: {
        timeout?: number;
        insecure?: boolean;
    });
    get(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
    post(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
}
