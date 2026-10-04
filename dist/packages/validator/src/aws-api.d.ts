import type { IHttpClient } from "@scanner/core";
export declare const AWS_SES_REGIONS: string[];
export declare const STS_REGIONS: string[];
export declare function extractXml(body: string, tag: string): string;
export declare function extractXmlList(body: string, tag: string): string[];
export declare function awsEndpoint(svc: string, region: string): {
    url: string;
    signSvc: string;
    signRegion: string;
    host: string;
};
export declare function awsQuery(http: IHttpClient, svc: string, region: string, access: string, secret: string, params: string): Promise<string>;
export declare function awsS3List(http: IHttpClient, access: string, secret: string): Promise<string>;
export declare function awsJson(http: IHttpClient, svc: string, region: string, target: string, access: string, secret: string, payload?: string): Promise<string>;
export declare function awsDenied(body: string): boolean;
export declare function awsOk(body: string, ...needles: string[]): boolean;
