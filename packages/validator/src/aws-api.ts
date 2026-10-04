import { createHash, createHmac } from "node:crypto";
import type { IHttpClient } from "@scanner/core";

export const AWS_SES_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ca-central-1",
  "sa-east-1",
];

export const STS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"];

export function extractXml(body: string, tag: string): string {
  const open = `<${tag}>`;
  const close = `</${tag}>`;
  const start = body.indexOf(open);
  if (start < 0) return "";
  const from = start + open.length;
  const end = body.indexOf(close, from);
  if (end < 0) return "";
  return body.slice(from, end);
}

export function extractXmlList(body: string, tag: string): string[] {
  const open = `<${tag}>`;
  const close = `</${tag}>`;
  const out: string[] = [];
  let rest = body;
  for (;;) {
    const start = rest.indexOf(open);
    if (start < 0) break;
    const from = start + open.length;
    const end = rest.indexOf(close, from);
    if (end < 0) break;
    out.push(rest.slice(from, end));
    rest = rest.slice(end + close.length);
  }
  return out;
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: Buffer | string, data: string | Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function signingKey(secret: string, dateStamp: string, region: string, service: string): Buffer {
  return hmac(hmac(hmac(hmac(`AWS4${secret}`, dateStamp), region), service), "aws4_request");
}

export function awsEndpoint(svc: string, region: string): { url: string; signSvc: string; signRegion: string; host: string } {
  let signSvc = svc;
  let signRegion = region;
  let url: string;
  switch (svc) {
    case "iam":
      url = "https://iam.amazonaws.com/";
      signRegion = "us-east-1";
      break;
    case "email":
      url = `https://email.${region}.amazonaws.com/`;
      signSvc = "ses";
      break;
    case "sts":
      url = !region || region === "us-east-1" ? "https://sts.amazonaws.com/" : `https://sts.${region}.amazonaws.com/`;
      if (!region) signRegion = "us-east-1";
      break;
    default:
      url = `https://${svc}.${region}.amazonaws.com/`;
  }
  const host = new URL(url).host;
  return { url, signSvc, signRegion, host };
}

function signedHeaders(opts: {
  method: "GET" | "POST";
  host: string;
  path: string;
  query: string;
  body: string;
  service: string;
  region: string;
  access: string;
  secret: string;
  extra: Record<string, string>;
}): Record<string, string> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(opts.body);
  const toSign: Record<string, string> = {
    host: opts.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...opts.extra,
  };
  const headerKeys = Object.keys(toSign).sort();
  const canonicalHeaders = headerKeys.map((k) => `${k}:${toSign[k].trim()}`).join("\n") + "\n";
  const signed = headerKeys.join(";");
  const canonical = [opts.method, opts.path || "/", opts.query, canonicalHeaders, signed, payloadHash].join("\n");
  const scope = `${dateStamp}/${opts.region}/${opts.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonical)].join("\n");
  const signature = createHmac("sha256", signingKey(opts.secret, dateStamp, opts.region, opts.service))
    .update(stringToSign)
    .digest("hex");
  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${opts.access}/${scope}, SignedHeaders=${signed}, Signature=${signature}`,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...Object.fromEntries(Object.entries(opts.extra).map(([k, v]) => [k, v])),
  };
}

export async function awsQuery(
  http: IHttpClient,
  svc: string,
  region: string,
  access: string,
  secret: string,
  params: string,
): Promise<string> {
  const ep = awsEndpoint(svc, region);
  const extra: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  const headers = signedHeaders({
    method: "POST",
    host: ep.host,
    path: "/",
    query: "",
    body: params,
    service: ep.signSvc,
    region: ep.signRegion,
    access,
    secret,
    extra,
  });
  const res = await http.post(ep.url, {
    budget: "httpRequest",
    body: params,
    headers,
    maxBytes: 256 * 1024,
  });
  return res.text;
}

export async function awsS3List(http: IHttpClient, access: string, secret: string): Promise<string> {
  const host = "s3.amazonaws.com";
  const headers = signedHeaders({
    method: "GET",
    host,
    path: "/",
    query: "",
    body: "",
    service: "s3",
    region: "us-east-1",
    access,
    secret,
    extra: {},
  });
  const res = await http.get("https://s3.amazonaws.com/", { budget: "httpRequest", headers, maxBytes: 256 * 1024 });
  return res.text;
}

export async function awsJson(
  http: IHttpClient,
  svc: string,
  region: string,
  target: string,
  access: string,
  secret: string,
  payload = "{}",
): Promise<string> {
  const host = `${svc}.${region}.amazonaws.com`;
  const contentType = svc === "secretsmanager" ? "application/x-amz-json-1.1" : "application/x-amz-json-1.0";
  const extra: Record<string, string> = { "content-type": contentType, "x-amz-target": target };
  const headers = signedHeaders({
    method: "POST",
    host,
    path: "/",
    query: "",
    body: payload,
    service: svc,
    region,
    access,
    secret,
    extra,
  });
  const res = await http.post(`https://${host}/`, {
    budget: "httpRequest",
    body: payload,
    headers,
    maxBytes: 256 * 1024,
  });
  return res.text;
}

export function awsDenied(body: string): boolean {
  return /AccessDenied|AuthFailure|UnauthorizedOperation|AuthorizationError|AccessDeniedException|UnrecognizedClientException/i.test(
    body,
  );
}

export function awsOk(body: string, ...needles: string[]): boolean {
  if (!body || awsDenied(body) || body.includes("<Error>")) return false;
  return needles.some((n) => body.includes(n));
}
