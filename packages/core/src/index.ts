import { Container } from "./di/container.js";
import { TOKENS } from "./di/tokens.js";
import { ConfigProvider } from "./config/config-provider.js";
import { DedupStore } from "./dedup/dedup-store.js";
import { EventBus } from "./events/event-bus.js";
import { HttpClient } from "./http/http-client.js";
import { CurlImpersonateClient, hasCurlImpersonate } from "./http/curl-impersonate-client.js";
import { Logger } from "./logging/logger.js";
import { ModuleRegistry } from "./modules/module-registry.js";
import type { IHttpClient, HttpRequestOptions, HttpResponse } from "./types.js";

// ---------------------------------------------------------------------------
// LazyHttpClient — resolves the real client on first request.
//
// DI registration is synchronous but PATH lookup (which/where) is async.
// This wrapper defers the decision until get()/post() is first called.
//
//   CURL_IMPERSONATE_BIN set  →  skipped entirely, CurlImpersonateClient used directly
//   binary found in PATH      →  CurlImpersonateClient on first request (real JA3/JA4)
//   not found                 →  undici (HttpClient) — no fake log, no lie
// ---------------------------------------------------------------------------
class LazyHttpClient implements IHttpClient {
  private _inner: IHttpClient | null = null;
  private _resolving: Promise<IHttpClient> | null = null;

  constructor(
    private readonly _undici: HttpClient,
    private readonly _logger: Logger,
  ) {}

  private resolve(): Promise<IHttpClient> {
    if (this._inner) return Promise.resolve(this._inner);
    if (this._resolving) return this._resolving;
    this._resolving = hasCurlImpersonate().then((has) => {
      if (has) {
        this._logger.info("TLS", "curl-impersonate found in PATH — real JA3/JA4 Chrome active");
        this._inner = new CurlImpersonateClient();
      } else {
        this._logger.warn("TLS", "curl-impersonate not found — undici active (Node.js TLS fingerprint)");
        this._logger.warn("TLS", "Set CURL_IMPERSONATE_BIN or install: https://github.com/lwthiker/curl-impersonate");
        this._inner = this._undici;
      }
      return this._inner;
    });
    return this._resolving;
  }

  async get(url: string, options?: HttpRequestOptions): Promise<HttpResponse> {
    return (await this.resolve()).get(url, options);
  }
  async post(url: string, options?: HttpRequestOptions): Promise<HttpResponse> {
    return (await this.resolve()).post(url, options);
  }
}

export function registerCore(container: Container, configPath: string): void {
  container.registerSingleton(TOKENS.Config, () => new ConfigProvider(configPath));
  container.registerSingleton(TOKENS.Logger, () => new Logger());
  container.registerSingleton(TOKENS.EventBus, () => new EventBus());
  container.registerSingleton(TOKENS.Dedup, () => new DedupStore());
  container.registerSingleton(
    TOKENS.Http,
    (c) => {
      const logger = c.resolve(TOKENS.Logger);
      const undici = new HttpClient(c.resolve(TOKENS.Config), logger);
      // CURL_IMPERSONATE_BIN → immediate, no PATH probe needed.
      if (process.env["CURL_IMPERSONATE_BIN"]) {
        logger.info("TLS", "curl-impersonate active (CURL_IMPERSONATE_BIN) — real JA3/JA4 Chrome");
        return new CurlImpersonateClient();
      }
      // No env var → lazy PATH check at first request. Without binary = undici, period.
      return new LazyHttpClient(undici, logger);
    },
  );
}

export { Container } from "./di/container.js";
export { TOKENS } from "./di/tokens.js";
export { ModuleRegistry } from "./modules/module-registry.js";
export { ConfigProvider } from "./config/config-provider.js";
export { DedupStore, hashUrl } from "./dedup/dedup-store.js";
export { EventBus } from "./events/event-bus.js";
export { HttpClient } from "./http/http-client.js";
export { CurlImpersonateClient, hasCurlImpersonate } from "./http/curl-impersonate-client.js";
export { decodeHttpBody } from "./http/decode-body.js";
export {
  isUnreachableError,
  isDeadHostError,
  isClientDestroyedError,
  isTlsPlaintextError,
  isTlsHandshakeError,
} from "./http/is-unreachable.js";
export { Logger } from "./logging/logger.js";
export {
  normalizeScanUrl,
  originOf,
  httpsToHttpSamePort,
  httpsToHttpDefaultPort,
  homepageVariants,
  resolveUrl,
  sameHost,
  scanIdentity,
} from "./url/normalize.js";
export type * from "./types.js";
export { encodePathUtf16le, wafBypassVariants, utf16leBypassPath } from "./url/waf-bypass.js";
export { isValidAwsSecretKey, isAwsAccessKey, isVendorSecretPath } from "./secrets/aws-secret.js";
export { extractNextActionIds } from "./next-actions.js";
export { Semaphore } from "./concurrency/semaphore.js";
