import type { Token } from "./container.js";
import type { IConfigProvider, IContentAnalyzer, IDedupStore, IEventBus, IHttpClient, ILogger, INotifier, IValidator } from "../types.js";
export declare const TOKENS: {
    Config: Token<IConfigProvider>;
    Http: Token<IHttpClient>;
    Analyzer: Token<IContentAnalyzer>;
    EventBus: Token<IEventBus>;
    Dedup: Token<IDedupStore>;
    Validator: Token<IValidator>;
    Notifier: Token<INotifier>;
    Logger: Token<ILogger>;
};
