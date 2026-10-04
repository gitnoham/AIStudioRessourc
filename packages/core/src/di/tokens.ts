import type { Token } from "./container.js";
import type {
  IConfigProvider,
  IContentAnalyzer,
  IDedupStore,
  IEventBus,
  IHttpClient,
  ILogger,
  INotifier,
  IValidator,
} from "../types.js";

export const TOKENS = {
  Config: Symbol("IConfigProvider") as Token<IConfigProvider>,
  Http: Symbol("IHttpClient") as Token<IHttpClient>,
  Analyzer: Symbol("IContentAnalyzer") as Token<IContentAnalyzer>,
  EventBus: Symbol("IEventBus") as Token<IEventBus>,
  Dedup: Symbol("IDedupStore") as Token<IDedupStore>,
  Validator: Symbol("IValidator") as Token<IValidator>,
  Notifier: Symbol("INotifier") as Token<INotifier>,
  Logger: Symbol("ILogger") as Token<ILogger>,
};
