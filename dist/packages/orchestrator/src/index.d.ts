import { Orchestrator } from "./orchestrator.js";
export declare function bootstrap(configPath: string, packagesRoot: string, 
/** Override appsettings.json concurrency.urlWorkers at runtime (no file write). */
workers?: number): Promise<Orchestrator>;
export { Orchestrator };
export { streamUrlFile } from "./url-stream.js";
