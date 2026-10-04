import type { ScanModule } from "../types.js";
import type { ILogger } from "../types.js";
export declare class ModuleRegistry {
    private readonly logger;
    readonly modules: ScanModule[];
    constructor(logger: ILogger);
    register(mod: ScanModule): void;
    enabled(config: {
        modules: Record<string, boolean>;
    }): ScanModule[];
    byPhase(phase: ScanModule["phase"], config: {
        modules: Record<string, boolean>;
    }): ScanModule[];
    discover(packagesRoot: string, instantiate: (Mod: new (...args: never[]) => ScanModule) => ScanModule): Promise<void>;
}
