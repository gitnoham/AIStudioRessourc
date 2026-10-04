import type { AppConfig, IConfigProvider, PatternFile } from "../types.js";
export declare class ConfigProvider implements IConfigProvider {
    private readonly config;
    private readonly patternFile;
    constructor(configPath: string);
    get(): AppConfig;
    patterns(): PatternFile;
    resolveBudget(name: string): number;
}
