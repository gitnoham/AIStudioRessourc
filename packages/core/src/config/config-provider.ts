import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { AppConfig, IConfigProvider, PatternFile } from "../types.js";

export class ConfigProvider implements IConfigProvider {
  private readonly config: AppConfig;
  private readonly patternFile: PatternFile;

  constructor(configPath: string) {
    const raw = JSON.parse(readFileSync(configPath, "utf8")) as AppConfig;
    this.config = raw;
    const patternsPath = resolve(process.cwd(), raw.patternsFile);
    this.patternFile = JSON.parse(readFileSync(patternsPath, "utf8")) as PatternFile;
  }

  get(): AppConfig {
    return this.config;
  }

  patterns(): PatternFile {
    return this.patternFile;
  }

  resolveBudget(name: string): number {
    const profile = this.config.budgets[name] ?? name;
    const ms = this.config.budgetProfiles[profile] ?? this.config.budgetProfiles.standard;
    return ms;
  }
}
