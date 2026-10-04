import { readFileSync } from "node:fs";
import { resolve } from "node:path";
export class ConfigProvider {
    config;
    patternFile;
    constructor(configPath) {
        const raw = JSON.parse(readFileSync(configPath, "utf8"));
        this.config = raw;
        const patternsPath = resolve(process.cwd(), raw.patternsFile);
        this.patternFile = JSON.parse(readFileSync(patternsPath, "utf8"));
    }
    get() {
        return this.config;
    }
    patterns() {
        return this.patternFile;
    }
    resolveBudget(name) {
        const profile = this.config.budgets[name] ?? name;
        const ms = this.config.budgetProfiles[profile] ?? this.config.budgetProfiles.standard;
        return ms;
    }
}
