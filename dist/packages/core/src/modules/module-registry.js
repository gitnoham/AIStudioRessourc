import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
export class ModuleRegistry {
    logger;
    modules = [];
    constructor(logger) {
        this.logger = logger;
    }
    register(mod) {
        this.modules.push(mod);
        this.logger.info("ORCH", `module loaded: ${mod.name} (phase=${mod.phase})`);
    }
    enabled(config) {
        return this.modules.filter((m) => m.isEnabled(config));
    }
    byPhase(phase, config) {
        return this.enabled(config).filter((m) => m.phase === phase);
    }
    // Convention: packages/engine-<name>/src/index.ts default-exports a ScanModule class.
    async discover(packagesRoot, instantiate) {
        const root = resolve(packagesRoot);
        let entries = [];
        try {
            entries = (await readdir(root, { withFileTypes: true }))
                .filter((e) => e.isDirectory() && e.name.startsWith("engine-"))
                .map((e) => e.name);
        }
        catch (err) {
            this.logger.warn("ORCH", `module discover failed: ${err.message}`);
            return;
        }
        for (const name of entries) {
            const candidates = [
                join(root, name, "src", "index.ts"),
                join(root, name, "dist", "index.js"),
                join(root, name, "index.ts"),
            ];
            for (const file of candidates) {
                try {
                    const mod = await import(pathToFileURL(file).href);
                    const Ctor = (mod.default ?? mod.ScanModule);
                    if (Ctor) {
                        this.register(instantiate(Ctor));
                        break;
                    }
                    if (typeof mod.createModule === "function") {
                        this.register(mod.createModule());
                        break;
                    }
                }
                catch {
                    continue;
                }
            }
        }
    }
}
