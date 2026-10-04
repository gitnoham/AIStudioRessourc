import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { ScanModule } from "../types.js";
import type { ILogger } from "../types.js";

export class ModuleRegistry {
  readonly modules: ScanModule[] = [];

  constructor(private readonly logger: ILogger) {}

  register(mod: ScanModule): void {
    this.modules.push(mod);
    this.logger.info("ORCH", `module loaded: ${mod.name} (phase=${mod.phase})`);
  }

  enabled(config: { modules: Record<string, boolean> }): ScanModule[] {
    return this.modules.filter((m) => m.isEnabled(config as never));
  }

  byPhase(phase: ScanModule["phase"], config: { modules: Record<string, boolean> }): ScanModule[] {
    return this.enabled(config).filter((m) => m.phase === phase);
  }

  // Convention: packages/engine-<name>/src/index.ts default-exports a ScanModule class.
  async discover(packagesRoot: string, instantiate: (Mod: new (...args: never[]) => ScanModule) => ScanModule): Promise<void> {
    const root = resolve(packagesRoot);
    let entries: string[] = [];
    try {
      entries = (await readdir(root, { withFileTypes: true }))
        .filter((e) => e.isDirectory() && e.name.startsWith("engine-"))
        .map((e) => e.name);
    } catch (err) {
      this.logger.warn("ORCH", `module discover failed: ${(err as Error).message}`);
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
          const Ctor = (mod.default ?? mod.ScanModule) as (new (...args: never[]) => ScanModule) | undefined;
          if (Ctor) {
            this.register(instantiate(Ctor));
            break;
          }
          if (typeof mod.createModule === "function") {
            this.register(mod.createModule() as ScanModule);
            break;
          }
        } catch {
          continue;
        }
      }
    }
  }
}
