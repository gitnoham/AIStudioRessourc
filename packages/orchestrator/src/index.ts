import { Container, ModuleRegistry, registerCore, Semaphore, TOKENS } from "@scanner/core";
import { ContentAnalyzer } from "@scanner/content-analyzer";
import { ValidatorService } from "@scanner/validator";
import { TelegramNotifier } from "@scanner/notifier-telegram";
import { Orchestrator } from "./orchestrator.js";
import type { ScanModule } from "@scanner/core";
import { join } from "node:path";

export async function bootstrap(
  configPath: string,
  packagesRoot: string,
  /** Override appsettings.json concurrency.urlWorkers at runtime (no file write). */
  workers?: number,
): Promise<Orchestrator> {
  const container = new Container();
  registerCore(container, configPath);
  container.registerSingleton(TOKENS.Analyzer, (c) => new ContentAnalyzer(c.resolve(TOKENS.Config)));
  container.registerSingleton(
    TOKENS.Notifier,
    (c) => new TelegramNotifier(c.resolve(TOKENS.Config), c.resolve(TOKENS.Logger), c.resolve(TOKENS.Http)),
  );
  container.registerSingleton(
    TOKENS.Validator,
    (c) => {
      const config = c.resolve(TOKENS.Config);
      const cfg = config.get();
      return new ValidatorService(
        c.resolve(TOKENS.Http),
        c.resolve(TOKENS.Notifier),
        c.resolve(TOKENS.EventBus),
        c.resolve(TOKENS.Logger),
        cfg.concurrency.validatorWorkers,
        [],
        join(cfg.dataDir, "seen_keys.json"),
        config.resolveBudget("smtpAuth"),
      );
    },
  );

  const logger = container.resolve(TOKENS.Logger);

  // Runtime override: --workers N from CLI, without touching appsettings.json.
  if (workers != null && workers > 0) {
    const cfg = container.resolve(TOKENS.Config).get();
    (cfg.concurrency as { urlWorkers: number }).urlWorkers = workers;
  }
  const registry = new ModuleRegistry(logger);
  const pathLimiter = new Semaphore(container.resolve(TOKENS.Config).get().concurrency.pathProbeGlobal ?? 240);
  const deps = {
    http: container.resolve(TOKENS.Http),
    analyzer: container.resolve(TOKENS.Analyzer),
    config: container.resolve(TOKENS.Config),
    dedup: container.resolve(TOKENS.Dedup),
    logger,
    pathLimiter,
  };

  await registry.discover(packagesRoot, (Ctor) => {
    return new (Ctor as unknown as new (d: typeof deps) => ScanModule)(deps);
  });

  if (!registry.modules.length) {
    const { default: Paths } = await import("@scanner/engine-paths");
    const { default: Js } = await import("@scanner/engine-js");
    const { default: Git } = await import("@scanner/engine-git");
    const { default: Recon } = await import("@scanner/engine-recon");
    const { default: Vuln } = await import("@scanner/engine-vuln");
    registry.register(new Paths(deps));
    registry.register(new Js(deps));
    registry.register(new Git(deps));
    registry.register(new Recon(deps));
    registry.register(new Vuln(deps));
  }

  return new Orchestrator(
    container.resolve(TOKENS.Config),
    container.resolve(TOKENS.Http),
    container.resolve(TOKENS.Analyzer),
    registry.modules,
    container.resolve(TOKENS.Validator),
    container.resolve(TOKENS.Notifier),
    container.resolve(TOKENS.Dedup),
    container.resolve(TOKENS.EventBus),
    logger,
  );
}

export { Orchestrator };
export { streamUrlFile } from "./url-stream.js";
