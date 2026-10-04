import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ensureEsbuild } from "./ensure-esbuild.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
ensureEsbuild(root);

const esbuild = await import("esbuild");
mkdirSync(join(root, "dist"), { recursive: true });

const alias = {
  "@scanner/core": join(root, "packages/core/src/index.ts"),
  "@scanner/content-analyzer": join(root, "packages/content-analyzer/src/index.ts"),
  "@scanner/orchestrator": join(root, "packages/orchestrator/src/index.ts"),
  "@scanner/engine-paths": join(root, "packages/engine-paths/src/index.ts"),
  "@scanner/engine-js": join(root, "packages/engine-js/src/index.ts"),
  "@scanner/engine-git": join(root, "packages/engine-git/src/index.ts"),
  "@scanner/engine-recon": join(root, "packages/engine-recon/src/index.ts"),
  "@scanner/engine-vuln": join(root, "packages/engine-vuln/src/index.ts"),
  "@scanner/validator": join(root, "packages/validator/src/index.ts"),
  "@scanner/notifier-telegram": join(root, "packages/notifier-telegram/src/index.ts"),
};

await esbuild.build({
  absWorkingDir: root,
  entryPoints: [join(root, "packages/cli/src/index.ts")],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  outfile: join(root, "dist/cli.mjs"),
  sourcemap: false,
  logLevel: "info",
  alias,
  external: ["undici", "adm-zip"],
});
