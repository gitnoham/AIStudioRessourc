import { existsSync, readdirSync, statSync } from "node:fs";
import { extname } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const cli = join(root, "dist/cli.mjs");

/** mtime du fichier source le plus récent sous `dir` (pour rebuild auto). */
function newestMtime(dir) {
  let newest = 0;
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git" || entry.name === ".agent-cache") {
        continue;
      }
      const p = join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if ([".ts", ".mjs"].includes(extname(entry.name))) {
        const t = statSync(p).mtimeMs;
        if (t > newest) newest = t;
      }
    }
  };
  walk(dir);
  return newest;
}

function bundleIsStale() {
  try {
    const bundleMtime = statSync(cli).mtimeMs;
    // Déploiement dist-only (VPS sans sources) : rien à rebundler, on tourne tel quel.
    if (!existsSync(join(root, "packages"))) return false;
    if (newestMtime(join(root, "packages")) > bundleMtime) return true;
    if (statSync(join(root, "scripts/bundle.mjs")).mtimeMs > bundleMtime) return true;
    if (statSync(join(root, "package.json")).mtimeMs > bundleMtime) return true;
    return false;
  } catch {
    return true;
  }
}

function fail(msg) {
  console.error(`[dreks] ${msg}`);
  process.exit(1);
}

/** Never spawn tsx. tsx → esbuild native → crash Windows node_modules on Linux. */
if (!existsSync(cli) || bundleIsStale()) {
  const heal = spawnSync(process.execPath, [join(root, "scripts/ensure-esbuild.mjs")], {
    cwd: root,
    stdio: "inherit",
    env: process.env,
  });
  if (heal.status !== 0) {
    fail("dist/cli.mjs absent. Sur Windows : npm run bundle — puis copier dist/ (pas node_modules).");
  }
  const bundle = spawnSync(process.execPath, [join(root, "scripts/bundle.mjs")], {
    cwd: root,
    stdio: "inherit",
    env: process.env,
  });
  if (bundle.status !== 0 || !existsSync(cli)) {
    fail("bundle echoue. Sur Windows : npm run bundle — puis copier dist/ sur le VPS.");
  }
}

const nodeArgs = [
  "--max-old-space-size=12288",
  "--tls-min-v1.0",
  cli,
  ...process.argv.slice(2),
];

const env = {
  ...process.env,
  UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE || "320",
};

const child =
  process.platform === "win32"
    ? spawn(process.execPath, nodeArgs, { stdio: "inherit", cwd: process.cwd(), env })
    : spawn(
        "bash",
        ["-c", 'ulimit -n 65535 2>/dev/null || true; exec "$@"', "dreks", process.execPath, ...nodeArgs],
        { stdio: "inherit", cwd: process.cwd(), env },
      );

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
