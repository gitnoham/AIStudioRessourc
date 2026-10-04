import { existsSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function scannerRoot() {
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

function platformPkg() {
  const os = process.platform === "win32" ? "win32" : process.platform;
  const cpu = process.arch === "arm64" ? "arm64" : "x64";
  return `@esbuild/${os}-${cpu}`;
}

function esbuildVersion(root) {
  try {
    return JSON.parse(readFileSync(join(root, "node_modules/esbuild/package.json"), "utf8")).version;
  } catch {
    return "0.28.2";
  }
}

function npm(root, args) {
  execSync(`npm ${args}`, {
    cwd: root,
    stdio: "inherit",
    env: process.env,
  });
}

/** Same resolve esbuild uses — existsSync on disk is not enough. */
export function resolveEsbuildBin(root = scannerRoot()) {
  const pkg = platformPkg();
  const sub = process.platform === "win32" ? "esbuild.exe" : "bin/esbuild";
  try {
    const require = createRequire(join(root, "package.json"));
    const bin = require.resolve(`${pkg}/${sub}`);
    if (existsSync(bin)) return bin;
  } catch {
    /* not installed for this OS */
  }
  const fallback = join(root, "node_modules", pkg, sub);
  return existsSync(fallback) ? fallback : "";
}

export function ensureEsbuild(root = scannerRoot()) {
  let bin = resolveEsbuildBin(root);
  if (bin) {
    process.env.ESBUILD_BINARY_PATH = bin;
    return;
  }

  const pkg = platformPkg();
  const ver = esbuildVersion(root);
  console.log(`[dreks] npm install ${pkg}@${ver}`);
  try {
    npm(root, `install ${pkg}@${ver} --no-save --no-audit --no-fund --force`);
  } catch {
    /* npm ci below */
  }
  bin = resolveEsbuildBin(root);
  if (bin) {
    process.env.ESBUILD_BINARY_PATH = bin;
    return;
  }
  throw new Error(`${pkg} absent. npm start n'en a pas besoin si dist/cli.mjs est present.`);
}

const entry = process.argv[1] ? resolve(process.argv[1]) : "";
if (entry && fileURLToPath(import.meta.url) === entry) {
  try {
    ensureEsbuild();
  } catch (err) {
    console.error(`[dreks] ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}
