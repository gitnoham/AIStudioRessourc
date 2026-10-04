import type { ILogger } from "../types.js";

const TAG: Record<string, string> = {
  PATHS: "PATHS",
  JS: "JS",
  GIT: "GIT",
  RECON: "RECON",
  VALIDATOR: "VALIDATOR",
  TELEGRAM: "TELEGRAM",
  ORCH: "ORCH",
  ANALYZER: "ANALYZER",
};

function stamp(): string {
  return new Date().toISOString().slice(11, 23);
}

export class Logger implements ILogger {
  info(module: string, msg: string, ...args: unknown[]): void {
    console.log(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
  }
  warn(module: string, msg: string, ...args: unknown[]): void {
    console.warn(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
  }
  error(module: string, msg: string, ...args: unknown[]): void {
    console.error(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
  }
}
