import type { ILogger } from "../types.js";
export declare class Logger implements ILogger {
    info(module: string, msg: string, ...args: unknown[]): void;
    warn(module: string, msg: string, ...args: unknown[]): void;
    error(module: string, msg: string, ...args: unknown[]): void;
}
