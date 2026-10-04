const TAG = {
    PATHS: "PATHS",
    JS: "JS",
    GIT: "GIT",
    RECON: "RECON",
    VALIDATOR: "VALIDATOR",
    TELEGRAM: "TELEGRAM",
    ORCH: "ORCH",
    ANALYZER: "ANALYZER",
};
function stamp() {
    return new Date().toISOString().slice(11, 23);
}
export class Logger {
    info(module, msg, ...args) {
        console.log(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
    }
    warn(module, msg, ...args) {
        console.warn(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
    }
    error(module, msg, ...args) {
        console.error(`[${stamp()}] [${TAG[module] ?? module}] ${msg}`, ...args);
    }
}
