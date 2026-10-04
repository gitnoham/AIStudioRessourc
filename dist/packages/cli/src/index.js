import { resolve } from "node:path";
import { setMaxListeners } from "node:events";
import { bootstrap } from "@scanner/orchestrator";
setMaxListeners(100);
function parseArgs() {
    const argv = process.argv.slice(2);
    const cmd = argv[0] ?? "start";
    if (cmd !== "start") {
        console.log("usage: scanner start [--workers N]");
        process.exit(1);
    }
    const root = process.cwd();
    const configPath = resolve(root, process.env.SCANNER_CONFIG ?? "config/appsettings.json");
    let workers;
    for (let i = 1; i < argv.length; i++) {
        const arg = argv[i];
        if ((arg === "--workers" || arg === "-w") && argv[i + 1]) {
            const n = parseInt(argv[++i], 10);
            if (!Number.isNaN(n) && n > 0)
                workers = n;
        }
        else if (arg.startsWith("--workers=")) {
            const n = parseInt(arg.slice(10), 10);
            if (!Number.isNaN(n) && n > 0)
                workers = n;
        }
    }
    return { configPath, packagesRoot: resolve(root, "packages"), workers };
}
async function main() {
    const { configPath, packagesRoot, workers } = parseArgs();
    const orch = await bootstrap(configPath, packagesRoot, workers);
    if (workers != null) {
        console.log(`[CLI] urlWorkers overridden → ${workers}`);
    }
    await orch.scanCheckFolder();
}
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
