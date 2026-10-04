// One-off test runner: executes the project test suite synchronously and
// writes the full output to test-results.txt (shell redirection is not
// reliable in this environment).
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const files = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      "packages/core/src/url/normalize.test.ts",
      "packages/core/src/http/decode-body.test.ts",
      "packages/core/src/http/is-unreachable.test.ts",
      "packages/core/src/secrets/aws-secret.test.ts",
      "packages/core/src/concurrency/semaphore.test.ts",
      "packages/content-analyzer/src/analyzer.test.ts",
      "packages/engine-paths/src/paths.test.ts",
      "packages/engine-js/src/js.test.ts",
      "packages/engine-git/src/git.test.ts",
      "packages/engine-recon/src/recon.test.ts",
      "packages/engine-vuln/src/index.test.ts",
      "packages/notifier-telegram/src/templates.test.ts",
      "packages/notifier-telegram/src/bot-pool.test.ts",
      "packages/notifier-telegram/src/channel.test.ts",
      "packages/validator/src/smtp-env.test.ts",
      "packages/validator/src/smtp-probe.test.ts",
      "packages/validator/src/aws-github.test.ts",
      "packages/validator/src/git-forges.test.ts",
      "packages/validator/src/github-harvest.test.ts",
      "packages/validator/src/twilio.test.ts",
      "packages/validator/src/ai-models.test.ts",
      "packages/validator/src/salesforce-env.test.ts",
      "packages/validator/src/azure-env.test.ts",
      "packages/validator/src/zoho-env.test.ts",
      "packages/validator/src/crm-handlers.test.ts",
      "packages/validator/src/react2shell.test.ts",
    ];

let exit = 0;
let output = "";
try {
  output = execFileSync(process.execPath, ["--import", "tsx", "--test", ...files], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    cwd: process.cwd(),
  });
} catch (err) {
  exit = err.status ?? 1;
  output = `${err.stdout ?? ""}${err.stderr ?? ""}`;
}
writeFileSync("test-results.txt", `${output}\nEXIT_CODE=${exit}\n`, "utf8");
console.log(`EXIT_CODE=${exit}`);
