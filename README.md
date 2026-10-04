# Web Scanner — microservices + DI

Node.js + TypeScript scanner. URLs in `Check/*.txt` → normalize/dedup → four engines (paths, js, git, recon) → ContentAnalyzer → validator → Telegram.

## Quick start

```bash
cd scanner
npm install
npm run bundle
npm start
```

VPS : copier `dist/cli.mjs` + `packages/` + `config/` + `start.mjs`. **Ne jamais copier `node_modules` Windows.** `npm start` lance `dist/cli.mjs` (pas tsx, pas esbuild).

Put one URL per line in `Check/urls.txt` (bare domains are fine). Processed files move to `Done/`.

## Layout

```
packages/core                 DI, EventBus, HTTP, types, module registry
packages/content-analyzer     regex, WAF, gzip/zip, source maps, SSR JSON
packages/engine-paths         probe PathsToCheck
packages/engine-js            JS crawl + source maps
packages/engine-git          exposed .git dump
packages/engine-recon         __NEXT_DATA__, robots, sitemap
packages/validator            API checks → valid | invalid | raw
packages/notifier-telegram    hit + stats messages
packages/orchestrator         pipeline + workers
packages/cli                  `npm start`
config/appsettings.json
config/patterns.json          YOUR regexes (compiled at boot)
```

## Add a regex

Edit `config/patterns.json`:

```json
"credentials": {
  "myservice": {
    "patterns": [
      { "source": "\\b(MYPREFIX_[A-Za-z0-9]+)\\b", "flags": "g", "name": "myservice.key" }
    ]
  }
}
```

Discovery patterns (`scriptSrc`, `jsImportRef`, …) feed the JS/recon engines. Restart after edits.

## Add a scan module

1. Create `packages/engine-<name>/src/index.ts`
2. `export default class` implementing `ScanModule` with `constructor(deps: EngineDeps)`
3. Enable it in `config/appsettings.json` → `modules.<name>: true`

The registry glob-loads `packages/engine-*` at boot. No orchestrator change.

## Add a validator handler

Implement `ValidationHandler` in `packages/validator/src/handlers.ts` and register it in `builtinHandlers()`. Unknown services are sent as **raw** (non validé).

## Telegram

`config/appsettings.json` → `telegram.botTokens` (1 à 3 tokens, rotation + fallback 429) + IDs stats / valid / invalid. Tous les bots doivent être membres des mêmes chats. `botToken` reste un alias du premier.

## Budgets

Numeric delays live only in `budgetProfiles`. Map them with semantic names under `budgets` (`fastProbe`, `standard`, `laneBudget`, …). Tune there — not in engine code.
