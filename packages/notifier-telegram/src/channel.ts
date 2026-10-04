import type { TelegramConfig, ValidatedHit } from "@scanner/core";

const IA_SERVICES = new Set([
  "openai",
  "anthropic",
  "groq",
  "huggingface",
  "openrouter",
  "perplexity",
  "xai",
  "mistral",
  "together",
  "fireworks",
  "deepseek",
  "cohere",
  "voyage",
  "replicate",
  "nvidia",
]);

export function isIaService(service: string | undefined): boolean {
  return !!service && IA_SERVICES.has(service);
}

export function hitChannelId(hit: ValidatedHit, tg: TelegramConfig): string {
  const service = hit.matches[0]?.service;
  if (hit.validationStatus === "invalid") return tg.invalidHitsChannelId;
  if (hit.validationStatus === "valid" && isIaService(service) && tg.iaValidHitsChannelId) {
    return tg.iaValidHitsChannelId;
  }
  return tg.validHitsChannelId;
}
