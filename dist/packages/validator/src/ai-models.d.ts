/** Parse GET /models JSON (OpenAI-compatible, Anthropic, Cohere). */
export declare const MODEL_LIST_CAP = 40;
export declare function parseModelIds(text: string): string[];
export declare function modelsMeta(ids: string[]): Record<string, string>;
