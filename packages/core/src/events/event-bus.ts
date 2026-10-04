import type { IEventBus } from "../types.js";

type Handler = (payload: unknown) => void;

export class EventBus implements IEventBus {
  private readonly handlers = new Map<string, Set<Handler>>();

  on<T>(event: string, handler: (payload: T) => void): () => void {
    let set = this.handlers.get(event);
    if (!set) {
      set = new Set();
      this.handlers.set(event, set);
    }
    const wrapped = handler as Handler;
    set.add(wrapped);
    return () => set!.delete(wrapped);
  }

  emit<T>(event: string, payload: T): void {
    const set = this.handlers.get(event);
    if (!set) return;
    for (const h of set) {
      try {
        h(payload);
      } catch (err) {
        console.error(`[EVENT] handler failed for ${event}:`, err);
      }
    }
  }
}
