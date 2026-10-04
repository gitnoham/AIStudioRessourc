import type { IEventBus } from "../types.js";
export declare class EventBus implements IEventBus {
    private readonly handlers;
    on<T>(event: string, handler: (payload: T) => void): () => void;
    emit<T>(event: string, payload: T): void;
}
