export declare class Semaphore {
    private readonly limit;
    private active;
    private readonly waiters;
    private wi;
    constructor(limit: number);
    acquire(signal?: AbortSignal): Promise<() => void>;
    private release;
}
