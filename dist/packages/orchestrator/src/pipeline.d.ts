/**
 * AsyncPipeline<T> — N-worker producer/consumer pipeline with back-pressure.
 *
 * Replaces the manual `state.queue[] + state.qi + sleep(20)` pattern used
 * in the orchestrator with a fully promise-driven implementation:
 *
 *   - N workers consume items concurrently.
 *   - `push(item)` resolves immediately when the queue has capacity.
 *   - `push(item)` suspends the caller (back-pressure) when the queue is full,
 *     resuming only when a worker picks up an item — zero polling / sleep loops.
 *   - `drain()` waits until all pushed items have been fully processed.
 *
 * Usage:
 *   const pipeline = new AsyncPipeline(400, async (url) => { ... });
 *   for await (const url of stream) await pipeline.push(url);
 *   await pipeline.drain();
 */
export declare class AsyncPipeline<T> {
    private readonly concurrency;
    private readonly handler;
    private readonly queueCap;
    private readonly queue;
    /** Callbacks waiting for space in the queue (back-pressure). */
    private readonly pushWaiters;
    /** Callbacks waiting for the queue to become non-empty (workers). */
    private readonly popWaiters;
    private activeWorkers;
    private _done;
    private _total;
    private closed;
    /** Resolvers waiting for the pipeline to fully drain. */
    private readonly drainWaiters;
    constructor(concurrency: number, handler: (item: T) => Promise<void>, queueCap?: number);
    /** Total items pushed so far. */
    get total(): number;
    /** Items fully processed. */
    get done(): number;
    /** Items currently waiting in the queue. */
    get pending(): number;
    /** Items actively being processed by workers. */
    get active(): number;
    /**
     * Push an item into the pipeline.
     * Suspends if the queue is at capacity (back-pressure) until a worker
     * picks up an item and makes room.
     */
    push(item: T): Promise<void>;
    /**
     * Signal that no more items will be pushed, then wait until all items
     * have been fully processed.
     */
    drain(): Promise<void>;
    private runWorker;
    /**
     * Pop the next item. Suspends the worker if the queue is empty.
     * Returns `undefined` when the pipeline is closed and drained.
     */
    private pop;
    private checkDrain;
}
