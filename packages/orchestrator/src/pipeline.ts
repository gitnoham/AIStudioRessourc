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

export class AsyncPipeline<T> {
  private readonly queue: T[] = [];
  /** Callbacks waiting for space in the queue (back-pressure). */
  private readonly pushWaiters: Array<() => void> = [];
  /** Callbacks waiting for the queue to become non-empty (workers). */
  private readonly popWaiters: Array<(item: T) => void> = [];
  private activeWorkers: number;
  private _done = 0;
  private _total = 0;
  private closed = false;

  /** Resolvers waiting for the pipeline to fully drain. */
  private readonly drainWaiters: Array<() => void> = [];

  constructor(
    private readonly concurrency: number,
    private readonly handler: (item: T) => Promise<void>,
    private readonly queueCap: number = concurrency * 8,
  ) {
    this.activeWorkers = concurrency;
    // Spawn N workers immediately.
    for (let i = 0; i < concurrency; i++) {
      void this.runWorker();
    }
  }

  /** Total items pushed so far. */
  get total(): number {
    return this._total;
  }

  /** Items fully processed. */
  get done(): number {
    return this._done;
  }

  /** Items currently waiting in the queue. */
  get pending(): number {
    return this.queue.length;
  }

  /** Items actively being processed by workers. */
  get active(): number {
    return this._total - this._done - this.queue.length;
  }

  /**
   * Push an item into the pipeline.
   * Suspends if the queue is at capacity (back-pressure) until a worker
   * picks up an item and makes room.
   */
  async push(item: T): Promise<void> {
    if (this.closed) throw new Error("AsyncPipeline: push() called after drain()");

    // If a worker is already waiting for work, hand it directly.
    if (this.popWaiters.length > 0) {
      const resolve = this.popWaiters.shift()!;
      this._total++;
      resolve(item);
      return;
    }

    // Apply back-pressure if the queue is full.
    if (this.queue.length >= this.queueCap) {
      await new Promise<void>((resolve) => {
        this.pushWaiters.push(resolve);
      });
    }

    this._total++;
    this.queue.push(item);
  }

  /**
   * Signal that no more items will be pushed, then wait until all items
   * have been fully processed.
   */
  async drain(): Promise<void> {
    this.closed = true;
    // Wake all workers waiting for pop so they detect the closed state.
    for (const resolve of this.popWaiters.splice(0)) {
      resolve(undefined as unknown as T); // sentinel — worker checks `closed`
    }
    if (this._done === this._total && this.activeWorkers === 0) return;
    await new Promise<void>((resolve) => {
      this.drainWaiters.push(resolve);
    });
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private async runWorker(): Promise<void> {
    for (;;) {
      const item = await this.pop();
      if (item === undefined) break; // sentinel: pipeline closed and empty

      try {
        await this.handler(item);
      } catch {
        /* individual URL errors are handled by the caller's handler */
      } finally {
        this._done++;
        this.checkDrain();
      }
    }
    this.activeWorkers--;
    this.checkDrain();
  }

  /**
   * Pop the next item. Suspends the worker if the queue is empty.
   * Returns `undefined` when the pipeline is closed and drained.
   */
  private pop(): Promise<T | undefined> {
    if (this.queue.length > 0) {
      const item = this.queue.shift()!;
      // Unblock a producer that was waiting for space.
      if (this.pushWaiters.length > 0) {
        const resolve = this.pushWaiters.shift()!;
        resolve();
      }
      return Promise.resolve(item);
    }

    if (this.closed) return Promise.resolve(undefined);

    return new Promise<T | undefined>((resolve) => {
      this.popWaiters.push((item: T) => {
        // After a direct hand-off, free a push-waiter if any.
        if (this.pushWaiters.length > 0) {
          this.pushWaiters.shift()!();
        }
        // If the pipeline was closed and we got a sentinel, resolve undefined.
        resolve(this.closed && item === undefined ? undefined : item);
      });
    });
  }

  private checkDrain(): void {
    if (this._done === this._total && (this.closed || this.activeWorkers === 0)) {
      for (const resolve of this.drainWaiters.splice(0)) {
        resolve();
      }
    }
  }
}
