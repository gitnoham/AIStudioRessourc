export class Semaphore {
  private active = 0;
  private readonly waiters: Array<{
    resolve: (release: () => void) => void;
    reject: (err: Error) => void;
    signal?: AbortSignal;
    onAbort?: () => void;
    cancelled: boolean;
  }> = [];
  private wi = 0;

  constructor(private readonly limit: number) {
    if (!Number.isFinite(limit) || limit < 1) {
      throw new Error(`semaphore limit must be >= 1, got ${limit}`);
    }
  }

  acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) return Promise.reject(abortError(signal.reason));
    if (this.active < this.limit) {
      this.active++;
      return Promise.resolve(() => this.release());
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve,
        reject,
        signal,
        cancelled: false,
        onAbort: undefined as (() => void) | undefined,
      };
      if (signal) {
        waiter.onAbort = () => {
          waiter.cancelled = true;
          reject(abortError(signal.reason));
        };
        signal.addEventListener("abort", waiter.onAbort, { once: true });
      }
      this.waiters.push(waiter);
    });
  }

  private release(): void {
    this.active--;
    while (this.wi < this.waiters.length) {
      const waiter = this.waiters[this.wi++];
      if (waiter.cancelled) continue;
      if (waiter.signal && waiter.onAbort) {
        waiter.signal.removeEventListener("abort", waiter.onAbort);
      }
      this.active++;
      waiter.resolve(() => this.release());
      return;
    }
    this.waiters.length = 0;
    this.wi = 0;
  }
}

function abortError(reason?: unknown): Error {
  const err = new Error("semaphore wait aborted") as Error & { reason?: unknown };
  err.name = "AbortError";
  err.reason = reason;
  return err;
}
