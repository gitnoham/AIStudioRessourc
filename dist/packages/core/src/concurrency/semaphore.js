export class Semaphore {
    limit;
    active = 0;
    waiters = [];
    wi = 0;
    constructor(limit) {
        this.limit = limit;
        if (!Number.isFinite(limit) || limit < 1) {
            throw new Error(`semaphore limit must be >= 1, got ${limit}`);
        }
    }
    acquire(signal) {
        if (signal?.aborted)
            return Promise.reject(abortError(signal.reason));
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
                onAbort: undefined,
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
    release() {
        this.active--;
        while (this.wi < this.waiters.length) {
            const waiter = this.waiters[this.wi++];
            if (waiter.cancelled)
                continue;
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
function abortError(reason) {
    const err = new Error("semaphore wait aborted");
    err.name = "AbortError";
    err.reason = reason;
    return err;
}
