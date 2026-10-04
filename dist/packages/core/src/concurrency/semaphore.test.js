import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Semaphore } from "./semaphore.js";
describe("Semaphore", () => {
    it("caps concurrency at the limit and releases slots", async () => {
        const sem = new Semaphore(2);
        let active = 0;
        let peak = 0;
        const run = async () => {
            const release = await sem.acquire();
            active++;
            peak = Math.max(peak, active);
            await new Promise((r) => setTimeout(r, 10));
            active--;
            release();
        };
        await Promise.all(Array.from({ length: 8 }, run));
        assert.equal(peak, 2);
    });
    it("rejects a queued acquire when the signal aborts", async () => {
        const sem = new Semaphore(1);
        await sem.acquire();
        const ac = new AbortController();
        const waiting = sem.acquire(ac.signal);
        ac.abort();
        await assert.rejects(waiting, (err) => err.name === "AbortError");
    });
    it("grants a slot after a cancelled waiter is skipped", async () => {
        const sem = new Semaphore(1);
        const holder = await sem.acquire();
        const ac = new AbortController();
        const cancelled = sem.acquire(ac.signal);
        ac.abort();
        await assert.rejects(cancelled);
        let granted = false;
        const next = sem.acquire().then((release) => {
            granted = true;
            release();
        });
        holder();
        await next;
        assert.equal(granted, true);
    });
    it("rejects immediately when the signal is already aborted", async () => {
        const sem = new Semaphore(1);
        const ac = new AbortController();
        ac.abort();
        await assert.rejects(sem.acquire(ac.signal), (err) => err.name === "AbortError");
    });
});
