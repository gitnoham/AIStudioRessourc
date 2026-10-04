export class EventBus {
    handlers = new Map();
    on(event, handler) {
        let set = this.handlers.get(event);
        if (!set) {
            set = new Set();
            this.handlers.set(event, set);
        }
        const wrapped = handler;
        set.add(wrapped);
        return () => set.delete(wrapped);
    }
    emit(event, payload) {
        const set = this.handlers.get(event);
        if (!set)
            return;
        for (const h of set) {
            try {
                h(payload);
            }
            catch (err) {
                console.error(`[EVENT] handler failed for ${event}:`, err);
            }
        }
    }
}
