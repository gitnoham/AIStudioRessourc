export class DedupStore {
    scopes = new Map();
    checkAndMark(scope, key) {
        if (!key)
            return false;
        let set = this.scopes.get(scope);
        if (!set) {
            set = new Set();
            this.scopes.set(scope, set);
        }
        if (set.has(key))
            return false;
        set.add(key);
        return true;
    }
    reset(scope) {
        if (scope)
            this.scopes.delete(scope);
        else
            this.scopes.clear();
    }
    unmark(scope, key) {
        this.scopes.get(scope)?.delete(key);
    }
}
export function hashUrl(value) {
    let h = 2166136261;
    const s = value.toLowerCase();
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(16);
}
