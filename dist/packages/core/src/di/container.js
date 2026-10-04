export class Container {
    regs = new Map();
    registerSingleton(token, factory) {
        this.regs.set(token, { factory, lifecycle: "singleton" });
        return this;
    }
    registerTransient(token, factory) {
        this.regs.set(token, { factory, lifecycle: "transient" });
        return this;
    }
    registerInstance(token, instance) {
        this.regs.set(token, { factory: () => instance, lifecycle: "singleton", instance });
        return this;
    }
    resolve(token) {
        const reg = this.regs.get(token);
        if (!reg) {
            throw new Error(`DI: no registration for ${String(token)}`);
        }
        if (reg.lifecycle === "singleton") {
            if (reg.instance === undefined) {
                reg.instance = reg.factory(this);
            }
            return reg.instance;
        }
        return reg.factory(this);
    }
    tryResolve(token) {
        if (!this.regs.has(token))
            return undefined;
        return this.resolve(token);
    }
}
