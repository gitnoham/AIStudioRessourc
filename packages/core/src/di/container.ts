export type Token<T> = symbol & { readonly __type?: T };

type Factory<T> = (c: Container) => T;
type Lifecycle = "singleton" | "transient";

interface Registration<T> {
  factory: Factory<T>;
  lifecycle: Lifecycle;
  instance?: T;
}

export class Container {
  private readonly regs = new Map<symbol, Registration<unknown>>();

  registerSingleton<T>(token: Token<T>, factory: Factory<T>): this {
    this.regs.set(token, { factory, lifecycle: "singleton" });
    return this;
  }

  registerTransient<T>(token: Token<T>, factory: Factory<T>): this {
    this.regs.set(token, { factory, lifecycle: "transient" });
    return this;
  }

  registerInstance<T>(token: Token<T>, instance: T): this {
    this.regs.set(token, { factory: () => instance, lifecycle: "singleton", instance });
    return this;
  }

  resolve<T>(token: Token<T>): T {
    const reg = this.regs.get(token) as Registration<T> | undefined;
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

  tryResolve<T>(token: Token<T>): T | undefined {
    if (!this.regs.has(token)) return undefined;
    return this.resolve(token);
  }
}
