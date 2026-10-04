export type Token<T> = symbol & {
    readonly __type?: T;
};
type Factory<T> = (c: Container) => T;
export declare class Container {
    private readonly regs;
    registerSingleton<T>(token: Token<T>, factory: Factory<T>): this;
    registerTransient<T>(token: Token<T>, factory: Factory<T>): this;
    registerInstance<T>(token: Token<T>, instance: T): this;
    resolve<T>(token: Token<T>): T;
    tryResolve<T>(token: Token<T>): T | undefined;
}
export {};
