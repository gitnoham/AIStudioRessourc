export declare function streamUrlFile(file: string, excluded: Set<string>, seen: Set<string>): AsyncGenerator<string>;
export declare function countUrlFile(file: string, _excluded: Set<string>): Promise<number>;
export declare function loadExcluded(file: string): Set<string>;
