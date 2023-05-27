/// <reference types="node" />
type Stringable = string | {
    toString: () => string;
};
export declare class ModSecurity {
    constructor();
    setLogCallback(callback: (message: string) => void): void;
}
export declare class Rules {
    constructor();
    loadFromFile(path: Stringable): boolean;
    add(rules: Stringable | Buffer): boolean;
    dump(): void;
    merge(rules: Rules): boolean;
    get length(): number;
}
export declare class Intervention {
    status: number;
    url: string | null;
    log: string | null;
    disruptive: boolean;
}
export declare class Transaction {
    constructor(modsec: ModSecurity, rules: Rules);
    processConnection(clientIP: Stringable, clientPort: number, serverIP: Stringable, serverPort: number): boolean | Intervention;
    processURI(uri: Stringable, method: Stringable, httpVersion: Stringable): boolean | Intervention;
    addRequestHeader(name: Stringable | Buffer, value: Stringable | Buffer): boolean;
    processRequestHeaders(): boolean | Intervention;
    appendRequestBody(body: string | Buffer): boolean | Intervention;
    requestBodyFromFile(path: Stringable): boolean | Intervention;
    processRequestBody(): boolean | Intervention;
    addResponseHeader(name: Stringable | Buffer, value: Stringable | Buffer): boolean;
    processResponseHeaders(status: number, protocolVersion: Stringable): boolean | Intervention;
    updateStatusCode(status: number): boolean;
    appendResponseBody(body: string | Buffer): boolean | Intervention;
    processResponseBody(): boolean | Intervention;
    processLogging(): boolean;
}
export {};
