export declare function probeSmtpPorts(host: string, ports: number[], timeoutMs: number): Promise<{
    ip: string;
    open: number[];
    errors: string[];
}>;
export type SmtpAuthResult = {
    ok: true;
    port: number;
} | {
    ok: false;
    kind: "auth";
    port: number;
    reply: string;
} | {
    ok: false;
    kind: "connect";
    errors: string[];
};
export declare function authenticateSmtp(opts: {
    host: string;
    user: string;
    pass: string;
    preferredPort: number;
    encryption?: string;
    timeoutMs: number;
    ports?: number[];
}): Promise<SmtpAuthResult>;
export declare function smtpPortOrder(preferred: number, encryption?: string): number[];
