export declare function isTlsPlaintextError(err: unknown): boolean;
/** Handshake failed (old TLS, SNI, cipher) — not a dead TCP host. HTTP-on-443 is isTlsPlaintextError instead. */
export declare function isTlsHandshakeError(err: unknown): boolean;
export declare function isUnreachableError(err: unknown): boolean;
/** Host does not exist or TCP never connects — later paths will not work. HTTP 403/timeout on a path is not this. */
export declare function isDeadHostError(err: unknown): boolean;
export declare function isClientDestroyedError(err: unknown): boolean;
