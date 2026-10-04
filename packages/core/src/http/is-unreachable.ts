function errText(err: unknown): string {
  return err instanceof Error ? `${err.name} ${err.message}` : String(err);
}

export function isTlsPlaintextError(err: unknown): boolean {
  return /wrong version number|ssl3_get_record|ERR_SSL_WRONG_VERSION_NUMBER|packet length too long/i.test(
    errText(err),
  );
}

/** Handshake failed (old TLS, SNI, cipher) — not a dead TCP host. HTTP-on-443 is isTlsPlaintextError instead. */
export function isTlsHandshakeError(err: unknown): boolean {
  if (isTlsPlaintextError(err)) return false;
  return /SSL routines|unsupported protocol|ssl_choose_client_version|unrecognized name|handshake failure|tlsv1 alert|sslv3 alert|SSL alert number/i.test(
    errText(err),
  );
}

export function isUnreachableError(err: unknown): boolean {
  const msg = errText(err);
  return (
    isTlsHandshakeError(err) ||
    /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ECONNRESET|EPIPE|ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT|UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT|UND_ERR_ABORTED|UND_ERR_SOCKET|UND_ERR_DESTROYED|ConnectTimeoutError|HeadersTimeoutError|BodyTimeoutError|TimeoutError|AbortError|Connect Timeout|other side closed|client is destroyed|disconnected before secure TLS|wrong version number|ssl3_get_record|ERR_SSL_WRONG_VERSION_NUMBER|packet length too long|HTTP\/1\.1 protocol|Invalid character in chunk size|HPE_INVALID_CHUNK|unsafe legacy renegotiation/i.test(
      msg,
    )
  );
}

/** Host does not exist or TCP never connects — later paths will not work. HTTP 403/timeout on a path is not this. */
export function isDeadHostError(err: unknown): boolean {
  if (isTlsPlaintextError(err) || isTlsHandshakeError(err) || isClientDestroyedError(err)) return false;
  const msg = errText(err);
  if (/disconnected before secure TLS|HTTP\/1\.1 protocol|Invalid character in chunk size|unsafe legacy renegotiation/i.test(msg)) return false;
  return /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|UND_ERR_CONNECT_TIMEOUT|ConnectTimeoutError|Connect Timeout/i.test(
    msg,
  );
}

export function isClientDestroyedError(err: unknown): boolean {
  return /client is destroyed|UND_ERR_DESTROYED|ClientDestroyedError/i.test(errText(err));
}
