import {
  ErrorReply,
  AbortError,
  TimeoutError,
  SocketClosedUnexpectedlyError,
  ClientClosedError,
  ClientOfflineError,
} from 'redis';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** Safe error prefixes never include Redis key, value, URL or server-message text. */
export function redisVendor(error: unknown): string | undefined {
  if (error instanceof KitError) return undefined;
  if (error instanceof ErrorReply)
    return error.message.match(/^([A-Z][A-Z0-9_]{0,63})(?=\s|(?![\s\S]))/)?.[1];
  const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}(?![\s\S])/.test(code) ? code : undefined;
}
/** Authentication and trust errors stop reconnect attempts before another credential exchange. */
export function permanentRedisError(error: unknown): boolean {
  return [
    'WRONGPASS',
    'NOAUTH',
    'NOPERM',
    'ERR_TLS_CERT_ALTNAME_INVALID',
    'CERT_HAS_EXPIRED',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  ].includes(redisVendor(error) ?? '');
}
/** An acknowledged Redis error differs from a write whose acknowledgment was lost. */
export function redisError(error: unknown, write = false, attempted = false): KitError {
  const vendor = redisVendor(error);
  let code: ErrorCode = 'EK_BACKEND_UNAVAILABLE';
  let retryable =
    error instanceof SocketClosedUnexpectedlyError ||
    error instanceof ClientClosedError ||
    error instanceof ClientOfflineError ||
    [
      'ECONNRESET',
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ENETUNREACH',
      'EHOSTUNREACH',
      'ENOTFOUND',
      'EPIPE',
    ].includes(vendor ?? '');
  if (error instanceof KitError) {
    code = error.code;
    retryable = error.retryable;
  } else if (error instanceof AbortError) code = 'EK_ABORTED';
  else if (error instanceof TimeoutError) code = 'EK_TIMEOUT';
  else if (['WRONGTYPE', 'ARKENIVA_INTEGER_RANGE', 'ARKENIVA_VALUE_LIMIT'].includes(vendor ?? ''))
    code = 'EK_KV_CONFLICT';
  const unknown = write && attempted && !(error instanceof ErrorReply);
  if (error instanceof KitError && !unknown) return error;
  return new KitError({
    code,
    message: unknown ? 'Redis write outcome is unknown' : 'Redis operation failed',
    cause: error,
    retryable: unknown ? false : retryable,
    details: {
      ...(vendor === undefined ? {} : { vendorCode: vendor }),
      ...(vendor === 'ARKENIVA_VALUE_LIMIT' ? { limitExceeded: true } : {}),
      ...(unknown ? { outcome: 'unknown' } : {}),
    },
  });
}
