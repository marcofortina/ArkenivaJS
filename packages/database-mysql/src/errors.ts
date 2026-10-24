import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** Keep only bounded numeric vendor identifiers, never SQL, values or server message text. */
export function mysqlErrno(error: unknown): number | undefined {
  const value = error && typeof error === 'object' && 'errno' in error ? error.errno : undefined;
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 65535
    ? value
    : undefined;
}

/** Classification is separate from retry: an adapter never replays a statement or callback. */
export function mysqlError(error: unknown, phase: 'connect' | 'query'): KitError {
  if (error instanceof KitError) return error;
  const errno = mysqlErrno(error);
  const native = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  let code: ErrorCode = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_QUERY';
  let retryable = false;
  if ([1062, 1048, 1451, 1452, 3819].includes(errno ?? 0)) code = 'EK_DATABASE_CONSTRAINT';
  else if ([1213, 1205].includes(errno ?? 0)) {
    code = 'EK_DATABASE_CONFLICT';
    retryable = true;
  } else if ([1317, 3024].includes(errno ?? 0)) code = 'EK_TIMEOUT';
  else if (
    [2006, 2013].includes(errno ?? 0) ||
    [
      'ECONNREFUSED',
      'ECONNRESET',
      'EPIPE',
      'ETIMEDOUT',
      'ENETUNREACH',
      'EHOSTUNREACH',
      'PROTOCOL_CONNECTION_LOST',
    ].includes(String(native))
  ) {
    code = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_UNAVAILABLE';
    retryable = true;
  } else if (
    phase === 'connect' &&
    error instanceof Error &&
    ['Queue limit reached.', 'No connections available.'].includes(error.message)
  ) {
    code = 'EK_DATABASE_POOL_TIMEOUT';
    retryable = true;
  }
  return new KitError({
    code,
    retryable,
    cause: error,
    message: phase === 'connect' ? 'MySQL connection acquisition failed' : 'MySQL statement failed',
    ...(errno === undefined ? {} : { details: { errno } }),
  });
}

/** A failed COMMIT acknowledgment never establishes that replay is safe. */
export function mysqlCommitError(error: unknown): KitError {
  return new KitError({
    code: 'EK_DATABASE_TRANSACTION',
    message: 'MySQL commit outcome is unknown',
    cause: error,
    retryable: false,
    details: { outcome: 'unknown' },
  });
}
