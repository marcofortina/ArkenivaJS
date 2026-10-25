// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** Keep only bounded numeric vendor identifiers, never SQL, values or server message text. */
export function mariadbErrno(error: unknown): number | undefined {
  const value = error && typeof error === 'object' && 'errno' in error ? error.errno : undefined;
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 65535
    ? value
    : undefined;
}

/** Classification is separate from retry: an adapter never replays a statement or callback. */
export function mariadbError(error: unknown, phase: 'connect' | 'query'): KitError {
  if (error instanceof KitError) return error;
  // A native pool acquisition error can retain the actual TLS/authentication failure as its cause.
  let source = error;
  if (phase === 'connect') {
    const seen = new Set<unknown>();
    for (
      let depth = 0;
      depth < 8 &&
      source &&
      typeof source === 'object' &&
      'cause' in source &&
      source.cause &&
      !seen.has(source.cause);
      depth++
    ) {
      seen.add(source);
      source = source.cause;
    }
  }
  const errno = mariadbErrno(source);
  const native = source && typeof source === 'object' && 'code' in source ? source.code : undefined;
  let code: ErrorCode = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_QUERY';
  let retryable = false;
  if ([1062, 1048, 1451, 1452, 4025].includes(errno ?? 0)) code = 'EK_DATABASE_CONSTRAINT';
  else if ([1213, 1205].includes(errno ?? 0)) {
    code = 'EK_DATABASE_CONFLICT';
    retryable = true;
  } else if ([1317, 1969].includes(errno ?? 0)) code = 'EK_TIMEOUT';
  else if (
    [1927, 2006, 2013, 45001, 45004, 45009, 45012, 45013, 45019, 45026].includes(errno ?? 0) ||
    ['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(
      String(native),
    )
  ) {
    code = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_UNAVAILABLE';
    retryable = true;
  } else if (phase === 'connect' && native === 'ER_GET_CONNECTION_TIMEOUT') {
    code = 'EK_DATABASE_POOL_TIMEOUT';
    retryable = true;
  }
  return new KitError({
    code,
    retryable,
    cause: error,
    message:
      phase === 'connect' ? 'MariaDB connection acquisition failed' : 'MariaDB statement failed',
    ...(errno === undefined ? {} : { details: { errno } }),
  });
}

/** A failed COMMIT acknowledgment never establishes that replay is safe. */
export function mariadbCommitError(error: unknown): KitError {
  return new KitError({
    code: 'EK_DATABASE_TRANSACTION',
    message: 'MariaDB commit outcome is unknown',
    cause: error,
    retryable: false,
    details: { outcome: 'unknown' },
  });
}
