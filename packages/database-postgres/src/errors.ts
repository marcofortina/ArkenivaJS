// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** Vendor metadata is bounded and never includes SQL, credentials, detail strings or object names. */
export function postgresSqlState(error: unknown): string | undefined {
  const value = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  return typeof value === 'string' && /^[0-9A-Z]{5}(?![\s\S])/.test(value) ? value : undefined;
}

/** Tested PostgreSQL classes retain native causes without exposing vendor messages in safe JSON. */
export function postgresError(error: unknown, phase: 'connect' | 'query'): KitError {
  if (error instanceof KitError) return error;
  const state = postgresSqlState(error);
  const native = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  let code: ErrorCode = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_QUERY';
  let retryable = false;
  if (state?.startsWith('23')) code = 'EK_DATABASE_CONSTRAINT';
  else if (state === '40001' || state === '40P01') {
    code = 'EK_DATABASE_CONFLICT';
    retryable = true;
  } else if (state === '57014') code = 'EK_TIMEOUT';
  else if (
    state?.startsWith('08') ||
    ['57P01', '57P02', '57P03'].includes(state ?? '') ||
    ['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(
      String(native),
    ) ||
    (error instanceof Error &&
      ['Connection terminated unexpectedly', 'Connection terminated'].includes(error.message))
  ) {
    code = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_UNAVAILABLE';
    retryable = true;
  } else if (
    phase === 'connect' &&
    error instanceof Error &&
    [
      'timeout exceeded when trying to connect',
      'Connection terminated due to connection timeout',
    ].includes(error.message)
  ) {
    code = 'EK_DATABASE_POOL_TIMEOUT';
    retryable = true;
  }
  return new KitError({
    code,
    message:
      phase === 'connect'
        ? 'PostgreSQL connection acquisition failed'
        : 'PostgreSQL statement failed',
    cause: error,
    retryable,
    ...(state ? { details: { sqlState: state } } : {}),
  });
}

/** Only a definite ordinary server rejection establishes that a failed commit did not succeed. */
export function postgresCommitError(error: unknown): KitError {
  const state = postgresSqlState(error);
  const knownRejection = state !== undefined && /^(23|40|25)/.test(state);
  return new KitError({
    code: 'EK_DATABASE_TRANSACTION',
    message: knownRejection
      ? 'PostgreSQL commit was rejected'
      : 'PostgreSQL commit outcome is unknown',
    cause: error,
    retryable: false,
    ...(knownRejection ? {} : { details: { outcome: 'unknown' } }),
  });
}
