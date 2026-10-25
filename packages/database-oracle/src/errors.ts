import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** Retain only a bounded vendor code in safe details; native messages remain in the cause. */
export function oracleCode(error: unknown): string | undefined {
  const value = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  return typeof value === 'string' && /^(?:ORA-\d{5}|NJS-\d{3}|DPI-\d{4})(?![\s\S])/.test(value)
    ? value
    : undefined;
}

/** Tested classification never authorizes automatic replay. */
export function oracleError(error: unknown, phase: 'connect' | 'query'): KitError {
  if (error instanceof KitError) return error;
  const vendor = oracleCode(error);
  let code: ErrorCode = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_QUERY';
  let retryable = false;
  if (['ORA-00001', 'ORA-01400', 'ORA-02290', 'ORA-02291', 'ORA-02292'].includes(vendor ?? ''))
    code = 'EK_DATABASE_CONSTRAINT';
  else if (['ORA-00060', 'ORA-08177'].includes(vendor ?? '')) {
    code = 'EK_DATABASE_CONFLICT';
    retryable = true;
  } else if (['ORA-01013', 'DPI-1067', 'NJS-040'].includes(vendor ?? '')) {
    code = phase === 'connect' && vendor === 'NJS-040' ? 'EK_DATABASE_POOL_TIMEOUT' : 'EK_TIMEOUT';
    retryable = code === 'EK_DATABASE_POOL_TIMEOUT';
  } else if (
    ['ORA-03113', 'ORA-03114', 'ORA-03135', 'NJS-500', 'NJS-501', 'NJS-503'].includes(vendor ?? '')
  ) {
    code = phase === 'connect' ? 'EK_DATABASE_CONNECT' : 'EK_DATABASE_UNAVAILABLE';
    retryable = true;
  }
  return new KitError({
    code,
    retryable,
    cause: error,
    message:
      phase === 'connect' ? 'Oracle connection acquisition failed' : 'Oracle statement failed',
    ...(vendor === undefined ? {} : { details: { vendorCode: vendor } }),
  });
}

/** Missing COMMIT acknowledgment is an unknown outcome, including cancellation. */
export function oracleCommitError(cause: unknown): KitError {
  return new KitError({
    code: 'EK_DATABASE_TRANSACTION',
    message: 'Oracle commit outcome is unknown',
    cause,
    retryable: false,
    details: { outcome: 'unknown' },
  });
}
