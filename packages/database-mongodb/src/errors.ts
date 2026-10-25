import {
  MongoServerError,
  MongoNetworkError,
  MongoServerSelectionError,
  MongoOperationTimeoutError,
  MongoNetworkTimeoutError,
  MongoInvalidArgumentError,
  MongoParseError,
  MongoExpiredSessionError,
  BSON,
} from 'mongodb';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** One portable attempt distinguishes native submission from an established acknowledgment. */
export interface MongoOutcome {
  readonly signal?: AbortSignal;
  readonly write: boolean;
  readonly atomic?: boolean;
  submitted: boolean;
  acknowledged: boolean;
  outcome?: 'acknowledged' | 'rolled_back';
}

const rejected = new Set([2, 9, 13, 18, 20, 26, 40, 66, 67, 72, 73, 121, 11000, 11001, 12582]);
const vendors: Readonly<Record<number, string>> = {
  2: 'BAD_VALUE',
  9: 'INVALID_ARGUMENT',
  13: 'UNAUTHORIZED',
  18: 'AUTHENTICATION_FAILED',
  20: 'ILLEGAL_OPERATION',
  26: 'NAMESPACE_NOT_FOUND',
  40: 'UPDATE_CONFLICT',
  50: 'EXECUTION_TIMEOUT',
  66: 'IMMUTABLE_FIELD',
  67: 'INDEX_INVALID',
  72: 'INVALID_OPTIONS',
  73: 'INVALID_NAMESPACE',
  91: 'SERVER_SHUTDOWN',
  112: 'WRITE_CONFLICT',
  121: 'DOCUMENT_VALIDATION',
  189: 'PRIMARY_CHANGED',
  251: 'TRANSACTION_MISSING',
  262: 'EXECUTION_TIMEOUT',
  11000: 'DUPLICATE_KEY',
  11001: 'DUPLICATE_KEY',
  12582: 'DUPLICATE_KEY',
};

/** Cursor BSON preservation also applies to native error envelopes; accept their exact int32 code. */
function serverCode(cause: MongoServerError): number {
  const value: unknown = cause.code;
  return value instanceof BSON.Int32 ? value.valueOf() : typeof value === 'number' ? value : -1;
}

/** Native message text and arbitrary code names never become default log or metric fields. */
export function mongoError(cause: unknown, scope?: MongoOutcome): KitError {
  const cancelled = scope?.signal?.aborted === true && cause === scope.signal.reason;
  const knownRejection =
    !cancelled &&
    cause instanceof MongoServerError &&
    rejected.has(serverCode(cause)) &&
    scope?.atomic !== false;
  const unknown =
    scope?.write === true && scope.submitted && !scope.acknowledged && !knownRejection;
  if (cause instanceof KitError && !unknown && !scope?.outcome && !cancelled) return cause;
  let code: ErrorCode = cause instanceof KitError ? cause.code : 'EK_DOCUMENT_OPERATION';
  let vendor: string | undefined;
  if (cause instanceof MongoOperationTimeoutError) {
    code = 'EK_TIMEOUT';
    vendor = 'OPERATION_TIMEOUT';
  } else if (cause instanceof Error && cause.name === 'MongoWaitQueueTimeoutError') {
    code = 'EK_DATABASE_POOL_TIMEOUT';
    vendor = 'POOL_TIMEOUT';
  } else if (cause instanceof MongoNetworkTimeoutError) {
    code = 'EK_TIMEOUT';
    vendor = 'NETWORK_TIMEOUT';
  } else if (cause instanceof MongoNetworkError || cause instanceof MongoServerSelectionError) {
    code = 'EK_DATABASE_UNAVAILABLE';
    vendor = 'NETWORK_UNAVAILABLE';
  } else if (cause instanceof MongoExpiredSessionError) {
    code = 'EK_RESOURCE_CLOSED';
    vendor = 'SESSION_CLOSED';
  } else if (cause instanceof MongoInvalidArgumentError || cause instanceof MongoParseError) {
    code = 'EK_CONFIG_INVALID';
    vendor = 'INVALID_ARGUMENT';
  } else if (cause instanceof MongoServerError) {
    const nativeCode = serverCode(cause);
    vendor = vendors[nativeCode] ?? 'SERVER_ERROR';
    if ([11000, 11001, 12582, 121].includes(nativeCode)) code = 'EK_DATABASE_CONSTRAINT';
    else if ([40, 112, 251].includes(nativeCode)) code = 'EK_DATABASE_CONFLICT';
    else if ([50, 262].includes(nativeCode)) code = 'EK_TIMEOUT';
    else if ([91, 189].includes(nativeCode)) code = 'EK_DATABASE_UNAVAILABLE';
  }
  if (cancelled) {
    const timedOut = cause instanceof KitError && cause.code === 'EK_TIMEOUT';
    code = timedOut ? 'EK_TIMEOUT' : 'EK_ABORTED';
    vendor = timedOut ? 'OPERATION_TIMEOUT' : 'CANCELLED';
  }
  return new KitError({
    code,
    message: unknown ? 'MongoDB write outcome is unknown' : 'MongoDB operation failed',
    cause,
    retryable: false,
    details: {
      ...(cause instanceof KitError ? cause.details : {}),
      ...(vendor ? { vendorCode: vendor } : {}),
      ...(unknown ? { outcome: 'unknown' } : scope?.outcome ? { outcome: scope.outcome } : {}),
    },
  });
}
