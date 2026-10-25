import {
  castGrpcError,
  GRPCCancelledError,
  GRPCDeadlineExceededError,
  GRPCUnavailableError,
  GRPCInvalidArgumentError,
  GRPCNotFoundError,
  GRPCAlreadyExistsError,
  GRPCFailedPreconditionError,
  GRPCOutOfRangeError,
  GRPCUnauthenticatedError,
  GRPCAbortedError,
  GRPCResourceExhastedError,
  EtcdLeaseInvalidError,
  EtcdPermissionDeniedError,
  EtcdAuthenticationFailedError,
  EtcdInvalidAuthTokenError,
} from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

/** A decoded response can explicitly reject an operation without an ambiguous transport outcome. */
export class EtcdAcknowledgedError extends KitError {}

const known = [
  [GRPCCancelledError, 'CANCELLED'],
  [GRPCDeadlineExceededError, 'DEADLINE_EXCEEDED'],
  [GRPCUnavailableError, 'UNAVAILABLE'],
  [GRPCInvalidArgumentError, 'INVALID_ARGUMENT'],
  [GRPCNotFoundError, 'NOT_FOUND'],
  [GRPCAlreadyExistsError, 'ALREADY_EXISTS'],
  [GRPCFailedPreconditionError, 'FAILED_PRECONDITION'],
  [GRPCOutOfRangeError, 'OUT_OF_RANGE'],
  [GRPCUnauthenticatedError, 'UNAUTHENTICATED'],
  [GRPCAbortedError, 'ABORTED'],
  [GRPCResourceExhastedError, 'RESOURCE_EXHAUSTED'],
  [EtcdLeaseInvalidError, 'LEASE_INVALID'],
  [EtcdPermissionDeniedError, 'PERMISSION_DENIED'],
  [EtcdAuthenticationFailedError, 'AUTHENTICATION_FAILED'],
  [EtcdInvalidAuthTokenError, 'INVALID_AUTH_TOKEN'],
] as const;

/** Native class/status recognition never promotes server message text into a diagnostic label. */
export function etcdVendor(error: unknown): string | undefined {
  if (!(error instanceof Error) || error instanceof KitError) return undefined;
  const classified = castGrpcError(error);
  return known.find(([type]) => classified instanceof type)?.[1];
}

/** An explicit server rejection differs from an interrupted call with unacknowledged effects. */
export function etcdAcknowledgedFailure(error: unknown): boolean {
  if (error instanceof EtcdAcknowledgedError) return true;
  return [
    'INVALID_ARGUMENT',
    'NOT_FOUND',
    'ALREADY_EXISTS',
    'FAILED_PRECONDITION',
    'OUT_OF_RANGE',
    'UNAUTHENTICATED',
    'ABORTED',
    'LEASE_INVALID',
    'PERMISSION_DENIED',
    'AUTHENTICATION_FAILED',
    'INVALID_AUTH_TOKEN',
  ].includes(etcdVendor(error) ?? '');
}

/** Permanent authentication failures must terminate a watch rather than loop through resubscription. */
export function permanentEtcdError(error: unknown): boolean {
  const vendor = error instanceof KitError ? error.details.vendorCode : etcdVendor(error);
  return [
    'UNAUTHENTICATED',
    'PERMISSION_DENIED',
    'AUTHENTICATION_FAILED',
    'INVALID_AUTH_TOKEN',
    'INVALID_ARGUMENT',
    'OUT_OF_RANGE',
    'RESOURCE_EXHAUSTED',
  ].includes(typeof vendor === 'string' ? vendor : '');
}

/** Preserve unknown submitted write outcomes and the original private native exception. */
export function etcdError(error: unknown, write = false, submitted = false): KitError {
  const vendor = etcdVendor(error),
    unknown = write && submitted && !etcdAcknowledgedFailure(error);
  if (error instanceof KitError && !unknown) return error;
  let code: ErrorCode = error instanceof KitError ? error.code : 'EK_BACKEND_UNAVAILABLE';
  if (vendor === 'CANCELLED') code = 'EK_ABORTED';
  else if (vendor === 'DEADLINE_EXCEEDED') code = 'EK_TIMEOUT';
  else if (['LEASE_INVALID', 'ALREADY_EXISTS', 'ABORTED'].includes(vendor ?? ''))
    code = 'EK_KV_CONFLICT';
  return new KitError({
    code,
    message: unknown ? 'etcd write outcome is unknown' : 'etcd operation failed',
    cause: error,
    retryable: !unknown && (error instanceof KitError ? error.retryable : vendor === 'UNAVAILABLE'),
    details: {
      ...(vendor === undefined ? {} : { vendorCode: vendor }),
      ...(unknown ? { outcome: 'unknown' } : {}),
    },
  });
}
