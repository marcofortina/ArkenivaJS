import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { ETCD_LIMITS } from './limits.js';

/** Copy operation policy before asynchronous work or native submission. */
export function etcdOptions(
  input: OperationOptions = {},
  defaultTimeoutMs: number = ETCD_LIMITS.timeoutMs,
): {
  timeoutMs: number;
  signal?: AbortSignal;
} {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    (input.signal !== undefined && !(input.signal instanceof AbortSignal))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'etcd options require an object and an AbortSignal',
    });
  const timeoutMs = input.timeoutMs ?? defaultTimeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'etcd timeout must be positive integer milliseconds',
    });
  if (input.signal?.aborted)
    throw new KitError({
      code: 'EK_ABORTED',
      message: 'etcd operation aborted',
      cause: input.signal.reason,
    });
  return { timeoutMs, ...(input.signal === undefined ? {} : { signal: input.signal }) };
}

/** Portable identifiers are exact UTF-8 text; raw binary keys remain a native capability. */
export function etcdKey(key: string, prefix: string, allowEmpty = false): string {
  if (
    typeof key !== 'string' ||
    (!allowEmpty && key.length === 0) ||
    /[\0\r\n]/.test(key) ||
    Buffer.byteLength(key) > ETCD_LIMITS.keyBytes ||
    Buffer.from(key).toString('utf8') !== key
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'etcd key or prefix is invalid or exceeds its byte limit',
    });
  return prefix + key;
}

/** A native protobuf int64 arrives as canonical decimal text, never as a JavaScript number. */
export function etcdInteger(value: unknown, allowZero = false): bigint {
  if (typeof value !== 'string' || value.length > 19 || !/^(?:0|[1-9]\d*)(?![\s\S])/.test(value))
    throw new KitError({
      code: 'EK_BACKEND_UNAVAILABLE',
      message: 'etcd returned an invalid exact integer',
    });
  const integer = BigInt(value);
  if (integer > 9_223_372_036_854_775_807n || (!allowZero && integer === 0n))
    throw new KitError({
      code: 'EK_BACKEND_UNAVAILABLE',
      message: 'etcd returned an out-of-range integer',
    });
  return integer;
}

/** Snapshot raw values without UTF-8 coercion or shared mutable native buffers. */
export function etcdBytes(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength > ETCD_LIMITS.valueBytes)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'etcd values require bounded raw bytes',
    });
  return Buffer.from(value);
}
