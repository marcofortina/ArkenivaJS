// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_CONFIG_INVALID'): KitError {
  const messages: Partial<Record<ErrorCode, string>> = {
    EK_CONFIG_INVALID: 'The realtime configuration or input is invalid',
    EK_REALTIME_AUTH: 'The realtime identity could not be authorized',
    EK_REALTIME_BACKPRESSURE: 'The realtime stream exceeds its bounded capacity',
    EK_REALTIME_CLOSED: 'The realtime stream is closed',
    EK_BACKEND_UNAVAILABLE: 'The realtime provider is unavailable',
    EK_ABORTED: 'The realtime operation was cancelled',
    EK_TIMEOUT: 'The realtime operation exceeded its deadline',
    EK_LIFECYCLE_STATE: 'Realtime registration is permitted only before listener activation',
    EK_RESOURCE_CLOSED: 'The realtime service is closed',
    EK_UNSUPPORTED_CAPABILITY: 'The requested realtime capability is not configured',
  };
  return new KitError({ code, message: messages[code] ?? 'The realtime operation failed' });
}
export function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure();
    result[key] = descriptor.value;
  }
  return result;
}
export function list(value: unknown, maximum: number, minimum = 0): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    value.length < minimum ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw failure();
  return Object.freeze(
    Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor)) throw failure();
      return descriptor.value;
    }),
  );
}
export function text(value: unknown, maximum: number, multiline = false): string {
  if (
    typeof value !== 'string' ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some(
      (c) =>
        c.charCodeAt(0) === 127 ||
        (c.charCodeAt(0) < 32 && !(multiline && ['\n', '\t'].includes(c))),
    )
  )
    throw failure();
  return value;
}
export function name(value: unknown, maximum = 128): string {
  const result = text(value, maximum);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/.test(result)) throw failure();
  return result;
}
export function positive(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure();
  return value as number;
}
const typedPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const getBuffer = Object.getOwnPropertyDescriptor(typedPrototype, 'buffer')!.get!;
const getOffset = Object.getOwnPropertyDescriptor(typedPrototype, 'byteOffset')!.get!;
const getLength = Object.getOwnPropertyDescriptor(typedPrototype, 'byteLength')!.get!;
/** Snapshot native byte slots without evaluating caller accessors, iterators or species constructors. */
export function bytes(input: unknown, maximum: number): Uint8Array {
  if (!types.isUint8Array(input) || types.isProxy(input)) throw failure();
  const length = getLength.call(input) as number,
    buffer = getBuffer.call(input) as ArrayBuffer;
  if (length > maximum || !(buffer instanceof ArrayBuffer))
    throw failure('EK_REALTIME_BACKPRESSURE');
  const result = new Uint8Array(length);
  Uint8Array.prototype.set.call(
    result,
    new Uint8Array(buffer, getOffset.call(input) as number, length),
  );
  return result;
}
export function method<T>(value: unknown, key: PropertyKey, required = true): T | undefined {
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw failure();
  let current: object | null = value;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) {
      if (
        !('value' in descriptor) ||
        typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)
      )
        throw failure();
      const callback = descriptor.value;
      return ((...args: unknown[]) => Reflect.apply(callback, value, args)) as T;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (required || current) throw failure();
  return undefined;
}
export function property(value: unknown, key: PropertyKey): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw failure();
  let current: object | null = value;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) {
      if (!('value' in descriptor)) throw failure();
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure();
  return undefined;
}
/** A bounded opaque cursor is validated independently by its durable source. */
export function cursor(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._~-]{1,256}$/.test(value))
    throw new SseCursorError('invalid');
  return value;
}
/** Sources report only safe, explicit cursor outcomes; arbitrary provider exceptions stay private. */
export class SseCursorError extends KitError {
  readonly reason: 'expired' | 'invalid';
  constructor(reason: 'expired' | 'invalid') {
    if (reason !== 'expired' && reason !== 'invalid') throw failure();
    super({
      code: 'EK_REALTIME_CLOSED',
      message:
        reason === 'expired'
          ? 'The event cursor is no longer retained'
          : 'The event cursor cannot be resumed',
      details: { reason: 'cursor-' + reason },
    });
    this.reason = reason;
  }
}
