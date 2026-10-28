// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_KAFKA_CONFIG', unknown = false): KitError {
  return new KitError({
    code,
    message: 'The managed Kafka operation could not complete',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
}
export function fields(value: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw failure();
  const output: Record<string, unknown> = Object.create(null);
  const keys = Reflect.ownKeys(value);
  if (keys.length > 128) throw failure();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (
      typeof key !== 'string' ||
      /^(?:__proto__|constructor|prototype)$/i.test(key) ||
      (allowed && !allowed.includes(key)) ||
      !('value' in descriptor)
    )
      throw failure();
    output[key] = descriptor.value;
  }
  return output;
}
export function array(value: unknown, maximum: number): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw failure();
  return Object.freeze(
    Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor)) throw failure();
      return descriptor.value as unknown;
    }),
  );
}
export function text(value: unknown, maximum: number, empty = false): string {
  if (
    typeof value !== 'string' ||
    (!empty && !value) ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure();
  return value;
}
export function integer(value: unknown, maximum: number, minimum = 1): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    throw failure();
  return value;
}
export function topic(value: unknown): string {
  const name = text(value, 249);
  if (!/^[A-Za-z0-9._-]+$/.test(name) || name === '.' || name === '..') throw failure();
  return name;
}
/** Offsets never pass through JavaScript number coercion. */
export function offset(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !/^(?:0|[1-9][0-9]{0,18})$/.test(value) ||
    BigInt(value) > 9223372036854775807n
  )
    throw failure('EK_KAFKA_OFFSET');
  return value;
}
/** Snapshot bytes without invoking user-defined iterators or accepting shared backing memory. */
export function bytes(value: unknown, maximum: number): Buffer {
  if (types.isProxy(value) || !types.isUint8Array(value)) throw failure();
  const length = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'byteLength',
  )!.get!.call(value) as number;
  const backing = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'buffer',
  )!.get!.call(value) as ArrayBufferLike;
  if (types.isSharedArrayBuffer(backing) || length > maximum) throw failure();
  try {
    const output = Buffer.alloc(length);
    Uint8Array.prototype.set.call(output, value);
    return output;
  } catch {
    throw failure();
  }
}
