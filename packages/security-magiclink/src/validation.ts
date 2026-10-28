// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import type { MagicLinkIntent } from './contracts.js';

export function failure(code: ErrorCode = 'EK_MAGICLINK_INVALID', uncertain = false): KitError {
  const messages: Partial<Record<ErrorCode, string>> = {
    EK_MAGICLINK_INVALID: 'The magic link operation could not be authorized',
    EK_MAGICLINK_EXPIRED: 'The magic link has expired',
    EK_MAGICLINK_REPLAY: 'The magic link is no longer available',
    EK_CONFIG_INVALID: 'The magic link configuration or input is invalid',
    EK_BACKEND_UNAVAILABLE: 'The magic link security provider is unavailable',
    EK_RESOURCE_CLOSED: 'The magic link service is closed',
    EK_ABORTED: 'The magic link operation was cancelled',
    EK_TIMEOUT: 'The magic link operation exceeded its deadline',
  };
  return new KitError({
    code,
    message: messages[code] ?? 'The magic link operation failed',
    ...(uncertain ? { details: { outcome: 'unknown' } } : {}),
  });
}
export function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    Array.isArray(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value))
  )
    throw failure('EK_CONFIG_INVALID');
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure('EK_CONFIG_INVALID');
    result[key] = descriptor.value;
  }
  return result;
}
export function property(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || types.isProxy(value))
    throw failure('EK_CONFIG_INVALID');
  let current: object | null = value;
  for (let depth = 0; current && depth < 32; depth++) {
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) {
      if (!('value' in descriptor)) throw failure('EK_CONFIG_INVALID');
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure('EK_CONFIG_INVALID');
  return undefined;
}
export function method<T>(value: unknown, key: string): T {
  const callable = property(value, key);
  if (typeof callable !== 'function' || types.isProxy(callable)) throw failure('EK_CONFIG_INVALID');
  return callable.bind(value) as T;
}
export function text(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure('EK_CONFIG_INVALID');
  return value;
}
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
export function intent(value: unknown): MagicLinkIntent {
  if (!['login', 'email-verify', 'account-recover'].includes(value as string))
    throw failure('EK_CONFIG_INVALID');
  return value as MagicLinkIntent;
}
export function issueId(value: unknown): string {
  const result = text(value, 36);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(result))
    throw failure('EK_MAGICLINK_INVALID');
  return result;
}
