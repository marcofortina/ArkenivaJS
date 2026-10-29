// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_SAML_CONFIGURATION', unknown = false): KitError {
  return new KitError({
    code,
    message:
      (
        {
          EK_SAML_CONFIGURATION: 'The SAML configuration is invalid',
          EK_SAML_SIGNATURE: 'The SAML signature could not be verified',
          EK_SAML_ASSERTION: 'The SAML message could not be accepted',
          EK_SAML_REPLAY: 'The SAML transaction is unavailable or already consumed',
          EK_ABORTED: 'The SAML operation was cancelled',
          EK_TIMEOUT: 'The SAML operation exceeded its deadline',
          EK_BACKEND_UNAVAILABLE: 'The SAML provider is unavailable',
          EK_RESOURCE_CLOSED: 'The SAML service is closed',
          EK_LIFECYCLE_STATE: 'The SAML service is not active',
        } as Partial<Record<ErrorCode, string>>
      )[code] ?? 'The SAML operation failed',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
}
export function fields(
  input: unknown,
  allowed: readonly string[],
  maximum = 64,
): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null),
    keys = Reflect.ownKeys(input);
  if (keys.length > maximum) throw failure();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure();
    result[key] = descriptor.value;
  }
  return result;
}
export function text(value: unknown, maximum: number, empty = false): string {
  if (
    typeof value !== 'string' ||
    (!empty && !value) ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure();
  return value;
}
export function integer(value: unknown, maximum: number, minimum = 1): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw failure();
  return value as number;
}
export function list(value: unknown, maximum: number): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw failure('EK_SAML_ASSERTION');
  return Object.freeze(
    Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor)) throw failure('EK_SAML_ASSERTION');
      return descriptor.value as unknown;
    }),
  );
}
export function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw failure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (!('value' in descriptor)) throw failure();
      return descriptor.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure();
  return undefined;
}
export function method<T extends (...args: never[]) => unknown>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function' || types.isProxy(value)) throw failure();
  const invoke = (...args: Parameters<T>): ReturnType<T> =>
    Reflect.apply(value, input, args) as ReturnType<T>;
  return invoke as T;
}
export function url(input: unknown, environment: string): string {
  const value = text(input, 2048);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw failure();
  }
  if (
    (parsed.protocol !== 'https:' &&
      !(
        environment === 'test' &&
        parsed.protocol === 'http:' &&
        ['127.0.0.1', '[::1]', 'localhost'].includes(parsed.hostname)
      )) ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    parsed.search ||
    parsed.href !== value
  )
    throw failure();
  return value;
}
export function requestId(value: unknown): string {
  const selected = text(value, 128);
  if (!/^_[a-f0-9]{40}$/.test(selected)) throw failure('EK_SAML_ASSERTION');
  return selected;
}
export function returnPath(value: unknown): string {
  const path = text(value, 2048);
  if (
    !path.startsWith('/') ||
    path.startsWith('//') ||
    /[\\#]/.test(path) ||
    /%(?:00|0a|0d|2f|5c)/i.test(path) ||
    new URL(path, 'https://local.invalid').origin !== 'https://local.invalid'
  )
    throw failure();
  return path;
}
