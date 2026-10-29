// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { types } from 'node:util';
import type { ErrorCode } from '@arkenivajs/core';
export const failure = (code: ErrorCode = 'EK_LDAP_FILTER', unknown = false) =>
  new KitError({
    code,
    message: 'The directory operation could not complete',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
export function fields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null),
    keys = Reflect.ownKeys(input);
  if (keys.length > 64) throw failure();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
    if (
      typeof key !== 'string' ||
      (allowed && !allowed.includes(key)) ||
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      !('value' in descriptor)
    )
      throw failure();
    result[key] = descriptor.value;
  }
  return result;
}
export function text(input: unknown, maximum: number, empty = false): string {
  if (
    typeof input !== 'string' ||
    (!empty && !input) ||
    input.length > maximum ||
    input.includes('\0') ||
    Buffer.byteLength(input) > maximum
  )
    throw failure();
  const encoded = Buffer.from(input);
  try {
    if (encoded.toString('utf8') !== input) throw failure();
    return input;
  } finally {
    encoded.fill(0);
  }
}
export function integer(input: unknown, maximum: number, minimum = 1): number {
  if (
    typeof input !== 'number' ||
    !Number.isSafeInteger(input) ||
    input < minimum ||
    input > maximum
  )
    throw failure();
  return input;
}
export function array(input: unknown, maximum: number): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure();
  return Object.freeze(
    Array.from({ length: input.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
      if (!descriptor || !('value' in descriptor)) throw failure();
      return descriptor.value as unknown;
    }),
  );
}
export function attribute(input: unknown): string {
  const value = text(input, 64).toLowerCase();
  if (
    !/^[a-z][a-z0-9-]*$/.test(value) ||
    [
      'userpassword',
      'authpassword',
      'unicodepwd',
      'supplementalcredentials',
      'pwdhistory',
      'ntpwdhistory',
      'lmpwdhistory',
      'dBCSPwd'.toLowerCase(),
      'msds-managedpassword',
    ].includes(value)
  )
    throw failure();
  return value;
}
export function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw failure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 64; depth++) {
    if (types.isProxy(current)) throw failure();
    const value = Object.getOwnPropertyDescriptor(current, name);
    if (value) {
      if (!('value' in value)) throw failure();
      return value.value as unknown;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw failure();
  return undefined;
}
export function method<T extends (...args: never[]) => unknown>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function' || types.isProxy(value)) throw failure();
  // Callable metadata cannot replace the configured function or its original receiver.
  const invoke = (...args: Parameters<T>): ReturnType<T> =>
    Reflect.apply(value, input, args) as ReturnType<T>;
  return invoke as T;
}
