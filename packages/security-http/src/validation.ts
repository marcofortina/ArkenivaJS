// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { types } from 'node:util';
import type { ErrorCode } from '@arkenivajs/core';
export const failure = (code: ErrorCode = 'EK_HTTP_SECURITY_POLICY', unknown = false) =>
  new KitError({
    code,
    message:
      code === 'EK_HTTP_SECURITY_POLICY'
        ? 'The HTTP security policy is invalid'
        : 'The HTTP security operation was rejected',
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
export function fields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const output: Record<string, unknown> = Object.create(null);
  const keys = Reflect.ownKeys(input);
  if (keys.length > 64) throw failure();
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(input, key)!;
    if (
      typeof key !== 'string' ||
      (allowed && !allowed.includes(key)) ||
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      !('value' in property)
    )
      throw failure();
    output[key] = property.value;
  }
  return output;
}
export function array(input: unknown, maximum: number): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure();
  const result: unknown[] = [];
  for (let i = 0; i < input.length; i++) {
    const value = Object.getOwnPropertyDescriptor(input, String(i));
    if (!value || !('value' in value)) throw failure();
    result.push(value.value);
  }
  return result;
}
export function text(input: unknown, maximum = 512): string {
  if (
    typeof input !== 'string' ||
    !input ||
    input.length > maximum ||
    [...input].some((character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127)
  )
    throw failure();
  return input;
}
export function integer(input: unknown, maximum: number): number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 1 || input > maximum)
    throw failure();
  return input;
}
export function method<T extends (...args: never[]) => unknown>(input: unknown, key: string): T {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw failure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 64; depth++) {
    if (types.isProxy(current)) throw failure();
    const value = Object.getOwnPropertyDescriptor(current, key);
    if (value) {
      if (!('value' in value) || typeof value.value !== 'function' || types.isProxy(value.value))
        throw failure();
      const captured = value.value;
      // Callable metadata cannot replace the configured function or its original receiver.
      const invoke = (...args: Parameters<T>): ReturnType<T> =>
        Reflect.apply(captured, input, args) as ReturnType<T>;
      return invoke as T;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw failure();
}
export function origin(input: unknown): string {
  const value = text(input, 2048);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw failure();
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.origin !== value ||
    url.username ||
    url.password ||
    url.hostname.includes('*')
  )
    throw failure();
  if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
    throw failure();
  return value;
}
