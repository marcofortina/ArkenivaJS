// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_EID_PROFILE'): KitError {
  return new KitError({
    code,
    message:
      code === 'EK_EID_ASSURANCE'
        ? 'The federation assurance policy was not satisfied'
        : code === 'EK_EID_FEDERATION'
          ? 'The federation trust policy was not satisfied'
          : 'The federation profile is invalid or unavailable',
  });
}
/** Reject executable configuration before reading any declared data properties. */
export function fields(input: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    Array.isArray(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const output = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(input)) {
    if (
      typeof key !== 'string' ||
      ['__proto__', 'prototype', 'constructor'].includes(key) ||
      (allowed && !allowed.includes(key))
    )
      throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw failure();
    output[key] = descriptor.value;
  }
  return output;
}
export function text(input: unknown, maximum = 256): string {
  if (
    typeof input !== 'string' ||
    !input.length ||
    Buffer.byteLength(input) > maximum ||
    /\s/u.test(input) ||
    [...input].some(
      (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    ) ||
    Buffer.from(input).toString() !== input
  )
    throw failure();
  return input;
}
export function integer(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) < 1) throw failure();
  return input as number;
}
export function url(input: unknown): string {
  const value = text(input, 2048);
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash)
      throw failure();
  } catch {
    throw failure();
  }
  return value;
}
export function list(input: unknown, maximum = 64): readonly unknown[] {
  if (
    !Array.isArray(input) ||
    types.isProxy(input) ||
    !input.length ||
    input.length > maximum ||
    Reflect.ownKeys(input).length !== input.length + 1
  )
    throw failure();
  const output: unknown[] = [];
  for (let index = 0; index < input.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !('value' in descriptor)) throw failure();
    output.push(descriptor.value);
  }
  return output;
}
/** Provider instances may use prototype methods; accessors and proxies are never invoked. */
export function method<T extends (...args: never[]) => unknown>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function' || types.isProxy(value)) throw failure();
  return Function.prototype.bind.call(value, input) as T;
}
export function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input))
    throw failure();
  let current: object | null = input;
  for (let depth = 0; current && depth < 8; depth++, current = Object.getPrototypeOf(current)) {
    if (types.isProxy(current)) throw failure();
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (!descriptor) continue;
    if (!('value' in descriptor)) throw failure();
    return descriptor.value;
  }
  if (current) throw failure();
  return undefined;
}
