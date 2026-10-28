// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_SCIM_BAD_REQUEST', unknown = false): KitError {
  return new KitError({
    code,
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
    message:
      code === 'EK_SCIM_UNAUTHORIZED'
        ? 'The SCIM request is not authorized'
        : code === 'EK_SCIM_CONFLICT'
          ? 'The SCIM resource conflicts with existing state'
          : code === 'EK_SCIM_PRECONDITION'
            ? 'The SCIM resource version does not match'
            : 'The SCIM request could not be accepted',
  });
}
/** Copy only inert JSON data before any native schema accessor or parser can observe it. */
export function data(value: unknown, maximumBytes = 262144): unknown {
  let nodes = 0,
    bytes = 0;
  const seen = new Set<object>();
  const copy = (input: unknown, depth: number): unknown => {
    if (++nodes > 8192 || depth > 16) throw failure();
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) throw failure();
      return input;
    }
    if (typeof input === 'string') {
      bytes += Buffer.byteLength(input);
      if (bytes > maximumBytes || toUSVString(input) !== input) throw failure();
      return input;
    }
    if (!input || typeof input !== 'object' || types.isProxy(input) || seen.has(input))
      throw failure();
    seen.add(input);
    const array = Array.isArray(input);
    if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(input))) throw failure();
    const keys = Reflect.ownKeys(input);
    if (array && (input.length > 1000 || keys.length !== input.length + 1)) throw failure();
    const output: Record<string, unknown> | unknown[] = array ? [] : {};
    for (const key of keys) {
      if (array && key === 'length') continue;
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (
        typeof key !== 'string' ||
        /^(?:__proto__|constructor|prototype)$/i.test(key) ||
        !descriptor ||
        !('value' in descriptor) ||
        (array && !/^(?:0|[1-9][0-9]*)$/.test(key))
      )
        throw failure();
      bytes += Buffer.byteLength(key);
      if (bytes > maximumBytes || toUSVString(key) !== key) throw failure();
      Object.defineProperty(output, key, {
        value: copy(descriptor.value, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    seen.delete(input);
    return output;
  };
  return copy(value, 0);
}
export function object(value: unknown): Record<string, unknown> {
  const result = data(value);
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw failure();
  return result as Record<string, unknown>;
}
export function text(value: unknown, maximum = 4096): string {
  if (
    typeof value !== 'string' ||
    !value ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value ||
    [...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw failure();
  return value;
}
/** Structural limits precede the SDK grammar parser, including its disjunction expansion. */
export function expression(value: unknown, maximumDepth = 8): string {
  const selected = text(value),
    stack: string[] = [];
  let quoted = false,
    escaped = false,
    plain = '';
  for (const c of selected) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"') {
      quoted = true;
      plain += ' ';
      continue;
    }
    plain += c;
    if (c === '(' || c === '[') {
      stack.push(c);
      if (stack.length > maximumDepth) throw failure();
    }
    if (c === ')' || c === ']') {
      if (stack.pop() !== (c === ')' ? '(' : '[')) throw failure();
    }
  }
  if (
    quoted ||
    stack.length ||
    /\b(?:and|or|not)\s*[\])]*\s*$/i.test(plain) ||
    /\b(?:__proto__|constructor|prototype)\b/i.test(plain) ||
    (plain.match(/\bor\b/gi)?.length ?? 0) > 8 ||
    (plain.match(/\b(?:and|or)\b/gi)?.length ?? 0) > 32
  )
    throw failure();
  return selected;
}

/** Capture top-level trusted ports without evaluating caller accessors or copying identity provenance. */
export function fields(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure('EK_CONFIG_INVALID');
  const output: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== 'string' ||
      !allowed.includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure('EK_CONFIG_INVALID');
    output[key] = descriptor.value;
  }
  return output;
}
export function integer(value: unknown, maximum: number, minimum = 1): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum)
    throw failure('EK_CONFIG_INVALID');
  return value as number;
}
export function method<T>(input: unknown, name: string): T {
  if (!input || typeof input !== 'object' || types.isProxy(input))
    throw failure('EK_CONFIG_INVALID');
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw failure('EK_CONFIG_INVALID');
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      if (
        !('value' in descriptor) ||
        typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)
      )
        throw failure('EK_CONFIG_INVALID');
      return Function.prototype.bind.call(descriptor.value, input) as T;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw failure('EK_CONFIG_INVALID');
}
