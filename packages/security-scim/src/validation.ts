// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';

export function failure(code: ErrorCode = 'EK_SCIM_BAD_REQUEST'): KitError {
  return new KitError({
    code,
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
    /\b(?:__proto__|constructor|prototype)\b/i.test(plain) ||
    (plain.match(/\bor\b/gi)?.length ?? 0) > 8 ||
    (plain.match(/\b(?:and|or)\b/gi)?.length ?? 0) > 32
  )
    throw failure();
  return selected;
}
