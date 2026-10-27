// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString, types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { failure, integer, record } from './validation.js';
import type { JsonOptions } from './contracts.js';
export interface Limits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly indentSpaces: number;
}
export function options(input?: JsonOptions, defaults?: Limits): Limits {
  const value = input === undefined ? {} : record(input, ['maxBytes', 'maxDepth', 'indentSpaces']);
  return Object.freeze({
    maxBytes: integer(value.maxBytes, defaults?.maxBytes ?? 1048576, defaults?.maxBytes ?? 8388608),
    maxDepth: integer(value.maxDepth, defaults?.maxDepth ?? 64, defaults?.maxDepth ?? 128),
    indentSpaces: integer(value.indentSpaces, defaults?.indentSpaces ?? 0, 10, 0),
  });
}
/** Snapshot only JSON data; never invoke getters, proxies, toJSON or inherited properties. */
export function snapshot(
  input: unknown,
  limits: Limits,
  check: () => void = () => undefined,
): unknown {
  let nodes = 0,
    bytes = 0;
  const ancestors = new Set<object>();
  const add = (count: number) => {
    bytes += count;
    if (bytes > limits.maxBytes) throw failure('EK_JSON_PARSE');
  };
  const text = (value: string) => {
    if (value.length > limits.maxBytes || toUSVString(value) !== value)
      throw failure('EK_JSON_PARSE');
    add(Buffer.byteLength(JSON.stringify(value)));
  };
  function walk(value: unknown, depth: number): unknown {
    check();
    if (++nodes > 100000 || depth > limits.maxDepth) throw failure('EK_JSON_PARSE');
    if (value === null || typeof value === 'boolean') {
      add(JSON.stringify(value).length);
      return value;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))
        throw failure('EK_JSON_PARSE');
      add(JSON.stringify(value).length);
      return value;
    }
    if (typeof value === 'string') {
      text(value);
      return value;
    }
    if (
      !value ||
      typeof value !== 'object' ||
      types.isProxy(value) ||
      ancestors.has(value) ||
      (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    )
      throw failure('EK_JSON_PARSE');
    const array = Array.isArray(value);
    if (array && (Object.getPrototypeOf(value) !== Array.prototype || value.length > 100000))
      throw failure('EK_JSON_PARSE');
    const keys = Reflect.ownKeys(value);
    if (keys.length > 100001 || (array && keys.length !== value.length + 1))
      throw failure('EK_JSON_PARSE');
    ancestors.add(value);
    add(2);
    const output: unknown[] | Record<string, unknown> = array ? [] : Object.create(null);
    let index = 0;
    for (const key of keys) {
      if (array && key === 'length') continue;
      if (
        typeof key !== 'string' ||
        ['__proto__', 'prototype', 'constructor'].includes(key) ||
        (array && key !== String(index))
      )
        throw failure('EK_JSON_PARSE');
      const field = Object.getOwnPropertyDescriptor(value, key);
      if (!field || !('value' in field) || !field.enumerable) throw failure('EK_JSON_PARSE');
      if (index++) add(1);
      if (!array) {
        text(key);
        add(1);
      }
      Object.defineProperty(output, key, { value: walk(field.value, depth + 1), enumerable: true });
    }
    ancestors.delete(value);
    return Object.freeze(output);
  }
  return walk(input, 0);
}
export function parse(text: string, limits: Limits, check?: () => void): unknown {
  if (
    typeof text !== 'string' ||
    text.length > limits.maxBytes ||
    Buffer.byteLength(text) > limits.maxBytes ||
    toUSVString(text) !== text
  )
    throw failure('EK_JSON_PARSE');
  try {
    return snapshot(JSON.parse(text), limits, check);
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_JSON_PARSE');
  }
}
export function stringify(value: unknown, limits: Limits, check?: () => void): string {
  const clean = snapshot(value, limits, check);
  const result = JSON.stringify(clean, undefined, limits.indentSpaces);
  check?.();
  if (Buffer.byteLength(result) > limits.maxBytes) throw failure('EK_JSON_PARSE');
  return result;
}
