// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, SqlProvider } from '@arkenivajs/core';
import { freezeData, within } from '@arkenivajs/core/support';

export const invalid = () =>
  new KitError({
    code: 'EK_CONFIG_INVALID',
    message: 'Invalid transactional security storage input',
  });
export const unavailable = (outcomeUnknown: boolean) =>
  new KitError({
    code: 'EK_DATABASE_UNAVAILABLE',
    message: 'Transactional security storage is unavailable',
    ...(outcomeUnknown ? { details: { outcome: 'unknown' } } : {}),
  });
export class Conflict extends Error {}

/** Snapshot the trusted injected SQL methods without invoking configuration accessors. */
export function captureSql(
  input: SqlProvider,
): Pick<SqlProvider, 'query' | 'queryOne' | 'execute' | 'transaction'> {
  try {
    if (!input || typeof input !== 'object') throw invalid();
    const method = (name: string) => {
      let current: object | null = input;
      while (current) {
        const field = Object.getOwnPropertyDescriptor(current, name);
        if (field) {
          if (!('value' in field) || typeof field.value !== 'function') throw invalid();
          return field.value.bind(input) as unknown;
        }
        current = Object.getPrototypeOf(current) as object | null;
      }
      throw invalid();
    };
    return Object.freeze({
      query: method('query') as SqlProvider['query'],
      queryOne: method('queryOne') as SqlProvider['queryOne'],
      execute: method('execute') as SqlProvider['execute'],
      transaction: method('transaction') as SqlProvider['transaction'],
    });
  } catch {
    throw invalid();
  }
}

export function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || !fields.includes(key)) throw invalid();
      const field = Object.getOwnPropertyDescriptor(value, key);
      if (!field || !('value' in field)) throw invalid();
      result[key] = field.value;
    }
    return result;
  } catch {
    throw invalid();
  }
}
export function reference(value: unknown, maximum = 256): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > maximum ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  )
    throw invalid();
}
export function owner(value: unknown): asserts value is string {
  reference(value);
  if (value.length < 16) throw invalid();
}
export function version(value: unknown): asserts value is string | null {
  if (
    value !== null &&
    (typeof value !== 'string' ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value))
  )
    throw invalid();
}
export function instant(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length !== 24 ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw invalid();
  return value;
}
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw invalid();
  return value as number;
}
/** Bounded lossless JSON subset; accessors, undefined, bigint, holes and prototypes are rejected. */
export function fields(value: unknown): Readonly<Record<string, unknown>> {
  let nodes = 0;
  const visit = (input: unknown, depth: number): unknown => {
    if (++nodes > 1024 || depth > 16) throw invalid();
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'string') {
      if (
        input.length > 32768 ||
        Buffer.byteLength(input) > 32768 ||
        input.includes('\u0000') ||
        Buffer.from(input).toString() !== input
      )
        throw invalid();
      return input;
    }
    if (typeof input === 'number') {
      if (!Number.isFinite(input) || Object.is(input, -0)) throw invalid();
      return input;
    }
    if (!input || typeof input !== 'object') throw invalid();
    if (Array.isArray(input)) {
      if (input.length > 256 || Reflect.ownKeys(input).length !== input.length + 1) throw invalid();
      return Array.from({ length: input.length }, (_, index) => {
        const field = Object.getOwnPropertyDescriptor(input, String(index));
        if (!field || !('value' in field)) throw invalid();
        return visit(field.value, depth + 1);
      });
    }
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) throw invalid();
    const keys = Reflect.ownKeys(input);
    if (keys.length > 64) throw invalid();
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (
        typeof key !== 'string' ||
        key.length > 256 ||
        key.includes('\u0000') ||
        Buffer.from(key).toString() !== key ||
        ['__proto__', 'prototype', 'constructor'].includes(key)
      )
        throw invalid();
      const field = Object.getOwnPropertyDescriptor(input, key);
      if (!field || !('value' in field)) throw invalid();
      result[key] = visit(field.value, depth + 1);
    }
    return result;
  };
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
    const result = visit(value, 0) as Record<string, unknown>;
    if (Buffer.byteLength(JSON.stringify(result)) > 32768 || Object.hasOwn(result, 'version'))
      throw invalid();
    return freezeData(result);
  } catch {
    throw invalid();
  }
}
export function table(schema: string, suffix: 'records' | 'claims' | 'epochs'): string {
  if (
    process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1' ||
    typeof schema !== 'string' ||
    !/^security_[a-f0-9]{24}$/.test(schema)
  )
    throw invalid();
  return schema + '.security_' + suffix;
}
function signal(value: unknown): asserts value is AbortSignal {
  try {
    if (!(value instanceof AbortSignal)) throw invalid();
    let current: object | null = value;
    while (current !== AbortSignal.prototype) {
      if (!current) throw invalid();
      for (const key of ['aborted', 'reason', 'addEventListener', 'removeEventListener'])
        if (Object.getOwnPropertyDescriptor(current, key)) throw invalid();
      current = Object.getPrototypeOf(current) as object | null;
    }
    Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value);
  } catch {
    throw invalid();
  }
}
/** No hidden queue; a backend that ignores cancellation retains its permit until it settles. */
export function runtime() {
  let active = 0;
  return async <T>(
    input: OperationOptions | undefined,
    write: boolean,
    work: (options: OperationOptions) => Promise<T>,
  ): Promise<T> => {
    const options = object(input === undefined ? {} : input, ['signal', 'timeoutMs']),
      timeoutMs = options.timeoutMs === undefined ? 5000 : integer(options.timeoutMs, 5000);
    if (options.signal !== undefined) signal(options.signal);
    const controller = new AbortController(),
      combined = AbortSignal.any([
        controller.signal,
        ...(options.signal ? [options.signal as AbortSignal] : []),
      ]);
    if (combined.aborted)
      throw new KitError({ code: 'EK_ABORTED', message: 'Security storage operation was aborted' });
    if (active >= 16)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Security storage admission is exhausted',
      });
    const deadline = performance.now() + timeoutMs;
    active++;
    const task = Promise.resolve().then(async () => {
      try {
        if (combined.aborted)
          throw new KitError({
            code: 'EK_ABORTED',
            message: 'Security storage operation was aborted',
          });
        if (performance.now() >= deadline)
          throw new KitError({
            code: 'EK_TIMEOUT',
            message: 'Security storage operation timed out',
          });
        const result = await work({ signal: combined, timeoutMs });
        if (combined.aborted)
          throw new KitError({
            code: 'EK_ABORTED',
            message: 'Security storage operation was aborted',
          });
        if (performance.now() >= deadline)
          throw new KitError({
            code: 'EK_TIMEOUT',
            message: 'Security storage operation timed out',
          });
        return result;
      } finally {
        active--;
      }
    });
    try {
      return await within(() => task, { signal: combined, timeoutMs });
    } catch (error) {
      if (error instanceof Conflict) throw error;
      if (error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code))
        throw new KitError({
          code: error.code,
          message: 'Security storage operation was interrupted',
          ...(write ? { details: { outcome: 'unknown' } } : {}),
        });
      throw unavailable(write);
    } finally {
      controller.abort();
    }
  };
}
