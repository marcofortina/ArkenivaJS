// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { parseError } from './certificate.js';
import type { Settings } from './settings.js';

export const failure = (code: ErrorCode = 'EK_MTLS_INVALID_PEER') =>
  new KitError({ code, message: 'The mutual TLS operation could not complete safely' });
export const invalid = () => failure('EK_MTLS_CONFIGURATION');
export interface Call {
  readonly options: OperationOptions;
  check(): void;
}
/** Capture exact data properties without invoking accessors or caller serialization hooks. */
export function data(value: unknown, names: readonly string[]): Record<string, unknown> {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw parseError();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== 'string' || !names.includes(key)) throw parseError();
      const field = descriptors[key]!;
      if (!('value' in field)) throw parseError();
      result[key] = field.value;
    }
    return result;
  } catch {
    throw parseError();
  }
}
export function list(value: unknown, maximum: number, minimum = 0): unknown[] {
  try {
    if (!Array.isArray(value)) throw parseError();
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value as unknown;
    if (
      !Number.isSafeInteger(length) ||
      (length as number) < minimum ||
      (length as number) > maximum
    )
      throw parseError();
    const result: unknown[] = [];
    const fields = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(fields).length !== (length as number) + 1) throw parseError();
    for (let index = 0; index < (length as number); index++) {
      const field = fields[String(index)];
      if (!field || !('value' in field)) throw parseError();
      result.push(field.value);
    }
    return result;
  } catch {
    throw parseError();
  }
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw invalid();
  return value as number;
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
/** A provider that ignores cancellation keeps its admission slot until it actually settles. */
export function createRuntime(settings: Settings) {
  const shutdown = new AbortController(),
    active = new Set<AbortController>();
  let closed = false;
  const checkOpen = () => {
    if (closed) throw failure('EK_RESOURCE_CLOSED');
  };
  async function run<T>(
    input: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
    discard?: (value: T) => void,
  ): Promise<T> {
    checkOpen();
    let options: OperationOptions;
    try {
      options = data(input === undefined ? {} : input, ['signal', 'timeoutMs']) as OperationOptions;
    } catch {
      throw invalid();
    }
    const timeoutMs =
      options.timeoutMs === undefined
        ? settings.timeoutMs
        : integer(options.timeoutMs, settings.timeoutMs);
    if (options.signal !== undefined) signal(options.signal);
    if (options.signal?.aborted) throw failure('EK_ABORTED');
    if (active.size >= settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    const controller = new AbortController();
    const combined = AbortSignal.any([
      shutdown.signal,
      controller.signal,
      ...(options.signal ? [options.signal] : []),
    ]);
    const deadline = performance.now() + timeoutMs;
    const check = () => {
      checkOpen();
      if (combined.aborted) throw failure('EK_ABORTED');
      if (performance.now() >= deadline) throw failure('EK_TIMEOUT');
    };
    active.add(controller);
    const task = Promise.resolve().then(async () => {
      try {
        check();
        const result = await work({
          options: Object.freeze({ signal: combined, timeoutMs }),
          check,
        });
        try {
          check();
          return result;
        } catch (error) {
          discard?.(result);
          throw error;
        }
      } finally {
        active.delete(controller);
      }
    });
    // Observe owned work even if the public wait expires before invoking its factory.
    void task.catch(() => undefined);
    try {
      return await within(() => task, { signal: combined, timeoutMs });
    } catch (error) {
      if (error instanceof KitError) throw failure(error.code);
      throw failure();
    } finally {
      controller.abort();
    }
  }
  return {
    run,
    checkOpen,
    bootstrap(applicationSignal: AbortSignal) {
      checkOpen();
      signal(applicationSignal);
      if (applicationSignal.aborted) throw failure('EK_ABORTED');
    },
    close() {
      if (!closed) {
        closed = true;
        shutdown.abort();
      }
    },
  };
}
