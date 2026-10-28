// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import { fields, integer, failure } from './validation.js';

export const defaultTimeout = 10000,
  maximumTimeout = 30000;
const codes = new Set<string>([
  'EK_CONFIG_INVALID',
  'EK_LIFECYCLE_STATE',
  'EK_RESOURCE_CLOSED',
  'EK_ABORTED',
  'EK_TIMEOUT',
  'EK_KAFKA_CONFIG',
  'EK_KAFKA_CONNECT',
  'EK_KAFKA_PUBLISH',
  'EK_KAFKA_CONSUME',
  'EK_KAFKA_OFFSET',
  'EK_KAFKA_REBALANCE',
]);
function publicCode(error: unknown, fallback: ErrorCode): ErrorCode {
  if (!error || typeof error !== 'object' || types.isProxy(error)) return fallback;
  const value: unknown = Object.getOwnPropertyDescriptor(error, 'code')?.value;
  return typeof value === 'string' && codes.has(value) ? (value as ErrorCode) : fallback;
}
export function operation(input: OperationOptions | undefined) {
  try {
    const value = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']);
    const signal = value.signal === undefined ? undefined : captureAbortSignal(value.signal);
    return {
      ...(signal === undefined ? {} : { signal }),
      timeoutMs: integer(
        value.timeoutMs === undefined ? defaultTimeout : value.timeoutMs,
        maximumTimeout,
      ),
    };
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
/** Cancellation does not release admission until provider and native work actually settle. */
export class Task<T> {
  readonly controller = new AbortController();
  readonly done: Promise<void>;
  readonly result: Promise<T>;
  readonly #deadline: number;
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #signals: readonly AbortSignal[];
  readonly #abort = () => this.stop('EK_ABORTED');
  #error: KitError | undefined;
  #reject!: (error: KitError) => void;
  #value: T | undefined;
  submitted = false;
  constructor(
    requested: OperationOptions | undefined,
    application: AbortSignal,
    readonly interrupt: () => void,
    work: (task: Task<T>) => Promise<T>,
    readonly errorCode: ErrorCode = 'EK_KAFKA_CONNECT',
  ) {
    const config = operation(requested);
    this.#deadline = performance.now() + config.timeoutMs;
    this.#signals = [...new Set([application, ...(config.signal ? [config.signal] : [])])];
    const aborted = new Promise<never>((_resolve, reject) => {
      this.#reject = reject;
    });
    void aborted.catch(() => undefined);
    this.#timer = setTimeout(() => this.stop('EK_TIMEOUT'), config.timeoutMs);
    for (const signal of this.#signals)
      signal.addEventListener('abort', this.#abort, { once: true });
    if (this.#signals.some((signal) => signal.aborted)) this.stop('EK_ABORTED');
    this.done = Promise.resolve()
      .then(async () => {
        try {
          this.#value = await work(this);
          this.check();
        } catch (error) {
          this.#error ??= failure(publicCode(error, this.errorCode), this.submitted);
        }
      })
      .finally(() => {
        clearTimeout(this.#timer);
        for (const signal of this.#signals) signal.removeEventListener('abort', this.#abort);
      });
    this.result = Promise.race([
      this.done.then(() => {
        this.check();
        return this.#value as T;
      }),
      aborted,
    ]);
    void this.result.catch(() => undefined);
  }
  check(): void {
    if (this.#error) throw this.#error;
    if (performance.now() >= this.#deadline) {
      this.stop('EK_TIMEOUT');
      throw this.#error;
    }
  }
  stop(code: ErrorCode): void {
    this.#error ??= failure(code, this.submitted);
    this.controller.abort();
    try {
      this.interrupt();
    } catch {
      /* Cancellation cannot lose the original outcome. */
    }
    this.#reject(this.#error);
  }
  async wait<V>(promise: Promise<V>): Promise<V> {
    const value = await promise;
    this.check();
    return value;
  }
  remaining(): number {
    this.check();
    return Math.max(1, Math.ceil(this.#deadline - performance.now()));
  }
}
