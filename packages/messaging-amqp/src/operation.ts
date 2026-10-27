// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { fields, integer, failure } from './validation.js';

export const defaultTimeout = 10000,
  maximumTimeout = 30000;
export function operation(input: OperationOptions | undefined) {
  try {
    const value = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']);
    if (value.signal !== undefined) {
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value.signal);
      if (!(value.signal instanceof AbortSignal)) throw failure();
      let current: object | null = value.signal;
      while (current !== AbortSignal.prototype) {
        if (
          !current ||
          ['aborted', 'reason', 'addEventListener', 'removeEventListener'].some((name) =>
            Object.hasOwn(current!, name),
          )
        )
          throw failure();
        current = Object.getPrototypeOf(current) as object | null;
      }
    }
    return {
      signal: value.signal as AbortSignal | undefined,
      timeoutMs: integer(value.timeoutMs ?? defaultTimeout, maximumTimeout),
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
    readonly unknownOutcome?: () => T,
    readonly errorCode: ErrorCode = 'EK_AMQP_CONNECT',
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
          this.#error ??= failure(
            error instanceof KitError ? error.code : this.errorCode,
            this.submitted,
          );
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
    ]).catch((error: unknown) => {
      if (
        this.submitted &&
        this.unknownOutcome &&
        error instanceof KitError &&
        ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code)
      )
        return this.unknownOutcome();
      throw error;
    });
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
    this.interrupt();
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
