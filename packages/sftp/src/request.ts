// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { fields, integer, failure } from './validation.js';

export function operation(input: OperationOptions | undefined, maximum: number) {
  const value = fields(input ?? {}, ['signal', 'timeoutMs']);
  if (value.signal !== undefined) {
    try {
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value.signal);
    } catch {
      throw failure('EK_CONFIG_INVALID');
    }
    if (!(value.signal instanceof AbortSignal)) throw failure('EK_CONFIG_INVALID');
    let current: object | null = value.signal;
    while (current !== AbortSignal.prototype) {
      if (
        !current ||
        ['aborted', 'reason', 'addEventListener', 'removeEventListener'].some((key) =>
          Object.hasOwn(current!, key),
        )
      )
        throw failure('EK_CONFIG_INVALID');
      current = Object.getPrototypeOf(current) as object | null;
    }
  }
  try {
    return {
      signal: value.signal as AbortSignal | undefined,
      timeoutMs: integer(value.timeoutMs ?? maximum, maximum),
    };
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}

/** Public cancellation is immediate; admission remains held until all owned work actually settles. */
export class Request<T> {
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
    maximum: number,
    options: OperationOptions | undefined,
    applicationSignal: AbortSignal,
    readonly interrupt: () => void,
    work: (request: Request<T>) => Promise<T>,
  ) {
    const configured = operation(options, maximum);
    this.#deadline = performance.now() + configured.timeoutMs;
    this.#signals = [
      ...new Set([applicationSignal, ...(configured.signal ? [configured.signal] : [])]),
    ];
    const aborted = new Promise<never>((_resolve, reject) => {
      this.#reject = reject;
    });
    void aborted.catch(() => undefined);
    this.#timer = setTimeout(() => this.stop('EK_TIMEOUT'), configured.timeoutMs);
    for (const signal of this.#signals)
      signal.addEventListener('abort', this.#abort, { once: true });
    if (this.#signals.some((signal) => signal.aborted)) this.stop('EK_ABORTED');
    this.done = Promise.resolve()
      .then(async () => {
        try {
          this.check();
          this.#value = await work(this);
          this.check();
        } catch (error) {
          this.#error ??= failure(
            error instanceof KitError ? error.code : 'EK_SFTP_TRANSFER',
            this.submitted,
          );
          this.interrupt();
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
    this.interrupt();
    this.#reject(this.#error);
  }
  async wait<V>(work: Promise<V>): Promise<V> {
    // The argument has already started; retain ownership even if it aborts synchronously.
    const result = await work;
    this.check();
    return result;
  }
  remaining(): number {
    this.check();
    return Math.max(1, Math.ceil(this.#deadline - performance.now()));
  }
}
