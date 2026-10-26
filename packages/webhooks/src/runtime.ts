// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { fields, integer, failure } from './validation.js';
import type { Settings } from './settings.js';

/** A request reservation outlives an expired public waiter until its provider/transport work settles. */
export class Call {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly started = performance.now();
  sideEffectAttempted = false;
  constructor(owner: AbortSignal, input: OperationOptions | undefined, settings: Settings) {
    const value = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']);
    const timeout =
      value.timeoutMs === undefined
        ? settings.timeoutMs
        : integer(value.timeoutMs, settings.timeoutMs);
    this.signal = AbortSignal.any([
      owner,
      this.controller.signal,
      ...(value.signal === undefined ? [] : [captureAbortSignal(value.signal)]),
    ]);
    this.deadline = this.started + timeout;
    this.check();
  }
  check(): void {
    if (this.signal.aborted) throw failure('EK_ABORTED', this.sideEffectAttempted);
    if (performance.now() >= this.deadline) throw failure('EK_TIMEOUT', this.sideEffectAttempted);
  }
  options(maximum?: number): OperationOptions {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(
        1,
        Math.min(maximum ?? 120000, Math.ceil(this.deadline - performance.now())),
      ),
    };
  }
}
export function runtime(
  settings: Settings,
  owner: AbortSignal,
  ready: () => boolean,
  retained: () => number,
) {
  const stop = new AbortController(),
    signal = AbortSignal.any([owner, stop.signal]),
    pending = new Set<Promise<unknown>>();
  let closed = false;
  return {
    async run<T>(
      options: OperationOptions | undefined,
      work: (call: Call) => Promise<T>,
    ): Promise<T> {
      if (closed) throw failure('EK_RESOURCE_CLOSED');
      if (!ready()) throw failure('EK_LIFECYCLE_STATE');
      const call = new Call(signal, options, settings);
      if (pending.size + retained() >= settings.maxConcurrent)
        throw failure('EK_BACKEND_UNAVAILABLE');
      const task = Promise.resolve().then(async () => {
        call.check();
        const result = await work(call);
        call.check();
        return result;
      });
      pending.add(task);
      void task.then(
        () => pending.delete(task),
        () => pending.delete(task),
      );
      try {
        return await within(() => task, call.options());
      } catch (cause) {
        let code: import('@arkenivajs/core').ErrorCode = 'EK_WEBHOOK_DELIVERY';
        try {
          if (cause instanceof KitError) code = cause.code;
        } catch {
          /* Provider exceptions are not diagnostic data. */
        }
        throw failure(code, call.sideEffectAttempted);
      } finally {
        call.controller.abort();
      }
    },
    async close(): Promise<void> {
      closed = true;
      stop.abort();
      await Promise.allSettled([...pending]);
    },
    check(): void {
      if (closed || signal.aborted) throw failure('EK_RESOURCE_CLOSED');
      if (!ready()) throw failure('EK_LIFECYCLE_STATE');
    },
  };
}
