// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { fields, integer, failure } from './validation.js';
import type { Settings } from './settings.js';

export class Call {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly deadline: number;
  sideEffectAttempted = false;
  constructor(owner: AbortSignal, options: OperationOptions | undefined, settings: Settings) {
    const value = fields(options === undefined ? {} : options, ['signal', 'timeoutMs']);
    const timeout =
      value.timeoutMs === undefined
        ? settings.timeoutMs
        : integer(value.timeoutMs, settings.timeoutMs);
    this.signal = AbortSignal.any([
      owner,
      this.controller.signal,
      ...(value.signal === undefined ? [] : [captureAbortSignal(value.signal)]),
    ]);
    this.deadline = performance.now() + timeout;
    this.check();
  }
  check(): void {
    if (this.signal.aborted) throw failure('EK_ABORTED', this.sideEffectAttempted);
    if (performance.now() >= this.deadline) throw failure('EK_TIMEOUT', this.sideEffectAttempted);
  }
  options(): OperationOptions {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(1, Math.ceil(this.deadline - performance.now())),
    };
  }
}
export function runtime(
  settings: Settings,
  owner: AbortSignal,
  ready: () => boolean,
  requestSignal: () => AbortSignal | undefined,
) {
  const stop = new AbortController(),
    signal = AbortSignal.any([owner, stop.signal]),
    pending = new Set<Promise<unknown>>();
  let closed = false;
  const check = () => {
    if (closed || signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!ready()) throw failure('EK_LIFECYCLE_STATE');
  };
  return {
    check,
    async run<T>(
      options: OperationOptions | undefined,
      work: (call: Call) => Promise<T>,
    ): Promise<T> {
      check();
      const request = requestSignal(),
        call = new Call(request ? AbortSignal.any([signal, request]) : signal, options, settings);
      if (pending.size >= settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
      const task = Promise.resolve().then(async () => {
        call.check();
        const value = await work(call);
        call.check();
        return value;
      });
      pending.add(task);
      void task.then(
        () => pending.delete(task),
        () => pending.delete(task),
      );
      try {
        return await within(() => task, call.options());
      } catch (cause) {
        let code: ErrorCode = 'EK_HTTP_CSRF';
        try {
          if (cause instanceof KitError) code = cause.code;
        } catch {
          /* Provider exceptions carry no safe diagnostics. */
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
  };
}
