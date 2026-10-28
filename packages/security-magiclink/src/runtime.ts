// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within, instrumentOperation } from '@arkenivajs/core/support';
import type { Settings } from './settings.js';
import { failure, fields, integer } from './validation.js';
import { active, record } from './observation.js';
import type { Observers, Label } from './observation.js';

export interface Call {
  readonly signal: AbortSignal;
  check(): void;
  options(): OperationOptions;
  step<T>(work: (options: OperationOptions) => Promise<T>, mutation?: boolean): Promise<T>;
}
/** Public cancellation never releases a reservation still owned by an external provider. */
export class Calls {
  private readonly stop = new AbortController();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly signal: AbortSignal;
  private closed = false;
  private closing: Promise<void> | undefined;
  constructor(
    private readonly settings: Settings,
    owner: AbortSignal,
    private readonly ready: () => boolean,
    private readonly observers: Observers = {},
  ) {
    this.signal = AbortSignal.any([owner, this.stop.signal]);
  }
  async run<T>(
    input: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
    startup = false,
    label: Label = { operation: startup ? 'startup' : 'consume', purpose: 'none' },
  ): Promise<T> {
    const options = fields(input ?? {}, ['timeoutMs', 'signal']),
      timeout =
        options.timeoutMs === undefined
          ? this.settings.timeoutMs
          : integer(options.timeoutMs, this.settings.timeoutMs),
      caller = options.signal === undefined ? undefined : captureAbortSignal(options.signal);
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!startup && !this.ready()) throw failure('EK_LIFECYCLE_STATE');
    if (caller?.aborted) throw failure('EK_ABORTED');
    if (this.pending.size >= this.settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    const controller = new AbortController(),
      signal = AbortSignal.any([this.signal, controller.signal, ...(caller ? [caller] : [])]),
      started = performance.now(),
      deadline = started + timeout,
      correlationId = randomUUID();
    let submitted = false;
    const check = () => {
      if (signal.aborted) throw failure('EK_ABORTED');
      if (performance.now() >= deadline) throw failure('EK_TIMEOUT');
    };
    const remaining = (): OperationOptions => {
      check();
      return { signal, timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())) };
    };
    const task = Promise.resolve()
      .then(() =>
        instrumentOperation(
          this.observers.telemetry,
          'magiclink.' + label.operation,
          { 'magiclink.operation': label.operation, 'magiclink.intent': label.purpose },
          () =>
            work({
              signal,
              check,
              options: remaining,
              async step(fn, mutation = false) {
                const request = remaining();
                submitted ||= mutation;
                try {
                  const result = await fn(request);
                  check();
                  return result;
                } catch {
                  check();
                  throw failure('EK_BACKEND_UNAVAILABLE', submitted);
                }
              },
            }),
          () => undefined,
        ),
      )
      .then((result) => {
        check();
        return result;
      });
    this.pending.add(task);
    active(this.observers, this.pending.size);
    const release = () => {
      this.pending.delete(task);
      active(this.observers, this.pending.size);
    };
    void task.then(release, release);
    let outcome: string | undefined;
    try {
      return await within(() => task, { signal, timeoutMs: timeout });
    } catch (error) {
      const allowed: readonly ErrorCode[] = [
        'EK_CONFIG_INVALID',
        'EK_MAGICLINK_INVALID',
        'EK_MAGICLINK_EXPIRED',
        'EK_MAGICLINK_REPLAY',
        'EK_BACKEND_UNAVAILABLE',
        'EK_RESOURCE_CLOSED',
        'EK_LIFECYCLE_STATE',
        'EK_TIMEOUT',
        'EK_ABORTED',
      ];
      const code =
        error instanceof KitError && allowed.includes(error.code)
          ? error.code
          : 'EK_BACKEND_UNAVAILABLE';
      outcome = code;
      throw failure(
        code,
        submitted &&
          ['EK_BACKEND_UNAVAILABLE', 'EK_TIMEOUT', 'EK_ABORTED', 'EK_RESOURCE_CLOSED'].includes(
            code,
          ),
      );
    } finally {
      controller.abort();
      record(this.observers, label, outcome, performance.now() - started, correlationId);
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    this.closing = within(() => Promise.allSettled([...this.pending]).then(() => undefined), {
      timeoutMs: this.settings.timeoutMs,
    });
    return this.closing;
  }
}
