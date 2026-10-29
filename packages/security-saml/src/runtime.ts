// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, ErrorCode } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { fields, failure, integer } from './validation.js';

export class Call {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly pending = new Set<Promise<unknown>>();
  readonly started = performance.now();
  readonly completion: Promise<void>;
  private resolve!: () => void;
  private finished = false;
  private released = false;
  private mutationStarted = false;
  get outcomeMayBeUnknown(): boolean {
    return this.mutationStarted;
  }
  constructor(
    readonly timeoutMs: number,
    signals: readonly AbortSignal[],
    private readonly release: () => void,
  ) {
    this.signal = AbortSignal.any([this.controller.signal, ...signals]);
    this.completion = new Promise((resolve) => {
      this.resolve = resolve;
    });
  }
  check(): void {
    if (this.signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() - this.started >= this.timeoutMs) throw failure('EK_TIMEOUT');
  }
  options(): Required<OperationOptions> {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(1, Math.ceil(this.timeoutMs - (performance.now() - this.started))),
    };
  }
  watch<T>(task: Promise<T>): Promise<T> {
    this.pending.add(task);
    const settle = () => {
      this.pending.delete(task);
      this.tryRelease();
    };
    void task.then(settle, settle);
    return task;
  }
  async step<T>(
    code: ErrorCode,
    work: (options: Required<OperationOptions>) => Promise<T>,
  ): Promise<T> {
    const options = this.options();
    const actual = this.watch(
      Promise.resolve().then(() => {
        this.check();
        return work(options);
      }),
    );
    try {
      const result = await within(() => actual, options);
      this.check();
      return result;
    } catch (error) {
      if (error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code))
        throw failure(error.code);
      if (
        error instanceof KitError &&
        [
          'EK_SAML_SIGNATURE',
          'EK_SAML_ASSERTION',
          'EK_SAML_REPLAY',
          'EK_SAML_CONFIGURATION',
        ].includes(error.code)
      )
        throw failure(error.code);
      throw failure(code);
    }
  }
  /** A deadline cannot promise rollback once a shared atomic mutation has been dispatched. */
  mutate<T>(work: (options: Required<OperationOptions>) => Promise<T>): Promise<T> {
    return this.step('EK_BACKEND_UNAVAILABLE', (options) => {
      this.mutationStarted = true;
      return work(options);
    });
  }
  finish(): void {
    this.finished = true;
    this.controller.abort();
    this.tryRelease();
  }
  private tryRelease(): void {
    if (this.released || !this.finished || this.pending.size) return;
    this.released = true;
    this.release();
    this.resolve();
  }
}
/** Public deadlines do not free capacity while a provider or native worker is still active. */
export class Runtime {
  private readonly calls = new Set<Call>();
  private readonly stop = new AbortController();
  private closing: Promise<void> | undefined;
  constructor(
    private readonly ready: () => boolean = () => true,
    private readonly owner?: AbortSignal,
    private readonly capacity: (count: number) => void = () => {},
  ) {}
  async run<T>(
    input: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
    bootstrap = false,
  ): Promise<T> {
    const options = fields(input ?? {}, ['signal', 'timeoutMs']),
      timeoutMs = integer(options.timeoutMs ?? 5000, 30000),
      signal = options.signal === undefined ? undefined : captureAbortSignal(options.signal);
    if (signal?.aborted) throw failure('EK_ABORTED');
    if (this.stop.signal.aborted || this.owner?.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!bootstrap && !this.ready()) throw failure('EK_LIFECYCLE_STATE');
    if (this.calls.size >= 8) throw failure('EK_BACKEND_UNAVAILABLE');
    const call = new Call(
      timeoutMs,
      [this.stop.signal, ...(signal ? [signal] : []), ...(this.owner ? [this.owner] : [])],
      () => {
        this.calls.delete(call);
        this.capacity(this.calls.size);
      },
    );
    this.calls.add(call);
    this.capacity(this.calls.size);
    const actual = call.watch(
      Promise.resolve().then(() => {
        call.check();
        return work(call);
      }),
    );
    try {
      return await within(() => actual, { timeoutMs, signal: call.signal });
    } catch (error) {
      if (error instanceof KitError)
        throw failure(
          error.code,
          call.outcomeMayBeUnknown &&
            ['EK_ABORTED', 'EK_TIMEOUT', 'EK_BACKEND_UNAVAILABLE'].includes(error.code),
        );
      throw failure('EK_BACKEND_UNAVAILABLE');
    } finally {
      call.finish();
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    const completion = this.drain();
    return (this.closing = within(() => completion, { timeoutMs: 5000 }));
  }
  /** Stop admission and retain actual settlement beyond a bounded caller's close deadline. */
  drain(): Promise<void> {
    this.stop.abort();
    return Promise.all([...this.calls].map((call) => call.completion)).then(() => undefined);
  }
}
