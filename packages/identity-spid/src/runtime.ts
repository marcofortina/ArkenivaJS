// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import type { BoundedRuntimePolicy } from './contracts.js';
import { failure, fields, integer } from './validation.js';

/** A public deadline never releases capacity still owned by provider or native work. */
export class FederationCall {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly completion: Promise<void>;
  private readonly began = performance.now();
  private readonly pending = new Set<Promise<unknown>>();
  private resolve!: () => void;
  private finished = false;
  private released = false;
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
  check() {
    if (this.signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() - this.began >= this.timeoutMs) throw failure('EK_TIMEOUT');
  }
  options(): Required<OperationOptions> {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(1, Math.ceil(this.timeoutMs - (performance.now() - this.began))),
    };
  }
  track = (task: Promise<unknown>): void => {
    if (this.pending.has(task)) return;
    this.pending.add(task);
    const settle = () => {
      this.pending.delete(task);
      this.tryRelease();
    };
    void task.then(settle, settle);
  };
  async step<T>(work: (options: Required<OperationOptions>) => Promise<T>): Promise<T> {
    this.check();
    const actual = Promise.resolve().then(() => work(this.options()));
    this.track(actual);
    try {
      const result = await within(() => actual, this.options());
      this.check();
      return result;
    } catch (error) {
      if (
        error instanceof KitError &&
        [
          'EK_TIMEOUT',
          'EK_ABORTED',
          'EK_BACKEND_UNAVAILABLE',
          'EK_RESOURCE_CLOSED',
          'EK_LIFECYCLE_STATE',
          'EK_EID_PROFILE',
          'EK_EID_FEDERATION',
          'EK_EID_ASSURANCE',
        ].includes(error.code)
      )
        throw failure(error.code);
      throw failure('EK_EID_FEDERATION');
    }
  }
  finish() {
    this.finished = true;
    this.controller.abort();
    this.tryRelease();
  }
  private tryRelease() {
    if (this.finished && !this.pending.size && !this.released) {
      this.released = true;
      this.release();
      this.resolve();
    }
  }
}
/** One application-local admission pool, with no implicit waiting queue or readiness bypass. */
export class FederationRuntime {
  private readonly calls = new Set<FederationCall>();
  private readonly stop = new AbortController();
  private readonly capacity: number;
  private readonly timeout: number;
  private readonly detach: () => void;
  private closing: Promise<void> | undefined;
  private closed = false;
  constructor(
    policy: BoundedRuntimePolicy,
    private readonly ready: () => boolean = () => true,
    owner?: AbortSignal,
  ) {
    const value = fields(policy, ['maxConcurrent', 'timeoutMs', 'maxInputBytes', 'maxOutputBytes']);
    this.capacity = integer(value.maxConcurrent);
    this.timeout = integer(value.timeoutMs);
    const signal = owner === undefined ? undefined : captureAbortSignal(owner);
    const abort = () => {
      this.closed = true;
      this.stop.abort();
    };
    signal?.addEventListener('abort', abort, { once: true });
    this.detach = () => signal?.removeEventListener('abort', abort);
    if (signal?.aborted) abort();
  }
  private options(input?: OperationOptions) {
    const value = fields(input ?? {}, ['signal', 'timeoutMs']);
    return {
      timeoutMs:
        value.timeoutMs === undefined
          ? this.timeout
          : Math.min(this.timeout, integer(value.timeoutMs)),
      ...(value.signal === undefined ? {} : { signal: captureAbortSignal(value.signal) }),
    };
  }
  async run<T>(
    work: (call: FederationCall) => Promise<T>,
    input?: OperationOptions,
    bootstrap = false,
  ): Promise<T> {
    const options = this.options(input);
    if (this.closed) throw failure('EK_RESOURCE_CLOSED');
    if (!bootstrap && !this.ready()) throw failure('EK_LIFECYCLE_STATE');
    if (this.calls.size >= this.capacity) throw failure('EK_BACKEND_UNAVAILABLE');
    const call: FederationCall = new FederationCall(
      options.timeoutMs,
      [this.stop.signal, ...(options.signal ? [options.signal] : [])],
      () => this.calls.delete(call),
    );
    this.calls.add(call);
    try {
      return await call.step(() => work(call));
    } finally {
      call.finish();
    }
  }
  stats() {
    return Object.freeze({ active: this.calls.size, closed: this.closed });
  }
  close(input?: OperationOptions): Promise<void> {
    if (this.closing) return this.closing;
    const options = this.options(input);
    this.closed = true;
    this.stop.abort();
    this.detach();
    return (this.closing = within(
      () => Promise.all([...this.calls].map((call) => call.completion)).then(() => undefined),
      options,
    ));
  }
}
