// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within, instrumentOperation } from '@arkenivajs/core/support';
import { record } from './observation.js';
import type { Observers, Operation } from './observation.js';
import { operation } from './settings.js';
import type { Settings } from './settings.js';
import { failure } from './validation.js';

export class Call {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly started = performance.now();
  readonly id = randomUUID();
  inputBytes = 0;
  outputBytes = 0;
  submitted = false;
  constructor(
    input: OperationOptions | undefined,
    timeout: number,
    owners: readonly AbortSignal[],
  ) {
    const options = operation(input, timeout);
    this.signal = AbortSignal.any([
      ...owners,
      this.controller.signal,
      ...(options.signal ? [options.signal] : []),
    ]);
    this.deadline = this.started + options.timeoutMs!;
    this.check();
  }
  check(): void {
    if (this.signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() >= this.deadline) throw failure('EK_TIMEOUT');
  }
  options(): OperationOptions {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(1, Math.ceil(this.deadline - performance.now())),
    };
  }
}
const safeCodes: readonly ErrorCode[] = [
  'EK_ABORTED',
  'EK_TIMEOUT',
  'EK_RESOURCE_CLOSED',
  'EK_CONFIG_INVALID',
  'EK_LIFECYCLE_STATE',
  'EK_BACKEND_UNAVAILABLE',
  'EK_SOAP_WSDL',
  'EK_SOAP_SCHEMA',
  'EK_SOAP_FAULT',
  'EK_UNSUPPORTED_CAPABILITY',
];
export function safeFailure(error: unknown, call?: Call): KitError {
  const code =
    error instanceof KitError ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined;
  const safe = failure(
    safeCodes.includes(code as ErrorCode) ? (code as ErrorCode) : 'EK_BACKEND_UNAVAILABLE',
  );
  return call?.submitted
    ? new KitError({ code: safe.code, message: safe.message, details: { outcome: 'unknown' } })
    : safe;
}
/** A public timeout never frees a physical reservation while an external provider still owns work. */
export class Calls {
  readonly pending = new Set<Promise<unknown>>();
  readonly stop = new AbortController();
  readonly signal: AbortSignal;
  private closed = false;
  private closing: Promise<void> | undefined;
  constructor(
    readonly settings: Settings,
    owner: AbortSignal,
    readonly ready: () => boolean,
    readonly observers: Observers = {},
  ) {
    this.signal = AbortSignal.any([owner, this.stop.signal]);
  }
  check(startup = false): void {
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!startup && !this.ready()) throw failure('EK_LIFECYCLE_STATE');
  }
  async run<T>(
    options: OperationOptions | undefined,
    work: (call: Call) => Promise<T>,
    owner?: AbortSignal,
    startup = false,
    kind: Operation = 'call',
  ): Promise<T> {
    this.check(startup);
    const call = new Call(options, this.settings.timeoutMs, [
      this.signal,
      ...(owner ? [owner] : []),
    ]);
    if (this.pending.size >= this.settings.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    const task = Promise.resolve().then(async () => {
      call.check();
      const result = await instrumentOperation(
        this.observers.telemetry,
        'soap.' + kind,
        { 'soap.operation': kind },
        () => work(call),
        () => undefined,
      );
      call.check();
      return result;
    });
    this.pending.add(task);
    void task.then(
      () => this.pending.delete(task),
      () => this.pending.delete(task),
    );
    let outcome: 'ok' | 'error' | 'fault' = 'error';
    try {
      const result = await within(() => task, call.options());
      outcome = 'ok';
      return result;
    } catch (error) {
      call.controller.abort();
      const safe = safeFailure(error, call);
      if (safe.code === 'EK_SOAP_FAULT') outcome = 'fault';
      throw safe;
    } finally {
      record(
        this.observers,
        kind,
        call,
        outcome,
        performance.now() - call.started,
        this.pending.size,
      );
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    this.closing = within(
      async () => {
        await Promise.allSettled([...this.pending]);
      },
      { timeoutMs: this.settings.timeoutMs },
    );
    void this.closing.catch(() => undefined);
    return this.closing;
  }
}
