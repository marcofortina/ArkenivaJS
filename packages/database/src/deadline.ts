// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError, DEFAULT_SQL_TIMEOUT_MS } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';

/** One owned deadline covers queueing and native work; closing always removes listeners and timers. */
export class SqlDeadline {
  private readonly controller = new AbortController();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly detach: (() => void)[] = [];
  readonly signal = this.controller.signal;

  constructor(options: OperationOptions = {}, lifetime?: AbortSignal) {
    if (!options || typeof options !== 'object' || Array.isArray(options))
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'SQL operation options must be an object',
      });
    const timeout = options.timeoutMs ?? DEFAULT_SQL_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(timeout) ||
      timeout <= 0 ||
      (options.signal !== undefined && !(options.signal instanceof AbortSignal))
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'SQL deadline requires a positive integer timeout and an AbortSignal',
      });
    for (const signal of [options.signal, lifetime]) {
      if (!signal) continue;
      const cancel = () =>
        this.abort(
          new KitError({
            code: 'EK_ABORTED',
            message: 'SQL operation aborted',
            cause: signal.reason,
          }),
        );
      if (signal.aborted) cancel();
      else {
        signal.addEventListener('abort', cancel, { once: true });
        this.detach.push(() => signal.removeEventListener('abort', cancel));
      }
    }
    if (!this.signal.aborted) {
      const expires = performance.now() + timeout;
      const schedule = (): void => {
        const remaining = Math.ceil(expires - performance.now());
        if (remaining <= 0)
          this.abort(
            new KitError({ code: 'EK_TIMEOUT', message: 'SQL operation deadline exceeded' }),
          );
        else this.timer = setTimeout(schedule, Math.min(remaining, 2_147_483_647));
      };
      schedule();
    }
  }

  /** Abort may discard a connection, but it never replays native work. */
  abort(reason: KitError): void {
    if (!this.signal.aborted) this.controller.abort(reason);
  }

  /** Reject before invoking work if cancellation already won. */
  check(): void {
    if (this.signal.aborted) throw this.signal.reason;
  }

  /** Observe both settlements even when the native promise resolves after caller cancellation. */
  async run<T>(work: () => Promise<T> | T): Promise<T> {
    this.check();
    let rejectAbort!: () => void;
    try {
      const cancelled = new Promise<never>((_resolve, reject) => {
        rejectAbort = () => reject(this.signal.reason);
        this.signal.addEventListener('abort', rejectAbort, { once: true });
      });
      return await Promise.race([
        Promise.resolve().then(() => {
          this.check();
          return work();
        }),
        cancelled,
      ]);
    } finally {
      this.signal.removeEventListener('abort', rejectAbort);
    }
  }

  /** Return remaining native operations to their owner; this only releases deadline bookkeeping. */
  close(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    for (const remove of this.detach.splice(0)) remove();
  }
}
