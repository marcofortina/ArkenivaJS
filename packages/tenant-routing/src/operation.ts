// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { routingFailure } from './errors.js';

/** A public timeout never releases capacity while application work is still physically running. */
export class RoutingOperation {
  readonly signal: AbortSignal;
  readonly completion: Promise<void>;
  private readonly controller = new AbortController();
  private readonly began = performance.now();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly detach: () => void;
  private release: () => void = () => {};
  private permit: (() => void) | undefined;
  private ended = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  constructor(
    readonly timeoutMs: number,
    owner: AbortSignal,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw routingFailure();
    this.signal = this.controller.signal;
    this.completion = new Promise((resolve) => {
      this.release = resolve;
    });
    const source = AbortSignal.any([owner]);
    const aborted = () => this.abort();
    source.addEventListener('abort', aborted, { once: true });
    this.detach = () => {
      source.removeEventListener('abort', aborted);
      if (this.timer) clearTimeout(this.timer);
    };
    const schedule = () => {
      const remaining = Math.ceil(timeoutMs - (performance.now() - this.began));
      if (remaining <= 0) {
        this.abort();
        return;
      }
      this.timer = setTimeout(schedule, Math.min(remaining, 2147483647));
    };
    schedule();
    if (source.aborted) this.abort();
  }
  check(): void {
    if (this.signal.aborted || performance.now() - this.began >= this.timeoutMs) {
      this.abort();
      throw routingFailure('EK_TROUTE_TIMEOUT');
    }
  }
  own(release: () => void): void {
    try {
      this.check();
      if (this.permit) throw routingFailure('EK_TROUTE_CAPACITY');
      this.permit = release;
    } catch (error) {
      release();
      throw error;
    }
  }
  async run<T>(work: () => T | Promise<T>): Promise<T> {
    this.check();
    const pending = Promise.resolve().then(() => {
      this.check();
      return work();
    });
    this.pending.add(pending);
    const settled = () => {
      this.pending.delete(pending);
      this.finish();
    };
    void pending.then(settled, settled);
    try {
      const result = await within(() => pending, {
        signal: this.signal,
        timeoutMs: Math.max(1, Math.ceil(this.timeoutMs - (performance.now() - this.began))),
      });
      this.check();
      return result;
    } catch (error) {
      if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) {
        this.abort();
        throw routingFailure('EK_TROUTE_TIMEOUT');
      }
      throw error;
    }
  }
  end(): void {
    this.ended = true;
    this.finish();
  }
  abort(): void {
    this.controller.abort(routingFailure('EK_TROUTE_TIMEOUT'));
  }
  private finish(): void {
    if (this.ended && this.pending.size === 0) {
      this.permit?.();
      this.permit = undefined;
      this.detach();
      this.release();
    }
  }
}
