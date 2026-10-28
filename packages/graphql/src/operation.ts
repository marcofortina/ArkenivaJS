// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { GraphqlExecutionLimits, GraphqlRequestContext } from './contracts.js';
import { failure } from './policy.js';

/** Public timeout does not relinquish ownership of still-running application work. */
export class Operation {
  readonly controller = new AbortController();
  readonly context: GraphqlRequestContext;
  readonly began = performance.now();
  readonly completion: Promise<void>;
  fields = 0;
  mutationEpoch = 0;
  private readonly pending = new Set<Promise<unknown>>();
  private release!: () => void;
  private ended = false;
  private readonly detach: () => void;

  constructor(
    context: Omit<GraphqlRequestContext, 'signal'>,
    readonly limits: GraphqlExecutionLimits,
    owner: AbortSignal,
  ) {
    this.context = Object.freeze({ ...context, signal: this.controller.signal });
    this.completion = new Promise((resolve) => {
      this.release = resolve;
    });
    const abort = () => this.controller.abort(failure('EK_GQL_TIMEOUT'));
    const lifecycle = AbortSignal.any([owner]);
    lifecycle.addEventListener('abort', abort, { once: true });
    this.detach = () => lifecycle.removeEventListener('abort', abort);
    if (lifecycle.aborted) abort();
  }

  check() {
    if (this.controller.signal.aborted) throw failure('EK_GQL_TIMEOUT');
    if (performance.now() - this.began >= this.limits.maxOperationMs) {
      this.controller.abort(failure('EK_GQL_TIMEOUT'));
      throw failure('EK_GQL_TIMEOUT');
    }
  }

  async run<T>(work: () => T | Promise<T>): Promise<T> {
    this.check();
    const pending = Promise.resolve().then(() => {
      this.check();
      return work();
    });
    this.pending.add(pending);
    const settle = () => {
      this.pending.delete(pending);
      this.finish();
    };
    void pending.then(settle, settle);
    try {
      return await within(() => pending, {
        signal: this.controller.signal,
        timeoutMs: Math.max(
          1,
          Math.ceil(this.limits.maxOperationMs - (performance.now() - this.began)),
        ),
      });
    } catch (error) {
      if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) {
        this.controller.abort(failure('EK_GQL_TIMEOUT'));
        throw failure('EK_GQL_TIMEOUT');
      }
      throw error;
    }
  }

  end() {
    this.ended = true;
    this.finish();
  }
  abort() {
    this.controller.abort(failure('EK_GQL_TIMEOUT'));
  }
  private finish() {
    if (this.ended && this.pending.size === 0) {
      this.detach();
      this.release();
    }
  }
}
