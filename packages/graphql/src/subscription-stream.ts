// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { failure, record } from './policy.js';

/** Native iterator.return() is not awaited by Mercurius; completion retains all physical work. */
export class SubscriptionStream implements AsyncIterableIterator<unknown> {
  readonly controller = new AbortController();
  readonly completion: Promise<void>;
  private resolveCompletion!: () => void;
  private readonly pending = new Set<Promise<unknown>>();
  private ready: Promise<void> | undefined;
  private iterator: AsyncIterator<unknown> | undefined;
  private stopped = false;
  private opening = false;
  private reading = false;
  private retired = false;
  private failed = false;
  private cleanupFailed = false;
  private readonly aborted: () => void;

  constructor(
    private readonly acquire: (
      signal: AbortSignal,
    ) => AsyncIterable<unknown> | Promise<AsyncIterable<unknown>>,
    private readonly owner: AbortSignal,
  ) {
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    this.aborted = () => this.stop();
    owner.addEventListener('abort', this.aborted, { once: true });
    if (owner.aborted) this.stop();
  }
  hasFailure() {
    return this.failed;
  }
  retirementFailed() {
    return this.cleanupFailed;
  }
  [Symbol.asyncIterator]() {
    return this;
  }
  private watch<T>(pending: Promise<T>): Promise<T> {
    this.pending.add(pending);
    const settled = () => {
      this.pending.delete(pending);
      this.finish();
    };
    void pending.then(settled, settled);
    return pending;
  }
  async open(): Promise<this> {
    if (this.stopped) throw failure('EK_GQL_SUBSCRIPTION');
    if (!this.ready) {
      this.opening = true;
      this.ready = this.watch(
        Promise.resolve().then(async () => {
          let acquired = false;
          try {
            if (this.stopped) throw failure('EK_GQL_SUBSCRIPTION');
            const source = await this.acquire(this.controller.signal);
            acquired = true;
            if (!source || typeof source[Symbol.asyncIterator] !== 'function')
              throw failure('EK_GQL_SUBSCRIPTION');
            const iterator = source[Symbol.asyncIterator]();
            if (!iterator || typeof iterator.return !== 'function')
              throw failure('EK_GQL_SUBSCRIPTION');
            this.iterator = iterator;
            if (typeof iterator.next !== 'function') throw failure('EK_GQL_SUBSCRIPTION');
          } catch {
            if (acquired && !this.iterator) this.cleanupFailed = true;
            if (!this.stopped) this.failed = true;
            this.stop();
            throw failure('EK_GQL_SUBSCRIPTION');
          } finally {
            this.opening = false;
            if (this.stopped) this.retire();
            this.finish();
          }
        }),
      );
    }
    await this.ready;
    if (this.stopped) throw failure('EK_GQL_SUBSCRIPTION');
    return this;
  }
  async next(): Promise<IteratorResult<unknown>> {
    if (this.stopped) return { value: undefined, done: true };
    if (this.reading) throw failure('EK_GQL_BACKPRESSURE');
    this.reading = true;
    try {
      await this.open();
      if (this.stopped) return { value: undefined, done: true };
      const result = await this.watch(Promise.resolve().then(() => this.iterator!.next()));
      if (this.stopped) return { value: undefined, done: true };
      const completion = record(result, ['done', 'value']);
      const done = completion.done;
      if (done !== undefined && typeof done !== 'boolean') throw failure('EK_GQL_SUBSCRIPTION');
      if (done) {
        this.stop();
        return { value: undefined, done: true };
      }
      return { value: completion.value, done: false };
    } catch {
      if (!this.stopped) this.failed = true;
      this.stop();
      throw failure('EK_GQL_SUBSCRIPTION');
    } finally {
      this.reading = false;
      this.finish();
    }
  }
  async return(): Promise<IteratorResult<unknown>> {
    this.stop();
    await this.completion;
    return { value: undefined, done: true };
  }
  stop() {
    this.stopped = true;
    this.controller.abort();
    this.retire();
    this.finish();
  }
  private retire() {
    if (!this.iterator || this.retired) return;
    this.retired = true;
    this.watch(
      Promise.resolve()
        .then(async () => {
          const result = record(await this.iterator!.return!(), ['done', 'value']);
          if (result.done !== true) throw failure('EK_GQL_SUBSCRIPTION');
        })
        .then(
          () => undefined,
          () => {
            this.failed = true;
            this.cleanupFailed = true;
          },
        ),
    );
  }
  private finish() {
    if (this.stopped && !this.opening && !this.reading && this.pending.size === 0) {
      this.owner.removeEventListener('abort', this.aborted);
      this.resolveCompletion();
    }
  }
}
