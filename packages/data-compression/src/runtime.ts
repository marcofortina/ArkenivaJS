// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { setInterval, clearInterval } from 'node:timers';
import { within } from '@arkenivajs/core/support';
import { failure, safeFailure, snapshot } from './settings.js';
import type { FailureCode, Policy, Captured } from './settings.js';
import type { InputBytes } from './contracts.js';

export interface Observation {
  readonly operation: 'gzip' | 'gunzip' | 'create_zip' | 'iterate_zip';
  readonly outcome: 'ok' | 'error' | 'cancelled';
  readonly durationMs: number;
  readonly compressedBytes: number;
  readonly expandedBytes: number;
  readonly processCpuMs: number;
  readonly processRssPeakBytes: number;
}

/** An operation retains physical admission while any owned native/user task remains unsettled. */
export class Lease {
  readonly #started = performance.now();
  #peakRss = process.memoryUsage().rss;
  #compressed = 0;
  #expanded = 0;
  #success = false;
  readonly #controller = new AbortController();
  readonly #tasks = new Set<Promise<unknown>>();
  readonly #cleanup = new Set<() => void>();
  readonly #deadline: number;
  readonly #cpu = process.cpuUsage();
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #cpuTimer: ReturnType<typeof setInterval>;
  readonly #release: () => void;
  readonly #signal: AbortSignal | undefined;
  readonly #abort = () => this.cancel('EK_ABORTED');
  #error: FailureCode | undefined;
  #finished = false;
  #retired = false;
  #resolve!: () => void;
  readonly drained = new Promise<void>((resolve) => {
    this.#resolve = resolve;
  });
  constructor(
    readonly policy: Policy,
    release: () => void,
    readonly kind: Observation['operation'],
    readonly observe: (value: Observation) => void,
  ) {
    this.#release = release;
    this.#deadline = performance.now() + policy.timeoutMs;
    this.#signal = policy.signal;
    this.#timer = setTimeout(() => this.cancel('EK_TIMEOUT'), policy.timeoutMs);
    this.#cpuTimer = setInterval(() => {
      try {
        this.check();
      } catch {
        /* check already cancels native resources. */
      }
    }, 25);
    this.#signal?.addEventListener('abort', this.#abort, { once: true });
    if (this.#signal?.aborted) this.cancel('EK_ABORTED');
  }
  get signal() {
    return this.#controller.signal;
  }
  cancel(code: FailureCode) {
    if (this.#error) return;
    this.#error = code;
    this.#controller.abort();
    this.finish();
  }
  check() {
    this.#peakRss = Math.max(this.#peakRss, process.memoryUsage().rss);
    if (!this.#error && performance.now() >= this.#deadline) this.cancel('EK_TIMEOUT');
    const cpu = process.cpuUsage(this.#cpu);
    if (!this.#error && (cpu.user + cpu.system) / 1000 > this.policy.maxCpuTimeMs)
      this.cancel('EK_ARCHIVE_LIMIT');
    if (this.#error) throw failure(this.#error);
  }
  account(compressed: number, expanded: number) {
    this.#compressed = compressed;
    this.#expanded = expanded;
  }
  success() {
    this.check();
    this.#success = true;
  }
  fail(cause: unknown) {
    const error = safeFailure(cause);
    this.cancel(error.code as FailureCode);
    return error;
  }
  cleanup(action: () => void) {
    this.#cleanup.add(action);
    if (this.#error) action();
  }
  track<T>(task: Promise<T>): Promise<T> {
    this.#tasks.add(task);
    void task.then(
      () => {
        this.#tasks.delete(task);
        this.#retire();
      },
      () => {
        this.#tasks.delete(task);
        this.#retire();
      },
    );
    return task;
  }
  async wait<T>(task: Promise<T>): Promise<T> {
    this.track(task);
    this.check();
    try {
      const result = await within(() => task, {
        signal: this.signal,
        timeoutMs: Math.max(1, Math.ceil(this.#deadline - performance.now())),
      });
      this.check();
      return result;
    } catch (cause) {
      this.check();
      throw safeFailure(cause);
    }
  }
  finish() {
    if (this.#finished) return;
    this.#finished = true;
    clearTimeout(this.#timer);
    clearInterval(this.#cpuTimer);
    this.#signal?.removeEventListener('abort', this.#abort);
    for (const cleanup of this.#cleanup) {
      try {
        cleanup();
      } catch {
        /* Native cleanup cannot replace the result. */
      }
    }
    this.#cleanup.clear();
    const cpu = process.cpuUsage(this.#cpu);
    try {
      this.observe({
        operation: this.kind,
        outcome: this.#error ? 'error' : this.#success ? 'ok' : 'cancelled',
        durationMs: Math.max(0, performance.now() - this.#started),
        compressedBytes: this.#compressed,
        expandedBytes: this.#expanded,
        processCpuMs: (cpu.user + cpu.system) / 1000,
        processRssPeakBytes: Math.max(this.#peakRss, process.memoryUsage().rss),
      });
    } catch {
      /* Observers cannot change stream outcomes. */
    }
    this.#retire();
  }
  #retire() {
    if (this.#finished && this.#tasks.size === 0 && !this.#retired) {
      this.#retired = true;
      this.#release();
      this.#resolve();
    }
  }
}
export class Runtime {
  readonly #active = new Set<Lease>();
  #closed = false;
  constructor(
    readonly settings: Captured,
    readonly observe: (value: Observation) => void = () => undefined,
  ) {}
  acquire(policy: Policy, kind: Observation['operation']): Lease {
    if (this.#closed) throw failure('EK_RESOURCE_CLOSED');
    if (policy.signal?.aborted) throw failure('EK_ABORTED');
    if (this.#active.size >= this.settings.maxConcurrent) throw failure('EK_ARCHIVE_LIMIT');
    const lease = new Lease(policy, () => this.#active.delete(lease), kind, this.observe);
    this.#active.add(lease);
    return lease;
  }
  async close() {
    this.#closed = true;
    const active = [...this.#active];
    for (const lease of active) {
      lease.cancel('EK_RESOURCE_CLOSED');
      lease.finish();
    }
    await Promise.all(active.map((lease) => lease.drained));
  }
}
/** Pull only one source item at a time and bound every copy before entering a native codec. */
export async function* chunks(
  input: InputBytes,
  lease: Lease,
  maximum: number,
): AsyncGenerator<Uint8Array> {
  lease.check();
  let total = 0;
  const iterator =
    input instanceof Uint8Array
      ? (async function* () {
          yield input;
        })()[Symbol.asyncIterator]()
      : input[Symbol.asyncIterator]();
  let ended = false;
  lease.cleanup(() => {
    if (!ended && iterator.return) {
      ended = true;
      lease.track(Promise.resolve().then(() => iterator.return!()));
    }
  });
  try {
    while (true) {
      lease.check();
      const next = await lease.wait(
        Promise.resolve().then(() => {
          lease.check();
          return iterator.next();
        }),
      );
      if (!next || typeof next !== 'object') throw failure('EK_ARCHIVE_CORRUPT');
      if (next.done) {
        ended = true;
        break;
      }
      const data = snapshot(next.value, maximum - total);
      total += data.byteLength;
      // Empty chunks are legal but cannot prevent the operation deadline from taking effect.
      for (let offset = 0; offset < data.byteLength; offset += 16384) {
        lease.check();
        yield data.slice(offset, offset + 16384);
      }
    }
  } catch (cause) {
    throw safeFailure(cause);
  }
}
