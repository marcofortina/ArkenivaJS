// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fork } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import type { Job, Result } from './codec.js';
import type { Captured, FailureCode } from './settings.js';
import { failure } from './settings.js';

interface Slot {
  readonly child: ChildProcess;
  readonly closed: Promise<void>;
  ready: boolean;
  retiring: boolean;
  current: { id: number; finish(result?: Result, error?: FailureCode): void } | undefined;
}
const childErrors = new Set<FailureCode>([
  'EK_CODE_UNSUPPORTED',
  'EK_CODE_DECODE',
  'EK_CODE_LIMIT',
]);
/** Owned processes isolate native image threads as well as JavaScript decoding work. */
export class CodePool {
  readonly #slots = new Set<Slot>();
  readonly #settings: Captured;
  #closed = false;
  #failed = false;
  #sequence = 0;
  constructor(settings: Captured) {
    this.#settings = settings;
  }

  async start(): Promise<void> {
    const started = await Promise.allSettled(
      Array.from({ length: this.#settings.maxConcurrent }, () => this.#spawn()),
    );
    if (started.some((result) => result.status === 'rejected')) {
      await this.close();
      throw failure('EK_RESOURCE_CLOSED');
    }
  }
  #spawn(): Promise<void> {
    if (this.#closed) return Promise.reject(failure('EK_RESOURCE_CLOSED'));
    return new Promise((resolve, reject) => {
      const child = fork(new URL('./codec-worker.js', import.meta.url), [], {
        execPath: process.execPath,
        execArgv: ['--max-old-space-size=128'],
        // Application credentials and dynamic-loader settings never reach the image process.
        env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'production', UV_THREADPOOL_SIZE: '1' },
        serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      let release!: () => void,
        booted = false;
      const closed = new Promise<void>((done) => {
          release = done;
        }),
        slot: Slot = { child, closed, ready: false, retiring: false, current: undefined };
      this.#slots.add(slot);
      const startup = setTimeout(() => {
        slot.retiring = true;
        child.kill('SIGKILL');
        reject(failure('EK_RESOURCE_CLOSED'));
      }, 10000);
      child.on(
        'message',
        (message: { ready?: boolean; id?: number; result?: Result; error?: FailureCode }) => {
          if (slot.retiring || this.#closed) return;
          if (!booted && message?.ready === true) {
            booted = true;
            clearTimeout(startup);
            slot.ready = true;
            resolve();
            return;
          }
          const current = slot.current;
          if (!booted || !current || message?.id !== current.id) {
            slot.retiring = true;
            child.kill('SIGKILL');
            return;
          }
          slot.current = undefined;
          slot.ready = true;
          current.finish(
            message.result,
            message.error && childErrors.has(message.error)
              ? message.error
              : message.result
                ? undefined
                : 'EK_CODE_DECODE',
          );
        },
      );
      child.on('error', () => {
        slot.retiring = true;
        child.kill('SIGKILL');
        reject(failure('EK_RESOURCE_CLOSED'));
      });
      child.once('close', () => {
        clearTimeout(startup);
        this.#slots.delete(slot);
        slot.current?.finish(undefined, this.#closed ? 'EK_RESOURCE_CLOSED' : 'EK_CODE_DECODE');
        release();
        if (!booted) reject(failure('EK_RESOURCE_CLOSED'));
        // Replacement starts only after all owned native threads have actually exited.
        if (booted && !this.#closed && !this.#failed) {
          void this.#spawn().catch(() => {
            this.#failed = true;
          });
        }
      });
    });
  }
  run(job: Job, timeoutMs: number, signal: AbortSignal | undefined): Promise<Result> {
    if (this.#closed || this.#failed) return Promise.reject(failure('EK_RESOURCE_CLOSED'));
    if (signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
    const slot = [...this.#slots].find((item) => item.ready && !item.retiring);
    if (!slot) return Promise.reject(failure('EK_CODE_LIMIT'));
    slot.ready = false;
    const id = ++this.#sequence,
      deadline = performance.now() + timeoutMs;
    return new Promise((resolve, reject) => {
      let completed = false;
      const finish = (result?: Result, error?: FailureCode) => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        if (!error && performance.now() >= deadline) error = 'EK_TIMEOUT';
        if (error) reject(failure(error));
        else if (
          !result ||
          !Number.isSafeInteger(result.pixels) ||
          result.pixels < 1 ||
          result.pixels > job.options.maxPixels ||
          result.bytes > job.maxOutputBytes
        )
          reject(failure('EK_CODE_LIMIT'));
        else resolve(result);
      };
      const retire = (error: FailureCode) => {
          slot.retiring = true;
          finish(undefined, error);
          slot.child.kill('SIGKILL');
        },
        abort = () => retire('EK_ABORTED'),
        timer = setTimeout(() => retire('EK_TIMEOUT'), timeoutMs);
      slot.current = { id, finish };
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) {
        abort();
        return;
      }
      try {
        slot.child.send({ id, job }, (error) => {
          if (error) retire('EK_CODE_DECODE');
        });
      } catch {
        retire('EK_CODE_DECODE');
      }
    });
  }
  async close(): Promise<void> {
    this.#closed = true;
    const slots = [...this.#slots];
    for (const slot of slots) {
      slot.retiring = true;
      slot.current?.finish(undefined, 'EK_RESOURCE_CLOSED');
      slot.child.kill('SIGKILL');
    }
    await Promise.all(slots.map((slot) => slot.closed));
  }
}
