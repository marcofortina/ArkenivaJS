// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fork } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import type { Settings } from './settings.js';
import { failure, fields, integer } from './validation.js';
import type { recorder } from './observation.js';

export function operation(input: OperationOptions | undefined, maximum: number) {
  const data = fields(input ?? {}, ['signal', 'timeoutMs']);
  if (data.signal !== undefined) {
    try {
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(data.signal);
    } catch {
      throw failure();
    }
    if (!(data.signal instanceof AbortSignal)) throw failure();
    let current: object | null = data.signal;
    while (current !== AbortSignal.prototype) {
      if (
        !current ||
        ['aborted', 'reason', 'addEventListener', 'removeEventListener'].some((key) =>
          Object.hasOwn(current!, key),
        )
      )
        throw failure();
      current = Object.getPrototypeOf(current) as object | null;
    }
  }
  return {
    signal: data.signal as AbortSignal | undefined,
    timeoutMs: integer(data.timeoutMs ?? maximum, maximum),
  };
}

/** Abort races never detach caller work from resource admission or application draining. */
export class Scope {
  readonly #deadline: number;
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #signal: AbortSignal | undefined;
  readonly #listener: () => void;
  readonly #bookListener: () => void;
  readonly #aborted: Promise<never>;
  #reject!: (error: unknown) => void;
  #error: KitError | undefined;
  constructor(
    readonly book: Book,
    input?: OperationOptions,
  ) {
    const config = operation(input, book.settings.timeoutMs);
    this.#deadline = performance.now() + config.timeoutMs;
    this.#signal = config.signal;
    this.#aborted = new Promise<never>((_resolve, reject) => {
      this.#reject = reject;
    });
    void this.#aborted.catch(() => undefined);
    this.#listener = () => this.stop('EK_ABORTED');
    this.#bookListener = () => this.stop('EK_ABORTED');
    this.#timer = setTimeout(() => this.stop('EK_TIMEOUT'), config.timeoutMs);
    config.signal?.addEventListener('abort', this.#listener, { once: true });
    book.cancelled.addEventListener('abort', this.#bookListener, { once: true });
    if (config.signal?.aborted) this.stop('EK_ABORTED');
  }
  stop(code: ErrorCode) {
    this.#error ??= failure(code);
    this.#reject(this.#error);
    this.book.stop(this.#error);
  }
  check() {
    if (this.#error) throw this.#error;
    if (performance.now() >= this.#deadline) this.stop('EK_TIMEOUT');
    if (this.#error) throw this.#error;
    this.book.check();
  }
  async wait<T>(work: Promise<T>): Promise<T> {
    this.book.track(work);
    const value = await Promise.race([work, this.#aborted]);
    this.check();
    return value;
  }
  finish() {
    clearTimeout(this.#timer);
    this.#signal?.removeEventListener('abort', this.#listener);
    this.book.cancelled.removeEventListener('abort', this.#bookListener);
  }
}

const acceptedErrors = new Set(['EK_XLSX_FORMAT', 'EK_XLSX_LIMIT', 'EK_XLSX_UNSUPPORTED']);
/** Reject concurrent pulls rather than accumulating the native async-generator request queue. */
export function cursor<T>(source: AsyncGenerator<T>, book: Book): AsyncIterableIterator<T> {
  let pending = false,
    closed = false;
  return {
    [Symbol.asyncIterator]() {
      return this;
    },
    async next() {
      if (closed) return { done: true, value: undefined };
      if (pending) throw failure('EK_XLSX_UNSUPPORTED');
      pending = true;
      try {
        const value = await source.next();
        if (value.done) closed = true;
        return value;
      } finally {
        pending = false;
      }
    },
    async return() {
      if (closed) return { done: true, value: undefined };
      closed = true;
      if (pending) book.stop();
      await source.return(undefined);
      return { done: true, value: undefined };
    },
  };
}
const require = createRequire(import.meta.url);
function readRoots(): readonly string[] {
  const native = realpathSync(require.resolve('exceljs')),
    marker = sep + 'node_modules' + sep,
    at = native.indexOf(marker),
    core = realpathSync(fileURLToPath(import.meta.resolve('@arkenivajs/core')));
  if (at < 0) throw failure('EK_CONFIG_INVALID');
  return [
    resolve(fileURLToPath(new URL('..', import.meta.url))),
    native.slice(0, at + marker.length - 1),
    resolve(dirname(core), '..'),
  ];
}
/** A workbook owns exactly one child, one RPC slot and all outstanding caller promises. */
export class Book {
  readonly #controller = new AbortController();
  readonly cancelled = this.#controller.signal;
  readonly done: Promise<void>;
  readonly #settled = new Set<Promise<unknown>>();
  #resolveDone!: () => void;
  #child: ChildProcess | undefined;
  #exited = true;
  #closed = false;
  #error: KitError | undefined;
  #sequence = 0;
  #pending: { id: number; resolve(value: unknown): void; reject(error: unknown): void } | undefined;
  #busy = false;
  #released = false;
  #completing = false;
  #memory = 0;
  #exit: Promise<void> = Promise.resolve();
  constructor(
    readonly settings: Settings,
    readonly released: () => void,
    readonly observe?: ReturnType<typeof recorder>,
  ) {
    this.done = new Promise((resolve) => {
      this.#resolveDone = resolve;
    });
  }
  track<T>(work: Promise<T>): void {
    this.#settled.add(work);
    void work
      .finally(() => {
        this.#settled.delete(work);
        this.#release();
      })
      .catch(() => undefined);
  }
  #release() {
    if (this.#closed && this.#exited && !this.#settled.size && !this.#released) {
      this.#released = true;
      this.released();
      this.#resolveDone();
    }
  }
  check() {
    if (this.#error) throw this.#error;
    if (this.#closed) throw failure('EK_RESOURCE_CLOSED');
  }
  async use<T>(
    input: OperationOptions | undefined,
    work: (scope: Scope) => Promise<T>,
  ): Promise<T> {
    const scope = this.begin(input);
    try {
      return await work(scope);
    } catch (error) {
      const normalized = error instanceof KitError ? error : failure();
      this.stop(normalized);
      throw normalized;
    } finally {
      this.end(scope);
    }
  }
  begin(input?: OperationOptions): Scope {
    this.check();
    if (this.#busy) throw failure('EK_XLSX_UNSUPPORTED');
    operation(input, this.settings.timeoutMs);
    this.#busy = true;
    try {
      const scope = new Scope(this, input);
      try {
        scope.check();
        return scope;
      } catch (error) {
        scope.finish();
        throw error;
      }
    } catch (error) {
      this.#busy = false;
      throw error;
    }
  }
  end(scope: Scope): void {
    scope.finish();
    this.#busy = false;
  }
  lock(): void {
    this.check();
    if (this.#busy) throw failure('EK_XLSX_UNSUPPORTED');
  }
  start(path?: string): void {
    this.check();
    if (this.#child) return;
    const roots = [...readRoots(), ...(path ? [path] : [])];
    const child = fork(new URL('./worker.js', import.meta.url), [], {
      execPath: process.execPath,
      execArgv: [
        '--permission',
        ...roots.map((root) => '--allow-fs-read=' + root),
        '--max-old-space-size=512',
        '--max-semi-space-size=8',
      ],
      env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'production', UV_THREADPOOL_SIZE: '1' },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      serialization: 'advanced',
    });
    this.#child = child;
    this.#exited = false;
    child.on('message', (raw: unknown) => {
      try {
        const message = fields(raw, ['id', 'value', 'error', 'memoryBytes']),
          pending = this.#pending;
        const memory = integer(message.memoryBytes, Number.MAX_SAFE_INTEGER);
        if (memory > this.#memory) {
          this.#memory = memory;
          this.observe?.measure('worker.memory.sampled-peak.bytes', memory);
        }
        if (!pending || pending.id !== message.id) throw failure();
        if (message.error !== undefined && !acceptedErrors.has(message.error as string))
          throw failure();
        this.#pending = undefined;
        if (message.error !== undefined) {
          pending.reject(failure(message.error as ErrorCode));
        } else pending.resolve(message.value);
      } catch {
        this.stop(failure());
      }
    });
    child.on('error', () => this.stop(failure()));
    this.#exit = new Promise<void>((resolveExit) =>
      child.once('close', (code) => {
        this.#exited = true;
        if ((!this.#closed && !this.#completing) || code !== 0) this.#error ??= failure();
        this.#pending?.reject(this.#error ?? failure('EK_RESOURCE_CLOSED'));
        this.#pending = undefined;
        this.#release();
        resolveExit();
      }),
    );
  }
  rpc(command: string, value: object = {}): Promise<unknown> {
    this.check();
    const child = this.#child;
    if (!child || !child.connected || this.#pending) return Promise.reject(failure());
    const id = ++this.#sequence;
    return new Promise((resolve, reject) => {
      this.#pending = { id, resolve, reject };
      child.send({ id, command, value }, (error) => {
        if (error) this.stop(failure());
      });
    });
  }
  stop(error = failure('EK_RESOURCE_CLOSED')): void {
    this.#error ??= error;
    this.#closed = true;
    if (!this.#controller.signal.aborted) this.#controller.abort();
    this.#pending?.reject(this.#error);
    this.#pending = undefined;
    if (!this.#exited) this.#child?.kill('SIGKILL');
    this.#release();
  }
  async close(): Promise<void> {
    this.stop();
    await this.done;
  }
  async complete(scope: Scope): Promise<void> {
    this.#completing = true;
    await scope.wait(this.rpc('close'));
    // The final acknowledgement is the actual child exit, not only an IPC reply.
    await scope.wait(this.#exit);
    this.#closed = true;
    this.#release();
  }
}
