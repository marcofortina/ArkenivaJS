// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, ErrorCode } from '@arkenivajs/core';
import { failure, fields, integer } from './validation.js';
import type { XmlDocument } from './contracts.js';
import type { options, Settings } from './settings.js';

export function operation(input: OperationOptions | undefined, maximum: number) {
  const value = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']);
  if (value.signal !== undefined) {
    try {
      Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(value.signal);
      if (!(value.signal instanceof AbortSignal)) throw failure();
      let current: object | null = value.signal;
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
    } catch {
      throw failure();
    }
  }
  return {
    ...(value.signal === undefined ? {} : { signal: value.signal as AbortSignal }),
    timeoutMs: integer(value.timeoutMs === undefined ? maximum : value.timeoutMs, maximum),
  };
}
const safeErrors = new Set<ErrorCode>([
  'EK_XML_PARSE',
  'EK_XML_SCHEMA',
  'EK_XML_SECURITY',
  'EK_UNSUPPORTED_CAPABILITY',
]);
export interface Measurement {
  readonly operation:
    'parse' | 'stringify' | 'xsd-guard' | 'xsd-schema' | 'xsd-gate' | 'validate-xsd';
  readonly outcome: 'ok' | 'error' | 'invalid';
  readonly durationMs: number;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly heapBytes: number;
}
interface Run {
  readonly done: Promise<void>;
  stop(code: ErrorCode): void;
}
function freeze(value: unknown): unknown {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** Each admitted operation owns one bounded native worker until its actual exit. */
export class Runtime {
  readonly active = new Set<Run>();
  closed = false;
  constructor(
    readonly settings: Settings,
    readonly signal: AbortSignal,
    readonly ready: () => boolean,
    readonly observe: (value: Measurement) => void = () => undefined,
  ) {}
  check(bootstrap = false): void {
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!bootstrap && !this.ready()) throw failure('EK_LIFECYCLE_STATE');
    if (this.active.size >= this.settings.maxConcurrent) throw failure('EK_XML_SECURITY');
  }
  execute<T extends string | XmlDocument>(
    command: 'parse' | 'stringify' | 'xsd-guard' | 'xsd-schema',
    input: string | XmlDocument,
    policy: ReturnType<typeof options>,
    requested?: OperationOptions,
    bootstrap = false,
  ): Promise<T> {
    this.check(bootstrap);
    const config = operation(requested, this.settings.timeoutMs);
    if (config.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
    const started = performance.now(),
      inputBytes = Buffer.byteLength(typeof input === 'string' ? input : JSON.stringify(input));
    let worker: Worker | undefined,
      error: ErrorCode | undefined,
      value: T | undefined,
      heapBytes = 0,
      received = false;
    let resolve!: (value: T) => void, reject!: (error: unknown) => void, finish!: () => void;
    const result = new Promise<T>((yes, no) => {
        resolve = yes;
        reject = no;
      }),
      done = new Promise<void>((yes) => {
        finish = yes;
      });
    void result.catch(() => undefined);
    const abort = () => run.stop('EK_ABORTED');
    const timer = setTimeout(() => run.stop('EK_TIMEOUT'), config.timeoutMs);
    const run: Run = {
      done,
      stop(code) {
        error ??= code;
        reject(failure(error));
        void worker?.terminate().catch(() => undefined);
      },
    };
    this.active.add(run);
    this.signal.addEventListener('abort', abort, { once: true });
    config.signal?.addEventListener('abort', abort, { once: true });
    const settle = () => {
      clearTimeout(timer);
      this.signal.removeEventListener('abort', abort);
      config.signal?.removeEventListener('abort', abort);
      this.active.delete(run);
      if (!received && !error) error = 'EK_XML_PARSE';
      if (!error && performance.now() - started >= config.timeoutMs) error = 'EK_TIMEOUT';
      const outputBytes =
        value === undefined
          ? 0
          : Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value));
      try {
        this.observe({
          operation: command,
          outcome: error ? 'error' : 'ok',
          durationMs: Math.max(0, performance.now() - started),
          inputBytes,
          outputBytes,
          heapBytes,
        });
      } catch {
        /* Diagnostics cannot alter parser outcomes. */
      }
      if (error) reject(failure(error));
      else resolve(freeze(value) as T);
      finish();
    };
    try {
      worker = new Worker(new URL('./worker.js', import.meta.url), {
        workerData: {
          command,
          input,
          policy,
          maxOutputBytes: command === 'xsd-schema' ? 256 * 1024 : this.settings.maxOutputBytes,
        },
        env: { TZ: 'UTC' },
        execArgv: [],
        stdout: true,
        stderr: true,
        resourceLimits: {
          maxOldGenerationSizeMb: 96,
          maxYoungGenerationSizeMb: 16,
          stackSizeMb: 4,
        },
      });
      worker.stdout.on('data', () => run.stop('EK_XML_SECURITY'));
      worker.stderr.on('data', () => run.stop('EK_XML_SECURITY'));
      worker.on('error', () => {
        error ??= 'EK_XML_PARSE';
      });
      worker.on('message', (message: unknown) => {
        try {
          if (received) throw failure();
          const data = fields(message, ['value', 'error', 'heapBytes']);
          received = true;
          if (data.error !== undefined) {
            if (!safeErrors.has(data.error as ErrorCode)) throw failure();
            error ??= data.error as ErrorCode;
          } else {
            if (
              command === 'parse'
                ? !data.value || typeof data.value !== 'object'
                : typeof data.value !== 'string'
            )
              throw failure();
            value = data.value as T;
            heapBytes = integer(data.heapBytes, 256 * 1024 * 1024);
          }
        } catch {
          run.stop('EK_XML_PARSE');
        }
      });
      worker.once('exit', (code) => {
        if (code !== 0) error ??= 'EK_XML_PARSE';
        settle();
      });
      if (this.signal.aborted || config.signal?.aborted) run.stop('EK_ABORTED');
    } catch {
      error ??= 'EK_XML_PARSE';
      settle();
    }
    return result;
  }

  /** Retain external native work and its admission until the actual process closes. */
  external<T>(
    requested: OperationOptions | undefined,
    inputBytes: number,
    work: (signal: AbortSignal, timeoutMs: number) => Promise<T>,
    bootstrap = false,
    classify: (value: T) => 'ok' | 'invalid' = () => 'ok',
  ): Promise<T> {
    this.check(bootstrap);
    const config = operation(requested, this.settings.timeoutMs),
      controller = new AbortController(),
      started = performance.now();
    if (config.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
    let error: ErrorCode | undefined,
      reject!: (error: unknown) => void,
      outcome: 'ok' | 'invalid' = 'ok';
    const canceled = new Promise<never>((_resolve, no) => {
      reject = no;
    });
    void canceled.catch(() => undefined);
    const abort = () => run.stop('EK_ABORTED');
    const timer = setTimeout(() => run.stop('EK_TIMEOUT'), config.timeoutMs);
    const run: Run = {
      done: Promise.resolve(),
      stop(code) {
        error ??= code;
        controller.abort();
        reject(failure(error));
      },
    };
    this.active.add(run);
    this.signal.addEventListener('abort', abort, { once: true });
    config.signal?.addEventListener('abort', abort, { once: true });
    const owned = Promise.resolve()
      .then(async () => {
        if (error) throw failure(error);
        const value = await work(controller.signal, config.timeoutMs);
        outcome = classify(value);
        if (!error && performance.now() - started >= config.timeoutMs) error = 'EK_TIMEOUT';
        if (error) throw failure(error);
        return value;
      })
      .catch((cause: unknown) => {
        error ??= cause instanceof KitError ? cause.code : 'EK_XML_SCHEMA';
        throw failure(error);
      })
      .finally(() => {
        clearTimeout(timer);
        this.signal.removeEventListener('abort', abort);
        config.signal?.removeEventListener('abort', abort);
        this.active.delete(run);
        try {
          this.observe({
            operation: bootstrap ? 'xsd-gate' : 'validate-xsd',
            outcome: error ? 'error' : outcome,
            durationMs: Math.max(0, performance.now() - started),
            inputBytes,
            outputBytes: 0,
            heapBytes: 0,
          });
        } catch {
          /* Diagnostics cannot change native validation. */
        }
      });
    Object.defineProperty(run, 'done', {
      value: owned.then(
        () => undefined,
        () => undefined,
      ),
    });
    if (this.signal.aborted || config.signal?.aborted) run.stop('EK_ABORTED');
    const result = Promise.race([owned, canceled]);
    void result.catch(() => undefined);
    return result;
  }
  async close(): Promise<void> {
    this.closed = true;
    const runs = [...this.active];
    for (const run of runs) run.stop('EK_ABORTED');
    await Promise.all(runs.map((run) => run.done));
  }
}
