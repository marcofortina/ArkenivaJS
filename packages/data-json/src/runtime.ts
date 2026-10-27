// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { JsonOptions, JsonValidation } from './contracts.js';
import { options, parse, stringify } from './codec.js';
import type { Settings } from './settings.js';
import { errorCodes, headerBytes } from './protocol.js';
import type { Operation } from './protocol.js';
import { failure } from './validation.js';

interface Slot {
  readonly worker: Worker;
  readonly header: Int32Array;
  readonly output: Uint8Array;
  readonly exited: Promise<void>;
  alive: boolean;
  available: boolean;
  retired: boolean;
}
export interface Measurement {
  readonly operation: Operation;
  readonly outcome: 'ok' | 'error' | 'invalid';
  readonly durationMs: number;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly heapBytes: number;
  readonly mappingId?: string;
  readonly mappingVersion?: string;
}

/** Synchronous public calls wait on bounded native workers; deadlines can terminate blocked validators. */
export class Runtime {
  readonly slots: Slot[] = [];
  closed = false;
  private closing: Promise<void> | undefined;
  private constructor(
    readonly settings: Settings,
    readonly signal: AbortSignal,
    readonly ready: () => boolean,
    readonly observe: (value: Measurement) => void,
  ) {}
  static async create(
    settings: Settings,
    signal: AbortSignal,
    ready: () => boolean,
    observe: (value: Measurement) => void = () => undefined,
  ): Promise<Runtime> {
    const runtime = new Runtime(settings, signal, ready, observe);
    const abort = () => {
      void runtime.close();
    };
    signal.addEventListener('abort', abort, { once: true });
    runtime.detach = () => signal.removeEventListener('abort', abort);
    try {
      if (signal.aborted) throw failure('EK_ABORTED');
      await Promise.all(Array.from({ length: settings.maxConcurrent }, () => runtime.start()));
      if (runtime.closed || signal.aborted) throw failure('EK_ABORTED');
      return runtime;
    } catch (error) {
      await runtime.close();
      throw error;
    }
  }
  private detach: () => void = () => undefined;
  private start(): Promise<void> {
    const buffer = new SharedArrayBuffer(headerBytes + this.settings.maxOutputBytes);
    const worker = new Worker(new URL('./worker.js', import.meta.url), {
      workerData: { settings: this.settings, buffer },
      env: { TZ: 'UTC' },
      execArgv: [],
      stdout: true,
      stderr: true,
      resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
    });
    worker.stdout.resume();
    worker.stderr.resume();
    let exit!: () => void;
    const slot: Slot = {
      worker,
      header: new Int32Array(buffer, 0, 4),
      output: new Uint8Array(buffer, headerBytes),
      exited: new Promise<void>((resolve) => {
        exit = resolve;
      }),
      alive: true,
      available: false,
      retired: false,
    };
    this.slots.push(slot);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error?: KitError) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else {
          slot.available = true;
          resolve();
        }
      };
      const timer = setTimeout(() => {
        this.retire(slot);
        finish(failure('EK_TIMEOUT'));
      }, this.settings.timeoutMs);
      worker.on('error', () => {
        this.retire(slot);
        finish(failure('EK_BACKEND_UNAVAILABLE'));
      });
      worker.once('exit', () => {
        slot.alive = false;
        slot.available = false;
        slot.output.fill(0);
        exit();
        finish(failure('EK_BACKEND_UNAVAILABLE'));
      });
      worker.once('message', (value: unknown) => {
        if (
          value &&
          typeof value === 'object' &&
          'ready' in value &&
          value.ready === true &&
          !this.closed
        )
          finish();
        else {
          const code =
            value &&
            typeof value === 'object' &&
            'code' in value &&
            errorCodes.includes(value.code as never)
              ? (value.code as (typeof errorCodes)[number])
              : 'EK_BACKEND_UNAVAILABLE';
          this.retire(slot);
          finish(failure(code));
        }
      });
    });
  }
  private retire(slot: Slot): void {
    slot.retired = true;
    slot.available = false;
    void slot.worker.terminate().catch(() => undefined);
  }
  call(operation: Operation, input: unknown, id?: string, requested?: JsonOptions): unknown {
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!this.ready()) throw failure('EK_LIFECYCLE_STATE');
    const slot = this.slots.find((value) => value.available && value.alive && !value.retired);
    if (!slot) throw failure('EK_BACKEND_UNAVAILABLE');
    const limits = options(requested, {
      ...this.settings.defaults,
      maxBytes: Math.min(
        this.settings.defaults.maxBytes,
        operation === 'stringify' ? this.settings.maxOutputBytes : this.settings.maxInputBytes,
      ),
    });
    const started = performance.now(),
      deadline = started + this.settings.timeoutMs;
    const check = () => {
      if (performance.now() > deadline) throw failure('EK_TIMEOUT');
    };
    let inputBytes = 0,
      outputBytes = 0,
      heapBytes = 0,
      submitted = false,
      outcome: Measurement['outcome'] = 'error';
    slot.available = false;
    try {
      let text: string;
      if (operation === 'parse') {
        if (
          typeof input !== 'string' ||
          input.length > limits.maxBytes ||
          Buffer.byteLength(input) > limits.maxBytes
        )
          throw failure('EK_JSON_PARSE');
        text = input;
      } else
        text = stringify(
          input,
          {
            ...limits,
            maxBytes: Math.min(limits.maxBytes, this.settings.maxInputBytes),
            indentSpaces: 0,
          },
          check,
        );
      inputBytes = Buffer.byteLength(text);
      check();
      if (
        operation === 'validate' &&
        (typeof id !== 'string' || !Object.hasOwn(this.settings.schemas, id))
      )
        throw failure('EK_JSON_SCHEMA');
      if (
        operation === 'transform' &&
        (typeof id !== 'string' || !this.settings.mappings.some((value) => value.id === id))
      )
        throw failure('EK_JSON_TRANSFORM');
      slot.header.fill(0);
      slot.worker.postMessage({
        operation,
        text,
        ...(id === undefined ? {} : { id }),
        limits,
        timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())),
      });
      submitted = true;
      const result = Atomics.wait(slot.header, 0, 0, Math.max(0, deadline - performance.now()));
      if (result === 'timed-out' || performance.now() > deadline) {
        this.retire(slot);
        throw failure('EK_TIMEOUT');
      }
      const status = Atomics.load(slot.header, 0);
      if (status === 2)
        throw failure(errorCodes[Atomics.load(slot.header, 2)] ?? 'EK_BACKEND_UNAVAILABLE');
      const length = Atomics.load(slot.header, 1);
      if (status !== 1 || length < 1 || length > slot.output.length) {
        this.retire(slot);
        throw failure('EK_BACKEND_UNAVAILABLE');
      }
      const output = Buffer.from(slot.output.subarray(0, length)).toString('utf8');
      outputBytes = length;
      heapBytes = Atomics.load(slot.header, 3);
      const value =
        operation === 'stringify'
          ? output
          : parse(
              output,
              {
                maxBytes: this.settings.maxOutputBytes,
                maxDepth: Math.min(132, limits.maxDepth + 4),
                indentSpaces: 0,
              },
              check,
            );
      outcome = operation === 'validate' && !(value as JsonValidation).valid ? 'invalid' : 'ok';
      return value;
    } catch (error) {
      if (error instanceof KitError) {
        if (submitted && error.code === 'EK_TIMEOUT') this.retire(slot);
        throw error;
      }
      if (submitted) this.retire(slot);
      throw failure('EK_BACKEND_UNAVAILABLE');
    } finally {
      slot.output.fill(0);
      if (
        slot.alive &&
        !slot.retired &&
        !this.closed &&
        slot.worker.threadId !== -1 &&
        !(submitted && performance.now() > deadline)
      )
        slot.available = true;
      const mapping =
        operation === 'transform'
          ? this.settings.mappings.find((value) => value.id === id)
          : undefined;
      try {
        this.observe({
          operation,
          outcome,
          durationMs: performance.now() - started,
          inputBytes,
          outputBytes,
          heapBytes,
          ...(mapping ? { mappingId: mapping.id, mappingVersion: mapping.schemaVersion } : {}),
        });
      } catch {
        /* Observations cannot alter JSON outcomes. */
      }
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.detach();
    for (const slot of this.slots) this.retire(slot);
    this.closing = Promise.all(this.slots.map((slot) => slot.exited)).then(() => undefined);
    return this.closing;
  }
}
