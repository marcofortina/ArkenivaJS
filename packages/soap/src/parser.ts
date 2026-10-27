// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import { deserialize } from 'node:v8';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import { errorCodes, headerBytes } from './protocol.js';
import type { ParserSettings } from './protocol.js';
import { failure } from './validation.js';

/** The approved native parser runs in an owned worker with an enforceable synchronous deadline. */
export class NativeParser {
  readonly worker: Worker;
  readonly exited: Promise<void>;
  private readonly header: Int32Array;
  private readonly output: Uint8Array;
  private retired = false;
  private closing: Promise<void> | undefined;
  private detach: () => void = () => undefined;
  private constructor(readonly settings: ParserSettings) {
    const buffer = new SharedArrayBuffer(headerBytes + 8388608);
    this.header = new Int32Array(buffer, 0, 4);
    this.output = new Uint8Array(buffer, headerBytes);
    this.worker = new Worker(new URL('./parser-worker.js', import.meta.url), {
      workerData: { settings, buffer },
      env: { TZ: 'UTC' },
      execArgv: [],
      stdout: true,
      stderr: true,
      resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
    });
    this.worker.stdout.resume();
    this.worker.stderr.resume();
    this.exited = new Promise<void>((resolve) =>
      this.worker.once('exit', () => {
        this.retired = true;
        this.output.fill(0);
        this.detach();
        resolve();
      }),
    );
  }
  static async create(settings: ParserSettings, signal: AbortSignal): Promise<NativeParser> {
    if (
      !Number.isInteger(settings.timeoutMs) ||
      settings.timeoutMs < 1 ||
      settings.timeoutMs > 60000 ||
      !Number.isInteger(settings.maxBytes) ||
      settings.maxBytes < 1 ||
      settings.maxBytes > 8388608 ||
      !['1.1', '1.2'].includes(settings.protocol) ||
      typeof settings.source !== 'string' ||
      settings.source.length > 1048576 ||
      Buffer.byteLength(settings.source) > 1048576
    )
      throw failure('EK_CONFIG_INVALID');
    if (signal.aborted) throw failure('EK_ABORTED');
    const parser = new NativeParser(Object.freeze({ ...settings }));
    const abort = () => {
      void parser.close();
    };
    signal.addEventListener('abort', abort, { once: true });
    parser.detach = () => signal.removeEventListener('abort', abort);
    try {
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (error?: KitError) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (error) reject(error);
          else resolve();
        };
        const timer = setTimeout(() => {
          void parser.close();
          finish(failure('EK_TIMEOUT'));
        }, settings.timeoutMs);
        parser.worker.on('error', () => {
          void parser.close();
          finish(failure('EK_BACKEND_UNAVAILABLE'));
        });
        parser.worker.once('exit', () =>
          finish(failure(signal.aborted ? 'EK_ABORTED' : 'EK_BACKEND_UNAVAILABLE')),
        );
        parser.worker.once('message', (message: unknown) => {
          if (signal.aborted || parser.retired) return finish(failure('EK_ABORTED'));
          if (
            message &&
            typeof message === 'object' &&
            'ready' in message &&
            message.ready === true
          )
            finish();
          else {
            const code =
              message &&
              typeof message === 'object' &&
              'code' in message &&
              errorCodes.includes(message.code as never)
                ? (message.code as (typeof errorCodes)[number])
                : 'EK_BACKEND_UNAVAILABLE';
            finish(failure(code));
          }
        });
      });
      return parser;
    } catch (error) {
      await parser.close();
      throw error;
    }
  }
  parse(source: string, timeoutMs = this.settings.timeoutMs): unknown {
    if (this.retired || this.worker.threadId === -1) throw failure('EK_RESOURCE_CLOSED');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > this.settings.timeoutMs)
      throw failure('EK_CONFIG_INVALID');
    if (
      typeof source !== 'string' ||
      source.length > this.settings.maxBytes ||
      Buffer.byteLength(source) > this.settings.maxBytes
    )
      throw failure('EK_SOAP_SCHEMA');
    const deadline = performance.now() + timeoutMs;
    this.header.fill(0);
    this.worker.postMessage(source);
    const status = Atomics.wait(this.header, 0, 0, Math.max(0, deadline - performance.now()));
    if (status === 'timed-out' || performance.now() > deadline) {
      void this.close();
      throw failure('EK_TIMEOUT');
    }
    if (Atomics.load(this.header, 0) === 2)
      throw failure(errorCodes[Atomics.load(this.header, 2)] ?? 'EK_BACKEND_UNAVAILABLE');
    const length = Atomics.load(this.header, 1);
    if (Atomics.load(this.header, 0) !== 1 || length < 1 || length > this.output.length) {
      void this.close();
      throw failure('EK_BACKEND_UNAVAILABLE');
    }
    let result: unknown;
    try {
      result = deserialize(Buffer.from(this.output.subarray(0, length)));
    } catch {
      void this.close();
      throw failure('EK_BACKEND_UNAVAILABLE');
    } finally {
      this.output.fill(0);
    }
    if (performance.now() > deadline) {
      void this.close();
      throw failure('EK_TIMEOUT');
    }
    return result;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.retired = true;
    this.detach();
    void this.worker.terminate().catch(() => undefined);
    this.closing = this.exited;
    return this.closing;
  }
}
