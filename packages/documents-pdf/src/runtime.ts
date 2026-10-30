// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fork } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { constants, realpathSync } from 'node:fs';
import { open, lstat, readFile } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import type { Work } from './backend.js';
import type { Settings } from './settings.js';
import { builtins } from './settings.js';
import { fields, failure, integer } from './validation.js';

export function operation(input: OperationOptions | undefined, maximum: number) {
  const value = fields(input ?? {}, ['signal', 'timeoutMs']);
  let signal: AbortSignal | undefined;
  if (value.signal !== undefined) {
    try {
      signal = captureAbortSignal(value.signal);
    } catch {
      throw failure();
    }
  }
  return {
    signal,
    timeoutMs: integer(value.timeoutMs ?? maximum, maximum),
  };
}
function roots(): readonly string[] {
  const native = realpathSync(
      fileURLToPath(import.meta.resolve('pdfjs-dist/legacy/build/pdf.mjs')),
    ),
    marker = sep + 'node_modules' + sep,
    at = native.indexOf(marker),
    core = realpathSync(fileURLToPath(import.meta.resolve('@arkenivajs/core')));
  if (at < 0) throw failure();
  return [
    resolve(fileURLToPath(new URL('..', import.meta.url))),
    native.slice(0, at + marker.length - 1),
    resolve(dirname(core), '..'),
  ];
}
export async function validateRuntime(): Promise<string> {
  if (process.platform !== 'linux') throw failure('EK_CONFIG_INVALID');
  const limiter = '/usr/bin/prlimit',
    executable = await lstat(limiter);
  if (
    !executable.isFile() ||
    executable.isSymbolicLink() ||
    (executable.mode & 0o022) !== 0 ||
    (executable.mode & 0o111) === 0
  )
    throw failure('EK_CONFIG_INVALID');
  return limiter;
}
/** A finite native operation retains its slot until font reads and actual child exit have both completed. */
export class Request {
  readonly done: Promise<void>;
  readonly result: Promise<unknown>;
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #aborted: Promise<never>;
  readonly #signals: readonly AbortSignal[];
  readonly #abort: () => void;
  readonly #deadline: number;
  #reject!: (error: unknown) => void;
  #error: KitError | undefined;
  #child: ChildProcess | undefined;
  #value: unknown;
  #received = false;
  constructor(
    readonly settings: Settings,
    readonly work: Work,
    requested: OperationOptions | undefined,
    applicationSignal: AbortSignal,
    readonly observe: (value: {
      memoryBytes: number;
      durationMs: number;
      cpuMs: number;
      pages: number;
    }) => void = () => undefined,
  ) {
    const config = operation(requested, Math.min(settings.timeoutMs, work.limits.maxDecodeMs));
    this.#deadline = performance.now() + config.timeoutMs;
    this.#aborted = new Promise<never>((_resolve, reject) => {
      this.#reject = reject;
    });
    void this.#aborted.catch(() => undefined);
    this.#signals = [...new Set([applicationSignal, ...(config.signal ? [config.signal] : [])])];
    this.#abort = () => this.stop('EK_ABORTED');
    this.#timer = setTimeout(() => this.stop('EK_TIMEOUT'), config.timeoutMs);
    for (const signal of this.#signals)
      signal.addEventListener('abort', this.#abort, { once: true });
    if (this.#signals.some((signal) => signal.aborted)) this.stop('EK_ABORTED');
    this.done = this.#run()
      .catch((error: unknown) => {
        this.#error ??= error instanceof KitError ? error : failure();
      })
      .finally(() => {
        clearTimeout(this.#timer);
        for (const signal of this.#signals) signal.removeEventListener('abort', this.#abort);
        for (const value of work.inputs) value.fill(0);
      });
    this.result = Promise.race([
      this.done.then(() => {
        this.check();
        return this.#value;
      }),
      this.#aborted,
    ]);
    void this.result.catch(() => undefined);
  }
  check(): void {
    if (this.#error) throw this.#error;
    if (performance.now() >= this.#deadline) {
      this.stop('EK_TIMEOUT');
      throw this.#error;
    }
  }
  stop(code: ErrorCode): void {
    this.#error ??= failure(code);
    this.#reject(this.#error);
    this.#child?.kill('SIGKILL');
  }
  async #run() {
    const fonts: Record<string, Uint8Array> = Object.create(null);
    try {
      this.check();
      let total = 0;
      for (const name of new Set(this.work.specs.map((spec) => spec.font))) {
        if (!this.settings.fonts.includes(name)) throw failure();
        if (builtins.has(name)) continue;
        this.check();
        const entry = await lstat(name);
        this.check();
        if (!entry.isFile() || entry.isSymbolicLink()) throw failure();
        const file = await open(
          name,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        try {
          const before = await file.stat();
          this.check();
          if (
            !before.isFile() ||
            before.size < 1 ||
            before.size > 4 * 1024 * 1024 ||
            (before.mode & 0o022) !== 0 ||
            (total += before.size) > 16 * 1024 * 1024
          )
            throw failure('EK_PDF_LIMIT');
          const data = Buffer.alloc(before.size);
          fonts[name] = data;
          let position = 0;
          while (position < data.length) {
            const read = await file.read(data, position, data.length - position, position);
            this.check();
            if (!read.bytesRead) throw failure();
            position += read.bytesRead;
          }
          const after = await file.stat();
          if (
            after.size !== before.size ||
            after.mtimeMs !== before.mtimeMs ||
            after.ctimeMs !== before.ctimeMs
          )
            throw failure();
        } finally {
          await file.close();
        }
      }
      this.check();
      const limiter = await validateRuntime();
      this.check();
      const child = fork(new URL('./worker.js', import.meta.url), [], {
        execPath: limiter,
        execArgv: [
          '--data=1073741824:1073741824',
          '--core=0:0',
          '--',
          process.execPath,
          '--permission',
          '--allow-addons',
          ...roots().map((root) => '--allow-fs-read=' + root),
          '--max-old-space-size=512',
          '--max-semi-space-size=8',
        ],
        env: {
          LANG: 'C.UTF-8',
          TZ: 'UTC',
          NODE_ENV: 'production',
          UV_THREADPOOL_SIZE: '1',
          DISABLE_SYSTEM_FONTS_LOAD: '1',
        },
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        serialization: 'advanced',
      });
      this.#child = child;
      let live = true,
        sampling: Promise<void> | undefined;
      const memoryLimit = Math.min(
        512 * 1024 * 1024,
        256 * 1024 * 1024 + this.work.limits.maxBytes * 2,
      );
      const monitor = setInterval(() => {
        if (!live || sampling || !child.pid || process.platform !== 'linux') return;
        sampling = readFile('/proc/' + child.pid + '/status', 'utf8')
          .then((value) => {
            if (!live) return;
            const match = /^VmRSS:\s+([0-9]+)\s+kB$/m.exec(value);
            // Linux may release the memory descriptor before the child close event is delivered.
            if (!match) return;
            if (Number(match[1]) * 1024 > memoryLimit) this.stop('EK_PDF_LIMIT');
          })
          .catch((error: unknown) => {
            if (
              live &&
              !(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')
            )
              this.stop('EK_PDF_PARSE');
          })
          .finally(() => {
            sampling = undefined;
          });
      }, 10);
      const exited = new Promise<void>((resolveExit) => {
        child.on('error', () => this.stop('EK_PDF_PARSE'));
        child.on('message', (raw: unknown) => {
          try {
            const message = fields(raw, [
              'type',
              'value',
              'code',
              'memoryBytes',
              'durationMs',
              'cpuMs',
              'pages',
            ]);
            if (this.#received) throw failure();
            this.#received = true;
            if (message.type === 'error') {
              if (
                !['EK_PDF_PARSE', 'EK_PDF_LIMIT', 'EK_PDF_SIGNED'].includes(message.code as string)
              )
                throw failure();
              this.#error ??= failure(message.code as ErrorCode);
            } else if (message.type === 'result') {
              this.check();
              const memoryBytes = integer(message.memoryBytes, Number.MAX_SAFE_INTEGER);
              if (
                ![message.durationMs, message.cpuMs].every(
                  (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0,
                )
              )
                throw failure();
              this.#value = message.value;
              this.observe({
                memoryBytes,
                pages: integer(message.pages, this.work.limits.maxPages),
                durationMs: message.durationMs as number,
                cpuMs: message.cpuMs as number,
              });
            } else throw failure();
          } catch {
            this.stop('EK_PDF_PARSE');
          }
        });
        child.once('close', (code) => {
          live = false;
          clearInterval(monitor);
          if (code !== 0 || !this.#received) this.#error ??= failure();
          resolveExit();
        });
      });
      try {
        this.check();
        child.send({ ...this.work, fonts }, (error) => {
          if (error) this.stop('EK_PDF_PARSE');
        });
      } catch {
        this.stop('EK_PDF_PARSE');
      }
      await exited;
      await sampling;
    } finally {
      for (const value of Object.values(fonts)) value.fill(0);
    }
  }
}
