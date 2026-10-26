// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Readable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { failure, fields, integer } from './policy.js';

/** A public timeout never releases a physical reservation while owned application work is pending. */
export class RequestScope {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly started = performance.now();
  readonly deadline: number;
  readonly pending = new Set<Promise<unknown>>();
  readonly streams = new Set<Readable>();
  error: KitError | undefined;
  bytes = 0;
  files = 0;
  parts = 0;
  exhausted = false;
  finished = false;
  private released = false;
  private readonly cleanup: (() => void)[] = [];
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly disconnected: () => void;
  private readonly responseClosed: () => void;
  private readonly aborted: () => void;

  constructor(
    readonly request: FastifyRequest,
    readonly reply: FastifyReply,
    owner: AbortSignal,
    timeoutMs: number,
    private readonly release: () => void,
  ) {
    this.deadline = this.started + timeoutMs;
    this.signal = AbortSignal.any([owner, this.controller.signal]);
    this.disconnected = () => {
      this.fail('EK_UPLOAD_TRUNCATED');
      this.finish();
    };
    this.responseClosed = () => {
      if (!reply.raw.writableEnded) {
        this.fail('EK_ABORTED');
        this.finish();
      }
    };
    this.aborted = () => {
      if (!this.error) this.error = failure('EK_ABORTED');
      for (const stream of this.streams) stream.destroy(this.error);
    };
    request.raw.once('aborted', this.disconnected);
    reply.raw.once('close', this.responseClosed);
    this.signal.addEventListener('abort', this.aborted, { once: true });
    this.timer = setTimeout(() => this.fail('EK_TIMEOUT'), timeoutMs);
    if (this.signal.aborted) this.aborted();
  }
  fail(code: ErrorCode): KitError {
    this.error ??= failure(code);
    this.controller.abort();
    return this.error;
  }
  check(): void {
    if (this.error) throw this.error;
    if (this.signal.aborted) throw this.fail('EK_ABORTED');
    if (performance.now() >= this.deadline) throw this.fail('EK_TIMEOUT');
  }
  options(): OperationOptions {
    this.check();
    return {
      signal: this.signal,
      timeoutMs: Math.max(1, Math.ceil(this.deadline - performance.now())),
    };
  }
  watch<T>(task: Promise<T>): Promise<T> {
    this.pending.add(task);
    void task.then(
      () => {
        this.pending.delete(task);
        this.tryRelease();
      },
      () => {
        this.pending.delete(task);
        this.tryRelease();
      },
    );
    return task;
  }
  async run<T>(work: () => Promise<T> | T): Promise<T> {
    const options = this.options();
    const task = this.watch(
      Promise.resolve().then(() => {
        this.check();
        return work();
      }),
    );
    try {
      const result = await within(() => task, options);
      this.check();
      return result;
    } catch (cause) {
      throw this.translate(cause);
    }
  }
  stream(stream: Readable): void {
    if (stream.closed) return;
    this.streams.add(stream);
    stream.on('error', () => {
      /* The iterator or wire guard reports a sanitized error. */
    });
    stream.once('close', () => {
      this.streams.delete(stream);
      this.tryRelease();
    });
  }
  translate(cause: unknown): KitError {
    if (this.error) return this.error;
    try {
      if (cause instanceof KitError) return this.fail(cause.code);
      const code =
        cause && typeof cause === 'object'
          ? Object.getOwnPropertyDescriptor(cause, 'code')?.value
          : undefined;
      return this.fail(
        typeof code === 'string' && /LIMIT|TOO_LARGE/.test(code)
          ? 'EK_UPLOAD_LIMIT'
          : 'EK_UPLOAD_TRUNCATED',
      );
    } catch {
      return this.fail('EK_UPLOAD_STREAM');
    }
  }
  onCleanup(work: () => void): void {
    this.cleanup.push(work);
  }
  finish(): void {
    if (this.finished) return;
    this.finished = true;
    clearTimeout(this.timer);
    for (const work of this.cleanup) work();
    this.cleanup.length = 0;
    if (this.error) this.request.raw.destroy();
    this.request.raw.off('aborted', this.disconnected);
    this.reply.raw.off('close', this.responseClosed);
    if (this.error) for (const stream of this.streams) stream.destroy(this.error);
    this.tryRelease();
  }
  private tryRelease(): void {
    if (this.released || !this.finished || this.pending.size || this.streams.size) return;
    this.released = true;
    this.signal.removeEventListener('abort', this.aborted);
    this.release();
  }
}

/** Discard may tighten the shared deadline and add cancellation; it cannot weaken request limits. */
export function discardOptions(
  input: OperationOptions | undefined,
  scope: RequestScope,
): OperationOptions {
  const value = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']);
  const timeoutMs = value.timeoutMs === undefined ? undefined : integer(value.timeoutMs, 120000);
  const signal =
    value.signal === undefined
      ? scope.signal
      : AbortSignal.any([scope.signal, captureAbortSignal(value.signal)]);
  const remaining = scope.options().timeoutMs!;
  return { signal, timeoutMs: Math.min(remaining, timeoutMs ?? remaining) };
}
