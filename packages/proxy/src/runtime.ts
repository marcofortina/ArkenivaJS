// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Transform, Readable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { ProxyRouteConfig } from './contracts.js';
import { failure } from './policy.js';

export function translated(error: unknown, depth = 0): KitError {
  if (error instanceof KitError && error.code === 'EK_TIMEOUT') return failure('EK_PROXY_TIMEOUT');
  if (
    error instanceof KitError &&
    [
      'EK_PROXY_POLICY',
      'EK_PROXY_TIMEOUT',
      'EK_PROXY_BODY_LIMIT',
      'EK_AUTH_REQUIRED',
      'EK_AUTH_INVALID',
      'EK_AUTH_FORBIDDEN',
      'EK_RESOURCE_CLOSED',
      'EK_ABORTED',
      'EK_BACKEND_UNAVAILABLE',
    ].includes(error.code)
  )
    return failure(error.code);
  const code =
    error && typeof error === 'object'
      ? Object.getOwnPropertyDescriptor(error, 'code')?.value
      : undefined;
  if (typeof code === 'string' && (code.includes('TIMEOUT') || code === 'ETIMEDOUT'))
    return failure('EK_PROXY_TIMEOUT');
  if (code === 'FST_ERR_CTP_BODY_TOO_LARGE') return failure('EK_PROXY_BODY_LIMIT');
  if (depth < 4 && error && typeof error === 'object') {
    const cause = Object.getOwnPropertyDescriptor(error, 'cause')?.value;
    if (cause !== undefined && cause !== error) return translated(cause, depth + 1);
  }
  return failure('EK_PROXY_UPSTREAM');
}
export function status(code: string): number {
  if (code === 'EK_PROXY_POLICY' || code === 'EK_AUTH_FORBIDDEN') return 403;
  if (code === 'EK_AUTH_REQUIRED' || code === 'EK_AUTH_INVALID') return 401;
  if (code === 'EK_PROXY_BODY_LIMIT') return 413;
  if (code === 'EK_PROXY_TIMEOUT') return 504;
  if (code === 'EK_RESOURCE_CLOSED' || code === 'EK_BACKEND_UNAVAILABLE') return 503;
  if (code === 'EK_ABORTED') return 400;
  return 502;
}
/** A scope retains admission until its real provider and body streams have settled. */
export class Scope {
  readonly controller = new AbortController();
  readonly started = performance.now();
  readonly completion: Promise<void>;
  readonly upstreamCompletion: Promise<void>;
  readonly streams = new Set<Readable>();
  readonly pending = new Set<Promise<unknown>>();
  error: KitError | undefined;
  requestBytes = 0;
  responseBytes = 0;
  credential: string | undefined;
  forwarded = false;
  private publicDone = false;
  private released = false;
  private resolveCompletion!: () => void;
  private resolveUpstream!: () => void;
  private readonly timer: ReturnType<typeof setTimeout>;
  private readonly disconnected: () => void;
  private readonly responseClosed: () => void;
  constructor(
    readonly request: FastifyRequest,
    readonly reply: FastifyReply,
    readonly route: ProxyRouteConfig,
    private readonly release: () => void,
    private readonly bytes: (side: 'request' | 'response', count: number) => void,
  ) {
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    this.upstreamCompletion = new Promise((resolve) => {
      this.resolveUpstream = resolve;
    });
    this.disconnected = () => {
      this.fail('EK_ABORTED');
      this.finish();
    };
    this.responseClosed = () => {
      if (!reply.raw.writableFinished) this.fail('EK_ABORTED');
      this.finish();
    };
    request.raw.once('aborted', this.disconnected);
    reply.raw.once('close', this.responseClosed);
    this.timer = setTimeout(() => {
      this.fail('EK_PROXY_TIMEOUT');
      this.respond();
    }, route.timeoutMs);
  }
  check(): void {
    if (this.error) throw this.error;
    if (this.controller.signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() - this.started >= this.route.timeoutMs)
      throw this.fail('EK_PROXY_TIMEOUT');
  }
  options(): OperationOptions {
    this.check();
    return {
      signal: this.controller.signal,
      timeoutMs: Math.max(1, Math.ceil(this.route.timeoutMs - (performance.now() - this.started))),
    };
  }
  watch<T>(task: Promise<T>): Promise<T> {
    this.pending.add(task);
    const settled = () => {
      this.pending.delete(task);
      this.tryRelease();
    };
    void task.then(settled, settled);
    return task;
  }
  async run<T>(work: () => Promise<T>): Promise<T> {
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
    } catch (error) {
      throw this.fail(
        error instanceof KitError && error.code === 'EK_TIMEOUT'
          ? 'EK_PROXY_TIMEOUT'
          : translated(error).code,
      );
    }
  }
  fail(code: ErrorCode): KitError {
    this.error ??= failure(code);
    this.controller.abort();
    for (const stream of this.streams) stream.destroy(this.error);
    this.resolveUpstream();
    return this.error;
  }
  respond(): void {
    const error = this.error ?? this.fail('EK_PROXY_UPSTREAM');
    if (this.reply.raw.headersSent) {
      this.reply.raw.destroy();
      this.finish();
    } else if (!this.reply.sent) {
      this.reply.removeHeader('content-length');
      this.reply.removeHeader('content-encoding');
      this.reply.removeHeader('location');
      void this.reply
        .code(status(error.code))
        .send({ error: { code: error.code, message: error.message } });
    }
  }
  stream(stream: Readable): void {
    this.streams.add(stream);
    stream.on('error', () => {
      /* The owning wire guard emits only a fixed public error. */
    });
    stream.once('close', () => {
      this.streams.delete(stream);
      this.tryRelease();
    });
  }
  limiter(side: 'request' | 'response'): Transform {
    const maximum = side === 'request' ? this.route.maxRequestBytes : this.route.maxResponseBytes;
    const transform = new Transform({
      highWaterMark: 16384,
      transform: (chunk: Buffer, _encoding, done) => {
        const count = Buffer.byteLength(chunk);
        if (side === 'request') this.requestBytes += count;
        else this.responseBytes += count;
        this.bytes(side, count);
        try {
          this.check();
          if ((side === 'request' ? this.requestBytes : this.responseBytes) > maximum)
            throw this.fail('EK_PROXY_BODY_LIMIT');
          done(null, chunk);
        } catch (error) {
          done(translated(error));
        }
      },
    });
    if (side === 'request')
      Object.defineProperty(transform, 'receivedEncodedLength', { get: () => this.requestBytes });
    this.stream(transform);
    return transform;
  }
  upstreamEnded(): void {
    this.resolveUpstream();
  }
  finish(): void {
    this.publicDone = true;
    clearTimeout(this.timer);
    this.controller.abort();
    for (const stream of this.streams) if (!stream.readableEnded) stream.destroy();
    this.credential = undefined;
    this.tryRelease();
  }
  private tryRelease(): void {
    if (this.released || !this.publicDone || this.pending.size || this.streams.size) return;
    this.released = true;
    this.request.raw.off('aborted', this.disconnected);
    this.reply.raw.off('close', this.responseClosed);
    this.release();
    this.resolveUpstream();
    this.resolveCompletion();
  }
}
