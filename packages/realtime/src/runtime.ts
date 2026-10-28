// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import type { FastifyRequest, FastifyReply } from 'fastify';
import type { AuthService, OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { RealtimePolicy } from './contracts.js';
import type { Settings } from './settings.js';
import type { RequestIdentity } from './identity.js';
import { authenticate, sameIdentity } from './identity.js';
import { failure } from './validation.js';
import type { Observation, DisconnectReason } from './observation.js';

/** A disconnected stream still retains capacity while its provider ignores cancellation. */
export class Connection {
  readonly controller = new AbortController();
  readonly signal: AbortSignal;
  readonly pending = new Set<Promise<unknown>>();
  readonly completion: Promise<void>;
  readonly started = performance.now();
  lastActivity = this.started;
  sentBytes = 0;
  receivedBytes = 0;
  private closed = false;
  private released = false;
  private resolveCompletion!: () => void;
  private timer: ReturnType<typeof setInterval> | undefined;
  private authorization: Promise<void> | undefined;
  private wireClose: ((force: boolean) => void) | undefined;
  private wireDone = false;
  private buffered: (() => number) | undefined;
  private queued = 0;
  private reason: DisconnectReason = 'closed';
  private readonly disconnected: () => void;
  private readonly aborted: () => void;
  constructor(
    readonly request: FastifyRequest,
    readonly reply: FastifyReply,
    readonly tenant: VerifiedTenantContext,
    readonly policy: RealtimePolicy,
    private readonly settings: Settings,
    private readonly auth: AuthService,
    private readonly snapshot: RequestIdentity,
    owner: AbortSignal,
    private readonly release: () => void,
    private readonly observation: Observation,
    private readonly protocol: 'websocket' | 'sse',
  ) {
    this.signal = AbortSignal.any([owner, this.controller.signal]);
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    this.disconnected = () => {
      this.wireDone = true;
      this.close();
      this.tryRelease();
    };
    this.aborted = () => this.close(true, owner.aborted ? 'shutdown' : 'closed');
    request.raw.once('aborted', this.disconnected);
    reply.raw.once('close', this.disconnected);
    this.signal.addEventListener('abort', this.aborted, { once: true });
    this.observation.connected(protocol);
  }
  attach(close: (force: boolean) => void, buffered: () => number): void {
    this.wireClose = close;
    this.buffered = buffered;
    this.timer = setInterval(() => {
      if (this.closed) return;
      this.sampleQueue();
      if (buffered() > this.policy.maxBufferBytes) {
        this.close(true, 'backpressure');
        return;
      }
      if (performance.now() - this.lastActivity >= this.policy.idleTimeoutMs) {
        this.close(true, 'idle');
        return;
      }
      void this.reauthorize().catch(() => this.close(true, 'authorization'));
    }, this.policy.heartbeatMs);
    this.timer.unref();
    if (this.signal.aborted) this.close();
  }
  check(): void {
    if (this.closed || this.signal.aborted) throw failure('EK_REALTIME_CLOSED');
  }
  options(): OperationOptions {
    this.check();
    return { signal: this.signal, timeoutMs: this.settings.runtime.timeoutMs };
  }
  get operationTimeoutMs(): number {
    return this.settings.runtime.timeoutMs;
  }
  get inputLimit(): number {
    return Math.min(this.policy.maxMessageBytes, this.settings.runtime.maxInputBytes);
  }
  get outputLimit(): number {
    return Math.min(this.policy.maxMessageBytes, this.settings.runtime.maxOutputBytes);
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
  wait<T>(task: Promise<T>): Promise<T> {
    this.check();
    return new Promise<T>((resolve, reject) => {
      const aborted = () => {
        cleanup();
        reject(failure('EK_REALTIME_CLOSED'));
      };
      const cleanup = () => this.signal.removeEventListener('abort', aborted);
      this.signal.addEventListener('abort', aborted, { once: true });
      void task.then(
        (value) => {
          cleanup();
          resolve(value);
        },
        (error) => {
          cleanup();
          reject(error);
        },
      );
      if (this.signal.aborted) aborted();
    });
  }
  wireClosed(): void {
    this.wireDone = true;
    this.close();
    this.tryRelease();
  }
  async run<T>(work: () => Promise<T>, timeoutMs = this.settings.runtime.timeoutMs): Promise<T> {
    this.check();
    const task = this.watch(
      Promise.resolve().then(() => {
        this.check();
        return work();
      }),
    );
    const result = await within(() => task, { timeoutMs, signal: this.signal });
    this.check();
    return result;
  }
  reauthorize(): Promise<void> {
    if (this.authorization) return this.authorization;
    const task = this.run(async () => {
      const current = await authenticate(this.auth, this.settings, this.snapshot, this.options());
      if (!sameIdentity(current, this.tenant)) throw failure('EK_REALTIME_AUTH');
    });
    this.authorization = task;
    void task.then(
      () => {
        this.authorization = undefined;
      },
      () => {
        this.authorization = undefined;
      },
    );
    return task;
  }
  activity(bytes: number, side: 'send' | 'receive'): void {
    this.lastActivity = performance.now();
    if (side === 'send') this.sentBytes += bytes;
    else this.receivedBytes += bytes;
    this.observation.bytes(this.protocol, side, bytes);
    this.sampleQueue();
  }
  private sampleQueue(): void {
    const current = this.buffered?.() ?? 0;
    this.observation.queue(this.protocol, current - this.queued);
    this.queued = current;
  }
  close(force = true, reason: DisconnectReason = 'closed'): void {
    if (this.closed) return;
    this.closed = true;
    this.reason = reason;
    this.controller.abort();
    if (this.timer) clearInterval(this.timer);
    this.request.raw.off('aborted', this.disconnected);
    this.signal.removeEventListener('abort', this.aborted);
    try {
      this.wireClose?.(force);
    } finally {
      this.tryRelease();
    }
  }
  private tryRelease(): void {
    if (this.released || !this.closed || !this.wireDone || this.pending.size) return;
    this.released = true;
    this.reply.raw.off('close', this.disconnected);
    this.release();
    this.observation.queue(this.protocol, -this.queued);
    this.observation.disconnected(this.protocol, this.reason);
    this.resolveCompletion();
  }
}
