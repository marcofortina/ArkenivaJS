// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { TextDecoder } from 'node:util';
import { Range } from 'etcd3';
import type { IDuplexStream, IWatchRequest, IWatchResponse } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { EtcdWatchEvent, EtcdWatchHandle, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { EtcdConfiguration } from './config.js';
import { etcdInteger, etcdOptions } from './common.js';
import { etcdError, permanentEtcdError } from './errors.js';
import { ETCD_LIMITS } from './limits.js';
import { EtcdTransport } from './transport.js';

interface Stream {
  readonly native: IDuplexStream<IWatchRequest, IWatchResponse>;
  readonly ended: Promise<void>;
  readonly finish: () => void;
}
interface Waiting {
  readonly resolve: (value: IteratorResult<EtcdWatchEvent>) => void;
  readonly reject: (cause: unknown) => void;
}

/** Bounded prefix iteration uses the selected SDK's exported watch RPC and exact decimal cursors. */
export class EtcdWatch implements EtcdWatchHandle, AsyncIterator<EtcdWatchEvent> {
  private readonly controller = new AbortController();
  private readonly signal: AbortSignal;
  private readonly transport: EtcdTransport;
  private readonly queued: { event: EtcdWatchEvent; bytes: number }[] = [];
  private readonly ready: Promise<void>;
  private readyResolve!: () => void;
  private readyReject!: (cause: unknown) => void;
  private waiting: Waiting | undefined;
  private current: Stream | undefined;
  private connecting: Promise<void> | undefined;
  private closing: Promise<void> | undefined;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  private heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
  private recoveryTimer: ReturnType<typeof setTimeout> | undefined;
  private cursor: bigint | undefined;
  private closed = false;
  private failure: KitError | undefined;
  private queueBytes = 0;
  private lastResponse = performance.now();
  private retries = 0;

  constructor(
    private readonly configuration: EtcdConfiguration,
    private readonly prefix: string,
    lifetime: AbortSignal,
    caller: AbortSignal | undefined,
    private readonly onReconnect: () => void,
    private readonly onClosed: (failure?: unknown) => void,
  ) {
    this.signal = AbortSignal.any([this.controller.signal, lifetime, ...(caller ? [caller] : [])]);
    this.transport = new EtcdTransport(configuration, this.signal);
    this.ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    void this.ready.catch(() => undefined);
    this.signal.addEventListener('abort', this.aborted, { once: true });
  }

  private readonly aborted = () => {
    if (!this.closed)
      this.fail(
        new KitError({
          code: 'EK_ABORTED',
          message: 'etcd watch aborted',
          cause: this.signal.reason,
        }),
      );
  };

  /** The setup budget does not impose a hidden expiry on a successfully opened watch. */
  async open(input?: OperationOptions): Promise<this> {
    if (this.closed)
      throw (
        this.failure ??
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd watch is closed' })
      );
    const captured = etcdOptions(input);
    if (this.signal.aborted) this.aborted();
    if (!this.closed && !this.connecting) this.launch();
    try {
      await within(() => this.ready, captured);
      return this;
    } catch (cause) {
      this.fail(etcdError(cause));
      try {
        await this.close();
      } catch (cleanup) {
        const error = etcdError(cause);
        throw new KitError({
          code: error.code,
          message: 'etcd watch setup and cleanup failed',
          cause: new AggregateError([cause, cleanup]),
          details: error.details,
        });
      }
      throw cause;
    }
  }

  private async connect(): Promise<void> {
    try {
      const native = await this.transport.client.watchClient.watch();
      let finish!: () => void;
      const record: Stream = {
        native,
        ended: new Promise<void>((resolve) => {
          finish = resolve;
        }),
        finish: () => finish(),
      };
      native.on('error', (cause) => {
        record.finish();
        this.disconnected(record, cause);
      });
      native.on('end', () => {
        record.finish();
        this.disconnected(record, new Error('etcd watch stream ended'));
      });
      native.on('status', record.finish);
      native.on('data', (response) => {
        if (this.closed || this.current !== record) return;
        try {
          this.receive(record, response);
        } catch (cause) {
          this.fail(etcdError(cause));
        }
      });
      if (this.closed) {
        native.cancel();
        await within(() => record.ended, { timeoutMs: ETCD_LIMITS.cleanupMs });
        return;
      }
      this.current = record;
      const range = Range.prefix(Buffer.from(this.prefix));
      native.write({
        create_request: {
          key: range.start,
          range_end: range.end,
          progress_notify: true,
          fragment: true,
          ...(this.cursor === undefined ? {} : { start_revision: this.cursor.toString() }),
        },
      });
    } catch (cause) {
      if (this.closed) throw cause;
      this.disconnected(undefined, cause);
    }
  }

  private launch(): void {
    this.connecting = this.connect();
    void this.connecting.catch(() => undefined);
  }

  private receive(record: Stream, response: IWatchResponse): void {
    if (
      !response ||
      typeof response !== 'object' ||
      !response.header ||
      !Array.isArray(response.events)
    )
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'etcd returned an invalid watch response',
      });
    this.lastResponse = performance.now();
    const compacted = etcdInteger(response.compact_revision, true);
    if (response.canceled || compacted > 0n)
      throw new KitError({
        code: 'EK_KV_CONFLICT',
        message: 'etcd watch history is unavailable',
        details: { watchGap: true, compactedRevision: compacted.toString() },
      });
    const revision = etcdInteger(response.header.revision);
    if (response.created) {
      // A resumed create acknowledgment can describe a newer head than the pending replay.
      if (this.cursor === undefined) this.cursor = revision + 1n;
      this.readyResolve();
      record.native.write({ progress_request: {} });
      this.heartbeat();
      return;
    }
    for (const item of response.events) {
      if (
        !item?.kv ||
        !['Put', 'Delete'].includes(String(item.type)) ||
        !Buffer.isBuffer(item.kv.key)
      )
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd returned an invalid watch event',
        });
      const key = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(item.kv.key);
      if (!key.startsWith(this.prefix))
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd watch returned a key outside its range',
        });
      const event: EtcdWatchEvent = Object.freeze({
        type: item.type === 'Put' ? 'put' : 'delete',
        key: key.slice(this.configuration.prefix.length),
        revision: etcdInteger(item.kv.mod_revision),
        ...(item.type === 'Put' ? { value: this.value(item.kv.value) } : {}),
      });
      const bytes = Buffer.byteLength(event.key) + (event.value?.byteLength ?? 0) + 32;
      if (this.waiting) {
        const waiter = this.waiting;
        this.waiting = undefined;
        waiter.resolve({ done: false, value: event });
      } else {
        if (
          this.queued.length >= ETCD_LIMITS.watchEvents ||
          this.queueBytes + bytes > ETCD_LIMITS.watchBytes
        )
          throw new KitError({
            code: 'EK_KV_CONFLICT',
            message: 'etcd watch consumer capacity is exhausted',
            details: { watchGap: true, limitExceeded: true },
          });
        this.queued.push({ event, bytes });
        this.queueBytes += bytes;
      }
    }
    if (!response.fragment) {
      const next = revision + 1n;
      if (this.cursor === undefined || next > this.cursor) this.cursor = next;
      this.retries = 0;
      if (this.recoveryTimer) clearTimeout(this.recoveryTimer);
      this.recoveryTimer = undefined;
    }
  }

  private value(value: unknown): Uint8Array {
    if (!Buffer.isBuffer(value) || value.length > ETCD_LIMITS.valueBytes)
      throw new KitError({
        code: 'EK_KV_CONFLICT',
        message: 'etcd watch value exceeds the portable byte limit',
        details: { watchGap: true, limitExceeded: true },
      });
    return Uint8Array.from(value);
  }

  private disconnected(record: Stream | undefined, cause: unknown): void {
    if (this.closed || (record !== undefined && this.current !== record)) return;
    this.current = undefined;
    if (record) {
      try {
        record.native.cancel();
      } catch (cleanup) {
        this.fail(
          new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd watch disconnect cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          }),
        );
        return;
      }
    }
    if (this.heartbeatTimer) clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    if (permanentEtcdError(cause)) {
      this.fail(etcdError(cause));
      return;
    }
    if (!this.recoveryTimer)
      this.recoveryTimer = setTimeout(
        () =>
          this.fail(
            new KitError({
              code: 'EK_TIMEOUT',
              message: 'etcd watch recovery budget expired',
              cause,
            }),
          ),
        ETCD_LIMITS.timeoutMs,
      );
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(
      () => {
        this.reconnectTimer = undefined;
        if (!this.closed) {
          try {
            this.onReconnect();
          } catch {
            /* Diagnostics do not control watch recovery. */
          }
          this.launch();
        }
      },
      Math.min(100 * 2 ** Math.min(this.retries++, 4), 1000),
    );
  }

  private heartbeat(): void {
    if (this.heartbeatTimer) clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = setTimeout(() => {
      this.heartbeatTimer = undefined;
      const record = this.current;
      if (this.closed || !record) return;
      try {
        if (performance.now() - this.lastResponse >= ETCD_LIMITS.timeoutMs)
          this.disconnected(record, new Error('etcd watch progress timed out'));
        else {
          record.native.write({ progress_request: {} });
          this.heartbeat();
        }
      } catch (cause) {
        this.disconnected(record, cause);
      }
    }, 5000);
  }

  private fail(cause: KitError): void {
    if (this.closed) return;
    this.failure = cause;
    void this.close().catch(() => undefined);
  }

  next(): Promise<IteratorResult<EtcdWatchEvent>> {
    if (this.failure) return Promise.reject(this.failure);
    const first = this.queued.shift();
    if (first) {
      this.queueBytes -= first.bytes;
      return Promise.resolve({ done: false, value: first.event });
    }
    if (this.closed) return Promise.resolve({ done: true, value: undefined });
    if (this.waiting)
      return Promise.reject(
        new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'etcd watch supports one pending iterator read',
        }),
      );
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
    });
  }

  [Symbol.asyncIterator](): AsyncIterator<EtcdWatchEvent> {
    return this;
  }
  async return(): Promise<IteratorResult<EtcdWatchEvent>> {
    await this.close();
    return { done: true, value: undefined };
  }

  /** Close the owned stream/client once; late connection promises remain observed. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    for (const timer of [this.reconnectTimer, this.heartbeatTimer, this.recoveryTimer])
      if (timer) clearTimeout(timer);
    this.signal.removeEventListener('abort', this.aborted);
    this.readyReject(
      this.failure ??
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd watch closed before readiness' }),
    );
    if (this.waiting) {
      if (this.failure) this.waiting.reject(this.failure);
      else this.waiting.resolve({ done: true, value: undefined });
      this.waiting = undefined;
    }
    this.queued.length = 0;
    this.queueBytes = 0;
    this.controller.abort();
    this.closing = (async () => {
      const failures: unknown[] = [],
        record = this.current;
      try {
        record?.native.cancel();
      } catch (cause) {
        failures.push(cause);
      }
      try {
        this.transport.client.close();
      } catch (cause) {
        failures.push(cause);
      }
      try {
        const settled = await within(
          () =>
            Promise.allSettled([
              ...(record ? [record.ended] : []),
              ...(this.connecting ? [this.connecting] : []),
            ]),
          { timeoutMs: ETCD_LIMITS.cleanupMs },
        );
        for (const result of settled)
          if (result.status === 'rejected') failures.push(result.reason);
      } catch (cause) {
        failures.push(cause);
      }
      if (failures.length)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd watch cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    void this.closing.then(
      () => {
        try {
          this.onClosed();
        } catch {
          /* Owner diagnostics must remain isolated. */
        }
      },
      (cause) => {
        try {
          this.onClosed(cause);
        } catch {
          /* The cleanup promise retains the failure. */
        }
      },
    );
    return this.closing;
  }
}
