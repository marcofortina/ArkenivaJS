// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import type { Etcd3 } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type {
  EtcdProvider,
  EtcdValue,
  EtcdWatchHandle,
  EtcdLease,
  OperationOptions,
  Logger,
  Telemetry,
  UsageMeter,
  MeterSession,
} from '@arkenivajs/core';
import { instrumentOperation, within } from '@arkenivajs/core/support';
import type { EtcdConfiguration } from './config.js';
import { etcdOptions, etcdKey, etcdBytes, etcdInteger } from './common.js';
import { etcdError } from './errors.js';
import { ETCD_LIMITS } from './limits.js';
import { EtcdTransport } from './transport.js';
import type { EtcdCallScope } from './transport.js';
import { EtcdWatch } from './watch.js';
import { EtcdOwnedLease } from './lease.js';

/** Observation ports are optional and resolve through explicit application dependencies. */
export interface EtcdObservationPorts {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
type Operation =
  'get' | 'put' | 'delete' | 'watch' | 'grantLease' | 'keepAlive' | 'revoke' | 'compareAndSwap';

/** One primary native client and bounded resource-owned clients preserve cancellation isolation. */
export class EtcdConnection implements EtcdProvider {
  private readonly stop = new AbortController();
  private readonly transport: EtcdTransport;
  private readonly pending = new Set<Promise<unknown>>();
  private readonly watches = new Set<EtcdWatch>();
  private readonly leases = new Map<string, EtcdOwnedLease>();
  private readonly cleanupFailures: unknown[] = [];
  private cleanupFailureCount = 0;
  private observerFailures = 0;
  private operations = 0;
  private reconnects = 0;
  private closed = false;
  private ready = false;
  private starting: Promise<void> | undefined;
  private closing: Promise<void> | undefined;

  constructor(
    private readonly name: string,
    private readonly configuration: EtcdConfiguration,
    private readonly observation: EtcdObservationPorts,
  ) {
    setMaxListeners(
      ETCD_LIMITS.pending + ETCD_LIMITS.watches + ETCD_LIMITS.leases + 16,
      this.stop.signal,
    );
    this.transport = new EtcdTransport(configuration, this.stop.signal);
  }

  private open(): void {
    if (this.closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd connection is closed' });
  }
  private diagnostic(work: () => void): void {
    try {
      work();
    } catch {
      this.observerFailures++;
    }
  }
  private session(): MeterSession | undefined {
    let session: MeterSession | undefined;
    this.diagnostic(() => {
      session = this.observation.meter?.current();
    });
    return session;
  }
  private missing(session: MeterSession | undefined, reason: string): void {
    if (!session) return;
    this.diagnostic(() => {
      const meter = this.observation.meter as UsageMeter & {
        markMissing?: (session: MeterSession, reason: string) => void;
      };
      if (!meter?.markMissing) throw new Error('Meter quality controls are unavailable');
      meter.markMissing(session, reason);
    });
  }
  private remember(cause: unknown): void {
    this.cleanupFailureCount++;
    if (this.cleanupFailures.length < 16) this.cleanupFailures.push(cause);
    this.diagnostic(() =>
      this.observation.logger?.warn('etcd resource cleanup failed', {
        driver: 'etcd',
        connection: this.name,
      }),
    );
  }

  /** A scoped keys-only read proves authentication without materializing application values. */
  private async probe(scope: EtcdCallScope): Promise<void> {
    await this.transport.run(scope, async () => {
      const response = await this.transport.client.kv.range({
        key: Buffer.from(this.configuration.prefix + '.arkenivajs:readiness'),
        keys_only: true,
        limit: 1,
      });
      if (!response.header || !Array.isArray(response.kvs) || response.kvs.length > 1)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd readiness response is invalid',
        });
      etcdInteger(response.header.revision);
    });
  }

  start(input?: OperationOptions): Promise<void> {
    this.open();
    if (this.starting) return this.starting;
    const captured = etcdOptions(input, ETCD_LIMITS.startupMs);
    this.starting = (async () => {
      try {
        await this.run('get', false, captured, (scope) => this.probe(scope), {
          startup: true,
          observe: false,
        });
        this.open();
        this.ready = true;
      } catch (cause) {
        try {
          await this.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd startup and cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw cause;
      }
    })();
    return this.starting;
  }

  /** Confirm scoped native range access again; startup's cached promise is not ongoing backend evidence. */
  async health(input?: OperationOptions): Promise<boolean> {
    await this.run('get', false, input, (scope) => this.probe(scope), { observe: false });
    return true;
  }

  private run<T>(
    operation: Operation,
    write: boolean,
    input: OperationOptions | undefined,
    command: (scope: EtcdCallScope) => Promise<T>,
    control: { cleanup?: boolean; startup?: boolean; observe?: boolean } = {},
  ): Promise<T> {
    if (!control.cleanup) this.open();
    const captured = etcdOptions(input);
    if (!this.ready && !control.startup && !control.cleanup)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'etcd provider is not ready' });
    if (!control.cleanup && this.pending.size >= ETCD_LIMITS.pending)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'etcd pending capacity is exhausted',
        retryable: true,
      });
    const controller = new AbortController();
    const signal = AbortSignal.any([
      controller.signal,
      ...(!control.cleanup ? [this.stop.signal] : []),
      ...(captured.signal ? [captured.signal] : []),
    ]);
    const scope: EtcdCallScope = { signal, timeoutMs: captured.timeoutMs, submitted: false };
    const attributes = { 'db.system.name': 'etcd', 'db.operation.name': operation };
    const session = control.observe === false ? undefined : this.session();
    let completed = false,
      answer: T,
      failure: KitError | undefined;
    const execute = async () => {
      if (signal.aborted)
        throw new KitError({
          code: 'EK_ABORTED',
          message: 'etcd operation aborted',
          cause: signal.reason,
        });
      if (control.observe !== false) {
        this.operations++;
        this.diagnostic(() => session?.recordOperation('db.query'));
        this.missing(session, 'driver_bytes_unavailable');
      }
      const began = performance.now();
      try {
        answer = await command(scope);
        completed = true;
        return answer;
      } catch (cause) {
        failure = etcdError(cause, write, scope.submitted);
        this.diagnostic(() =>
          this.observation.logger?.warn('etcd command failed', {
            driver: 'etcd',
            connection: this.name,
            operation,
            errorCode: failure!.code,
          }),
        );
        throw failure;
      } finally {
        if (control.observe !== false) {
          const elapsed = performance.now() - began;
          this.diagnostic(() =>
            this.observation.telemetry?.recordHistogram(
              'db.client.operation.duration',
              elapsed / 1000,
              attributes,
            ),
          );
          this.diagnostic(() =>
            session?.recordUsage('db.client.elapsed', {
              value: elapsed,
              unit: 'milliseconds',
              source: 'observed',
            }),
          );
        }
      }
    };
    const work = (async () => {
      try {
        return await within(
          () =>
            control.observe === false
              ? execute()
              : instrumentOperation(
                  this.observation.telemetry,
                  'db.client.operation',
                  attributes,
                  execute,
                  () => {
                    this.observerFailures++;
                  },
                ),
          { timeoutMs: captured.timeoutMs, signal },
        );
      } catch (cause) {
        controller.abort(cause);
        if (completed) {
          this.observerFailures++;
          return answer!;
        }
        if (failure) throw failure;
        throw etcdError(cause, write, scope.submitted);
      }
    })();
    this.pending.add(work);
    void work.then(
      () => this.pending.delete(work),
      () => this.pending.delete(work),
    );
    return work;
  }

  async get(key: string, input?: OperationOptions): Promise<EtcdValue | null> {
    this.open();
    const name = etcdKey(key, this.configuration.prefix);
    return this.run('get', false, input, (scope) =>
      this.transport.run(scope, async () => {
        const result = await this.transport.client.get(name).exec();
        if (
          !Array.isArray(result.kvs) ||
          result.kvs.length > 1 ||
          result.more ||
          etcdInteger(result.count, true) !== BigInt(result.kvs.length)
        )
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd returned an invalid single-key result',
          });
        const row = result.kvs[0];
        if (!row) return null;
        if (
          !Buffer.isBuffer(row.key) ||
          !row.key.equals(Buffer.from(name)) ||
          !Buffer.isBuffer(row.value)
        )
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd returned an unexpected key or raw value',
          });
        if (row.value.length > ETCD_LIMITS.valueBytes)
          throw new KitError({
            code: 'EK_KV_CONFLICT',
            message: 'etcd stored value exceeds the portable byte limit',
            details: { limitExceeded: true },
          });
        return Object.freeze({
          key,
          value: Uint8Array.from(row.value),
          revision: etcdInteger(row.mod_revision),
          version: etcdInteger(row.version),
        });
      }),
    );
  }

  async put(
    key: string,
    value: Uint8Array,
    input: OperationOptions & { leaseId?: string } = {},
  ): Promise<void> {
    this.open();
    etcdOptions(input);
    const name = etcdKey(key, this.configuration.prefix),
      captured = etcdBytes(value),
      leaseId = input.leaseId;
    if (leaseId !== undefined) {
      if (
        typeof leaseId !== 'string' ||
        !/^[1-9]\d{0,18}(?![\s\S])/.test(leaseId) ||
        BigInt(leaseId) > 9_223_372_036_854_775_807n
      )
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'etcd leaseId requires a positive int64 string',
        });
      const lease = this.leases.get(leaseId);
      if (!lease)
        throw new KitError({
          code: 'EK_KV_CONFLICT',
          message: 'etcd lease belongs to another owner',
        });
      lease.assertUsable();
    }
    return this.run('put', true, input, (scope) =>
      this.transport.run(scope, async () => {
        const request = this.transport.client.put(name).value(captured);
        if (leaseId !== undefined) {
          const lease = this.leases.get(leaseId);
          if (!lease)
            throw new KitError({
              code: 'EK_KV_CONFLICT',
              message: 'etcd lease no longer belongs to this owner',
            });
          lease.assertUsable();
          request.lease(leaseId);
        }
        const response = await request.exec();
        etcdInteger(response.header.revision);
      }),
    );
  }

  async delete(key: string, input?: OperationOptions): Promise<boolean> {
    this.open();
    const name = etcdKey(key, this.configuration.prefix);
    return this.run('delete', true, input, (scope) =>
      this.transport.run(scope, async () => {
        const result = await this.transport.client.delete().key(name).exec();
        const count = etcdInteger(result.deleted, true);
        if (count > 1n)
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd returned an invalid single-key deletion count',
          });
        return count === 1n;
      }),
    );
  }

  async compareAndSwap(
    input: { key: string; expectedRevision: bigint; value: Uint8Array },
    options?: OperationOptions,
  ): Promise<boolean> {
    this.open();
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      typeof input.expectedRevision !== 'bigint' ||
      input.expectedRevision < 0n ||
      input.expectedRevision > 9_223_372_036_854_775_807n
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'etcd CAS requires an exact nonnegative int64 revision',
      });
    const name = etcdKey(input.key, this.configuration.prefix),
      revision = input.expectedRevision.toString(),
      value = etcdBytes(input.value);
    return this.run('compareAndSwap', true, options, (scope) =>
      this.transport.run(scope, async () => {
        const result = await this.transport.client
          .if(name, 'Mod', '==', revision)
          .then(this.transport.client.put(name).value(value))
          .commit();
        if (typeof result.succeeded !== 'boolean')
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'etcd returned an invalid CAS acknowledgment',
          });
        return result.succeeded;
      }),
    );
  }

  async watch(prefix: string, input?: OperationOptions): Promise<EtcdWatchHandle> {
    this.open();
    const captured = etcdOptions(input),
      name = etcdKey(prefix, this.configuration.prefix, true);
    if (!this.ready)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'etcd provider is not ready' });
    if (this.watches.size >= ETCD_LIMITS.watches)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'etcd watch capacity is exhausted',
      });
    const watch = new EtcdWatch(
      this.configuration,
      name,
      this.stop.signal,
      captured.signal,
      () => {
        this.reconnects++;
      },
      (cause) => {
        this.watches.delete(watch);
        if (cause !== undefined) this.remember(cause);
      },
    );
    this.watches.add(watch);
    try {
      return await this.run('watch', false, captured, (scope) =>
        watch.open({ timeoutMs: scope.timeoutMs, signal: scope.signal }),
      );
    } catch (cause) {
      try {
        await watch.close();
      } catch (cleanup) {
        const error = etcdError(cause);
        throw new KitError({
          code: error.code,
          message: 'etcd watch acquisition and cleanup failed',
          cause: new AggregateError([cause, cleanup]),
          details: error.details,
        });
      }
      throw cause;
    }
  }

  async grantLease(ttlSeconds: number, input?: OperationOptions): Promise<EtcdLease> {
    this.open();
    etcdOptions(input);
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'etcd lease TTL requires positive integer seconds',
      });
    if (!this.ready)
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'etcd provider is not ready' });
    if (this.leases.size >= ETCD_LIMITS.leases)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'etcd lease capacity is exhausted',
      });
    const lease = new EtcdOwnedLease(
      this.configuration,
      ttlSeconds,
      this.stop.signal,
      (operation, options, command, cleanup) =>
        this.run(operation, true, options, command, { ...(cleanup ? { cleanup: true } : {}) }),
      () =>
        this.diagnostic(() =>
          this.observation.logger?.warn('etcd owned lease validity was lost', {
            driver: 'etcd',
            connection: this.name,
          }),
        ),
      (cause) => {
        if (this.leases.get(lease.id) === lease) this.leases.delete(lease.id);
        if (cause !== undefined) this.remember(cause);
      },
    );
    if (this.leases.has(lease.id)) {
      await lease.dispose();
      throw new KitError({
        code: 'EK_KV_CONFLICT',
        message: 'etcd owned lease identity collision',
      });
    }
    this.leases.set(lease.id, lease);
    try {
      return await lease.grant(input);
    } catch (cause) {
      try {
        await lease.dispose();
      } catch (cleanup) {
        const error = etcdError(cause);
        throw new KitError({
          code: error.code,
          message: 'etcd lease acquisition and cleanup failed',
          cause: new AggregateError([cause, cleanup]),
          retryable: false,
          details: { ...error.details, leaseId: lease.id },
        });
      }
      throw cause;
    }
  }

  native(): Etcd3 {
    this.open();
    this.missing(this.session(), 'not_instrumented');
    return this.transport.client;
  }
  stats(): Readonly<Record<string, number | null>> {
    return Object.freeze({
      ready: this.ready && !this.closed ? 1 : 0,
      pending: this.pending.size,
      watches: this.watches.size,
      leases: this.leases.size,
      operations: this.operations,
      reconnects: this.reconnects,
      observerFailures: this.observerFailures,
      cleanupFailures: this.cleanupFailureCount,
      nativeChannels: null,
    });
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    const watches = [...this.watches].map((watch) => watch.close());
    for (const lease of this.leases.values()) lease.stopRenewing();
    this.stop.abort();
    const leases = [...this.leases.values()].map((lease) => lease.dispose());
    this.closing = (async () => {
      const failures = new Set<unknown>();
      try {
        const [, resources] = await within(
          () =>
            Promise.all([
              Promise.allSettled([...this.pending]),
              Promise.allSettled([...watches, ...leases]),
            ]),
          { timeoutMs: ETCD_LIMITS.shutdownMs },
        );
        for (const result of resources)
          if (result.status === 'rejected') failures.add(result.reason);
      } catch (cause) {
        failures.add(cause);
      }
      try {
        this.transport.client.close();
      } catch (cause) {
        failures.add(cause);
      }
      for (const cause of this.cleanupFailures) failures.add(cause);
      if (failures.size)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd shutdown cleanup failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.closing;
  }
}
