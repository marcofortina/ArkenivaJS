// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { IDuplexStream, ILeaseKeepAliveRequest, ILeaseKeepAliveResponse } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { EtcdLease, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { EtcdConfiguration } from './config.js';
import { etcdInteger, etcdOptions } from './common.js';
import {
  EtcdAcknowledgedError,
  etcdAcknowledgedFailure,
  etcdError,
  permanentEtcdError,
} from './errors.js';
import { ETCD_LIMITS } from './limits.js';
import { EtcdTransport, etcdCallOptions } from './transport.js';
import type { EtcdCallScope } from './transport.js';

/** Each resource call enters the owning connection's bounded observation and deadline boundary. */
export interface EtcdLeaseAttempt {
  <T>(
    operation: 'grantLease' | 'keepAlive' | 'revoke',
    input: OperationOptions | undefined,
    work: (scope: EtcdCallScope) => Promise<T>,
    cleanup?: boolean,
  ): Promise<T>;
}

/** Caller-owned lease identity remains known even when its grant acknowledgment is lost. */
export class EtcdOwnedLease {
  readonly id: string;
  readonly handle: EtcdLease;
  private readonly transport: EtcdTransport;
  private readonly lifetime = new AbortController();
  private readonly renewal = new AbortController();
  private ownership: 'none' | 'possible' | 'granted' | 'revoked' = 'none';
  private ttl = 0n;
  private expires = 0n;
  private enabled = false;
  private retiring = false;
  private lost: KitError | undefined;
  private loop: Promise<void> | undefined;
  private renewalWork: Promise<void> | undefined;
  private revoking: Promise<void> | undefined;
  private revocationScope: EtcdCallScope | undefined;
  private grantWork: Promise<EtcdLease> | undefined;
  private acquiring = false;
  private disposing: Promise<void> | undefined;
  private disposal: Promise<void> | undefined;

  constructor(
    configuration: EtcdConfiguration,
    private readonly ttlSeconds: number,
    private readonly parent: AbortSignal,
    private readonly attempt: EtcdLeaseAttempt,
    private readonly onLost: (failure: KitError) => void,
    private readonly onClosed: (failure?: unknown) => void,
    requestedId?: string,
  ) {
    this.id =
      requestedId ??
      (BigInt('0x' + randomBytes(8).toString('hex')) & 9_223_372_036_854_775_807n || 1n).toString();
    etcdInteger(this.id);
    this.transport = new EtcdTransport(
      configuration,
      AbortSignal.any([parent, this.lifetime.signal]),
    );
    this.handle = Object.freeze({
      id: this.id,
      keepAlive: () => this.keepAlive(),
      revoke: (input?: OperationOptions) => this.revoke(input),
    });
  }

  /** Grant does not start automatic renewal; only keepAlive explicitly authorizes that activity. */
  async grant(input?: OperationOptions): Promise<EtcdLease> {
    if (!Number.isSafeInteger(this.ttlSeconds) || this.ttlSeconds <= 0)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'etcd lease TTL requires positive integer seconds',
      });
    if (this.acquiring || this.retiring)
      throw new KitError({
        code: 'EK_LIFECYCLE_STATE',
        message: 'etcd lease grant already started or closed',
      });
    this.acquiring = true;
    return this.attempt('grantLease', input, (scope) => {
      if (this.retiring)
        throw new KitError({
          code: 'EK_RESOURCE_CLOSED',
          message: 'etcd lease closed before submission',
        });
      this.ownership = 'possible';
      const work = this.transport.run(scope, async () => {
        let rejected = false;
        try {
          const response = await this.transport.client.leaseClient.leaseGrant({
            ID: this.id,
            TTL: String(this.ttlSeconds),
          });
          if (response.error) {
            rejected = true;
            throw new EtcdAcknowledgedError({
              code: 'EK_KV_CONFLICT',
              message: 'etcd rejected the lease grant',
              cause: response.error,
            });
          }
          if (etcdInteger(response.ID).toString() !== this.id)
            throw new KitError({
              code: 'EK_BACKEND_UNAVAILABLE',
              message: 'etcd returned a different lease identity',
            });
          this.ttl = etcdInteger(response.TTL);
          this.expires = process.hrtime.bigint() + this.ttl * 1_000_000_000n;
          this.ownership = 'granted';
          return this.handle;
        } catch (cause) {
          this.ownership =
            !rejected && scope.submitted && !etcdAcknowledgedFailure(cause) ? 'possible' : 'none';
          throw cause;
        }
      });
      this.grantWork = work;
      void work.catch(() => undefined);
      return work;
    });
  }

  /** New attachments require an owned lease whose observed validity has not expired. */
  assertUsable(): void {
    if (this.parent.aborted || this.disposal)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd lease owner is closed' });
    if (
      this.retiring ||
      this.ownership !== 'granted' ||
      this.lost ||
      process.hrtime.bigint() >= this.expires
    )
      throw new KitError({
        code: 'EK_KV_CONFLICT',
        message: 'etcd lease validity is no longer established',
        cause: this.lost,
      });
  }

  private keepAlive(): void {
    this.assertUsable();
    if (this.enabled) return;
    this.enabled = true;
    this.loop = this.renewLoop();
    void this.loop.catch((cause) => this.loss(etcdError(cause)));
  }

  private async renewLoop(): Promise<void> {
    const signal = AbortSignal.any([this.renewal.signal, this.parent]);
    while (this.enabled && !signal.aborted) {
      const remaining = (this.expires - process.hrtime.bigint()) / 1_000_000n;
      if (remaining <= 0n) {
        this.loss(
          new KitError({ code: 'EK_KV_CONFLICT', message: 'etcd lease renewal validity expired' }),
        );
        return;
      }
      const timeoutMs = Number(remaining > 5000n ? 5000n : remaining);
      try {
        await this.attempt('keepAlive', { timeoutMs, signal }, (scope) => {
          const work = this.transport.run(scope, () => this.renew(scope));
          this.renewalWork = work;
          void work.catch(() => undefined);
          return work;
        });
      } catch (cause) {
        if (!this.enabled || signal.aborted) return;
        try {
          if (this.renewalWork)
            await within(() => Promise.allSettled([this.renewalWork!]), {
              timeoutMs: ETCD_LIMITS.cleanupMs,
            });
        } catch (cleanup) {
          this.loss(etcdError(cleanup));
          return;
        }
        if (
          permanentEtcdError(cause) ||
          (cause instanceof KitError && cause.code === 'EK_KV_CONFLICT')
        ) {
          this.loss(etcdError(cause));
          return;
        }
        try {
          await delay(100, undefined, { signal });
        } catch {
          return;
        }
        continue;
      }
      const interval = (this.ttl * 1000n) / 3n;
      try {
        await delay(Math.max(100, Number(interval > 5000n ? 5000n : interval)), undefined, {
          signal,
        });
      } catch {
        return;
      }
    }
  }

  private async renew(scope: EtcdCallScope): Promise<void> {
    let stream: IDuplexStream<ILeaseKeepAliveRequest, ILeaseKeepAliveResponse> | undefined;
    let finish!: () => void;
    const ended = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let primary: unknown,
      failed = false;
    try {
      stream = await this.transport.client.leaseClient.leaseKeepAlive(etcdCallOptions(scope));
      const current = stream;
      const response = new Promise<ILeaseKeepAliveResponse>((resolve, reject) => {
        current.on('error', (cause) => {
          finish();
          reject(cause);
        });
        current.on('end', () => {
          finish();
          reject(new Error('etcd lease heartbeat ended before acknowledgment'));
        });
        current.on('status', finish);
        current.on('data', resolve);
        current.write({ ID: this.id });
      });
      const reply = await response;
      if (etcdInteger(reply.ID).toString() !== this.id)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd renewed a different lease identity',
        });
      if (reply.TTL === '0' || reply.TTL === '-1')
        throw new KitError({
          code: 'EK_KV_CONFLICT',
          message: 'etcd lease no longer exists',
          details: { leaseExpired: true },
        });
      this.ttl = etcdInteger(reply.TTL);
      this.expires = process.hrtime.bigint() + this.ttl * 1_000_000_000n;
    } catch (cause) {
      primary = cause;
      failed = true;
    }
    const cleanup: unknown[] = [];
    if (stream) {
      // Half-close first so a normal owned cancellation cannot reset the SDK's cached lease service.
      try {
        stream.end();
      } catch (cause) {
        cleanup.push(cause);
      }
      try {
        stream.cancel();
      } catch (cause) {
        cleanup.push(cause);
      }
      try {
        await within(() => ended, { timeoutMs: ETCD_LIMITS.cleanupMs });
      } catch (cause) {
        cleanup.push(cause);
      }
    }
    if (cleanup.length)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'etcd lease heartbeat cleanup failed',
        cause: new AggregateError([...(failed ? [primary] : []), ...cleanup]),
      });
    if (failed) throw primary;
  }

  private loss(cause: KitError): void {
    if (this.lost || this.retiring) return;
    this.lost = cause;
    this.enabled = false;
    this.renewal.abort(cause);
    try {
      this.onLost(cause);
    } catch {
      /* Diagnostic failures do not authorize another lease grant. */
    }
  }

  /** Repeated revocation is idempotent; it never creates a replacement lease. */
  private async revoke(input?: OperationOptions): Promise<void> {
    const captured = etcdOptions(input);
    if (this.ownership === 'revoked') {
      await this.closeClient();
      return;
    }
    if (this.parent.aborted || this.disposal)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'etcd lease owner is closed' });
    if (!this.revoking) {
      this.stopRenewing();
      this.revocationScope = undefined;
      const started = this.remove(input, false);
      this.revoking = started;
      void started.then(
        () => {
          this.revoking = undefined;
        },
        () => {
          this.revoking = undefined;
        },
      );
    }
    try {
      await within(() => this.revoking!, captured);
    } catch (cause) {
      if (this.revocationAcknowledged()) {
        await this.closeClient();
        return;
      }
      throw etcdError(cause, true, this.revocationScope?.submitted ?? false);
    }
  }

  private revocationAcknowledged(): boolean {
    return this.ownership === 'revoked';
  }

  /** Shutdown stops renewal before issuing its separately budgeted, idempotent owned cleanup. */
  stopRenewing(): void {
    this.retiring = true;
    this.enabled = false;
    this.renewal.abort();
  }

  private async remove(input: OperationOptions | undefined, cleanup: boolean): Promise<void> {
    await within(
      () =>
        Promise.allSettled([
          ...(this.loop ? [this.loop] : []),
          ...(this.renewalWork ? [this.renewalWork] : []),
        ]),
      { timeoutMs: ETCD_LIMITS.cleanupMs },
    );
    await this.attempt(
      'revoke',
      input,
      (scope) =>
        this.transport.run(scope, async () => {
          this.revocationScope = scope;
          try {
            await this.transport.client.leaseClient.leaseRevoke({ ID: this.id });
          } catch (cause) {
            if (!(etcdError(cause).details.vendorCode === 'LEASE_INVALID')) throw cause;
          }
          this.ownership = 'revoked';
        }),
      cleanup,
    );
    await this.closeClient();
  }

  /** A provisional grant retains its chosen ID for cleanup after an unacknowledged result. */
  dispose(): Promise<void> {
    if (this.disposing) return this.disposing;
    this.stopRenewing();
    this.disposing = (async () => {
      const failures: unknown[] = [];
      try {
        if (this.grantWork)
          await within(() => Promise.allSettled([this.grantWork!]), {
            timeoutMs: ETCD_LIMITS.cleanupMs,
          });
      } catch (cause) {
        failures.push(cause);
      }
      try {
        if (this.ownership === 'possible' || this.ownership === 'granted')
          await this.remove({ timeoutMs: ETCD_LIMITS.cleanupMs }, true);
      } catch (cause) {
        failures.push(cause);
      }
      try {
        await this.closeClient();
      } catch (cause) {
        failures.push(cause);
      }
      if (failures.length)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd lease disposal failed',
          cause: new AggregateError(failures),
        });
    })();
    return this.disposing;
  }

  private closeClient(): Promise<void> {
    if (this.disposal) return this.disposal;
    this.disposal = (async () => {
      this.lifetime.abort();
      try {
        this.transport.client.close();
      } catch (cause) {
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'etcd lease client cleanup failed',
          cause,
          details: { outcome: this.ownership === 'revoked' ? 'acknowledged' : 'unknown' },
        });
      }
    })();
    void this.disposal.then(
      () => {
        try {
          this.onClosed();
        } catch {
          /* Owner diagnostics remain isolated. */
        }
      },
      (cause) => {
        try {
          this.onClosed(cause);
        } catch {
          /* The disposal promise retains this failure. */
        }
      },
    );
    return this.disposal;
  }
}
