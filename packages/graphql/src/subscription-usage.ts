// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MeterSession, VerifiedTenantContext } from '@arkenivajs/core';
import type { Operation } from './operation.js';
import type { Observers } from './observation.js';
import { observe } from './observation.js';
import { failure } from './policy.js';

/** Connection lifetime is distinct from HTTP duration; child work never repeats network bytes. */
export class SubscriptionUsage {
  private parent: MeterSession | undefined;
  private closed = false;
  constructor(
    private readonly meter: Observers['meter'],
    tenant: VerifiedTenantContext,
    private readonly requestId: string,
  ) {
    if (!meter) return;
    if (!meter.withoutScope) throw failure();
    let attempted = false;
    try {
      meter.withoutScope(() => {
        if (attempted) return;
        attempted = true;
        this.parent = meter.start({
          tenant,
          requestId,
          operation: 'graphql.subscription.connection',
        });
      });
    } catch (error) {
      if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
        throw failure('EK_GQL_AUTH');
      this.missing();
    }
    // No payload or driver-reported wire-byte observations are available at this boundary.
    if (this.parent) observe(() => meter.markMissing(this.parent!, 'driver_bytes_unavailable'));
  }

  private missing() {
    if (this.parent) observe(() => this.meter?.markMissing(this.parent!, 'span_not_instrumented'));
  }

  async scope(scope: Operation, phase: 'source' | 'event', work: () => Promise<void>) {
    if (this.closed) throw failure('EK_GQL_SUBSCRIPTION');
    const meter = this.meter,
      parent = this.parent;
    let child: MeterSession | undefined;
    if (meter && parent && scope.context.auth) {
      let attempted = false;
      try {
        meter.run(parent, () => {
          if (attempted) return;
          attempted = true;
          if (meter.current() !== parent) throw failure();
          child = meter.start({
            tenant: scope.context.auth!,
            requestId: this.requestId,
            operation: 'graphql.subscription.' + phase,
          });
        });
      } catch (error) {
        if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
          throw failure('EK_GQL_AUTH');
        this.missing();
      }
      if (!child) this.missing();
    }
    const owned = child;
    if (owned) {
      try {
        owned.recordOperation(
          phase === 'source' ? 'graphql.operations' : 'graphql.subscription_events',
        );
      } catch {
        observe(() => meter?.markMissing(owned, 'span_not_instrumented'));
      }
      void scope.completion.then(() => {
        try {
          owned.recordOperation('graphql.resolved_fields', scope.resolvedFields);
          owned.recordOperation('graphql.loader_batches', scope.loaderBatches);
          owned.recordUsage('graphql.loader_items', {
            unit: 'items',
            source: 'observed',
            value: scope.loaderItems,
          });
        } catch {
          observe(() => meter?.markMissing(owned, 'span_not_instrumented'));
        }
        observe(() =>
          owned.end(scope.failed ? 'error' : scope.controller.signal.aborted ? 'aborted' : 'ok'),
        );
      });
    }
    let task: Promise<void> | undefined;
    const invoke = () => (task ??= Promise.resolve().then(work));
    if (meter && owned) {
      try {
        const result = meter.run(owned, invoke);
        void Promise.resolve(result).catch(() => undefined);
      } catch {
        observe(() => meter.markMissing(owned, 'span_not_instrumented'));
      }
      if (!task) observe(() => meter.markMissing(owned, 'span_not_instrumented'));
    }
    await invoke();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    observe(() => this.parent?.end('ok'));
  }
}
