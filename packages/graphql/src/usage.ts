// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MeterSession, MeterResultStatus, VerifiedTenantContext } from '@arkenivajs/core';
import type { GraphqlOperationKind } from './contracts.js';
import type { Operation } from './operation.js';
import type { Observers } from './observation.js';
import { observe } from './observation.js';
import { failure } from './policy.js';

/** One verified HTTP accounting parent; child work never repeats the parent's byte totals. */
export class RequestUsage {
  private readonly meter: Observers['meter'];
  private parent: MeterSession | undefined;
  private child: MeterSession | undefined;
  private ended = false;
  private outcome: MeterResultStatus = 'ok';
  private responseBytes: number | undefined;
  constructor(
    observers: Observers,
    private readonly scope: Operation,
    private readonly tenant: VerifiedTenantContext | undefined,
    private readonly requestId: string,
    method: string,
    path: string,
    requestBytes: number,
  ) {
    this.meter = observers.meter;
    if (!this.meter || !tenant) return;
    try {
      this.parent = this.meter.start({ tenant, operation: method + ' ' + path, requestId });
    } catch (error) {
      if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
        throw failure('EK_GQL_AUTH');
      return;
    }
    this.record(this.parent, () => {
      this.parent!.recordOperation('http.requests');
      this.parent!.recordUsage('http.request.bytes', {
        unit: 'bytes',
        source: 'observed',
        value: requestBytes,
      });
    });
  }
  private record(session: MeterSession, work: () => void) {
    try {
      work();
    } catch {
      observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
    }
  }
  private run<T>(session: MeterSession | undefined, work: () => T | Promise<T>): Promise<T> {
    let task: Promise<T> | undefined;
    const invoke = () => (task ??= Promise.resolve().then(work));
    if (session && this.meter) {
      try {
        const scoped = this.meter.run(session, invoke);
        void Promise.resolve(scoped).catch(() => undefined);
      } catch {
        observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
      }
      if (!task) observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
    }
    return invoke();
  }
  http<T>(work: () => T | Promise<T>) {
    return this.run(this.parent, work);
  }
  operation<T>(kind: GraphqlOperationKind | undefined, work: () => T | Promise<T>): Promise<T> {
    if (this.parent && this.meter && this.tenant) {
      try {
        if (this.meter.current() !== this.parent) throw failure();
        this.child = this.meter.start({
          tenant: this.tenant,
          operation: 'graphql.' + (kind ?? 'invalid'),
          requestId: this.requestId,
        });
        this.record(this.child, () => this.child!.recordOperation('graphql.operations'));
        void this.scope.completion.then(() => {
          const child = this.child!;
          this.record(child, () => {
            child.recordOperation('graphql.resolved_fields', this.scope.resolvedFields);
            child.recordOperation('graphql.loader_batches', this.scope.loaderBatches);
            child.recordUsage('graphql.loader_items', {
              unit: 'items',
              source: 'observed',
              value: this.scope.loaderItems,
            });
          });
          observe(() => child.end(this.outcome));
        });
      } catch {
        observe(() => this.meter?.markMissing(this.parent!, 'span_not_instrumented'));
      }
    }
    return this.run(this.child, work);
  }
  reject(error: unknown) {
    this.outcome =
      error instanceof KitError && error.code === 'EK_GQL_TIMEOUT' ? 'unknown' : 'error';
  }
  response(payload: unknown) {
    if (typeof payload === 'string' || Buffer.isBuffer(payload))
      this.responseBytes = Buffer.byteLength(payload);
  }
  finish(status: number) {
    if (this.ended) return;
    this.ended = true;
    if (status === 499) this.outcome = 'unknown';
    if (!this.parent) return;
    if (this.responseBytes === undefined)
      observe(() => this.meter?.markMissing(this.parent!, 'driver_bytes_unavailable'));
    else
      this.record(this.parent, () =>
        this.parent!.recordUsage('http.response.bytes', {
          unit: 'bytes',
          source: 'observed',
          value: this.responseBytes!,
        }),
      );
    const result: MeterResultStatus =
      status === 499 || status === 504
        ? 'aborted'
        : status >= 400 || this.outcome !== 'ok'
          ? 'error'
          : 'ok';
    observe(() => this.parent!.end(result));
  }
}
