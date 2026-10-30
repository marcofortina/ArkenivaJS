// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { MeterSession, MeterResultStatus, VerifiedTenantContext } from '@arkenivajs/core';
import type { Observers } from './observation.js';
import { observe } from './observation.js';
import { routingFailure } from './errors.js';
import type { RoutingOperation } from './operation.js';

/** The HTTP parent owns entity bytes; the logical child owns physical execution. */
export class RequestUsage {
  private readonly meter: Observers['meter'];
  private parent: MeterSession | undefined;
  private child: MeterSession | undefined;
  private ended = false;
  private outcome: MeterResultStatus = 'ok';
  private responseBytes: number | undefined;
  constructor(
    observers: Observers,
    private readonly scope: RoutingOperation,
    private readonly tenant: VerifiedTenantContext,
    private readonly requestId: string,
    requestBytes: number,
  ) {
    this.meter = observers.meter;
    if (!this.meter) return;
    try {
      this.parent = this.meter.start({ tenant, operation: 'http.request', requestId });
    } catch (error) {
      if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
        throw routingFailure('EK_AUTH_REQUIRED');
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
  private record(session: MeterSession, work: () => void): void {
    try {
      work();
    } catch {
      observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
    }
  }
  private run<T>(session: MeterSession | undefined, work: () => Promise<T>): Promise<T> {
    let pending: Promise<T> | undefined;
    const invoke = () => (pending ??= Promise.resolve().then(work));
    if (session && this.meter) {
      try {
        void Promise.resolve(this.meter.run(session, invoke)).catch(() => undefined);
      } catch {
        observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
      }
      if (!pending) observe(() => this.meter?.markMissing(session, 'span_not_instrumented'));
    }
    return invoke();
  }
  http<T>(work: () => Promise<T>): Promise<T> {
    return this.run(this.parent, work);
  }
  operation<T>(operationId: string, work: () => Promise<T>): Promise<T> {
    if (this.parent && this.meter) {
      try {
        if (this.meter.current() !== this.parent) throw routingFailure();
        this.child = this.meter.start({
          tenant: this.tenant,
          operation: operationId,
          requestId: this.requestId,
        });
        this.record(this.child, () => this.child!.recordOperation('tenant.routing.operations'));
        void this.scope.completion.then(() => {
          observe(() => this.child!.end(this.outcome));
        });
      } catch (error) {
        // A current provenance rejection is an authorization failure, not an observation gap.
        if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
          throw routingFailure('EK_AUTH_REQUIRED');
        observe(() => this.meter?.markMissing(this.parent!, 'span_not_instrumented'));
      }
    }
    return this.run(this.child, work);
  }
  reject(error: unknown): void {
    this.outcome =
      error instanceof KitError && error.code === 'EK_TROUTE_TIMEOUT' ? 'unknown' : 'error';
  }
  response(payload: unknown): void {
    if (typeof payload === 'string' || Buffer.isBuffer(payload))
      this.responseBytes = Buffer.byteLength(payload);
  }
  finish(status: number): void {
    if (this.ended) return;
    this.ended = true;
    this.outcome =
      status === 499 || status === 504 ? 'unknown' : status >= 400 ? 'error' : this.outcome;
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
    // Already settled operation children close first; unfinished physical work
    // remains visible to the parent as incomplete instead of being hidden.
    queueMicrotask(() =>
      observe(() => this.parent!.end(status === 499 || status === 504 ? 'aborted' : this.outcome)),
    );
  }
}
