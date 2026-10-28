// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { Ajv2020 } from 'ajv/dist/2020.js';
import type { OperationOptions } from '@arkenivajs/core';
import { within, captureAbortSignal } from '@arkenivajs/core/support';
import type { TenantRoutingEventExporter, TenantRoutingEventV1 } from './contracts.js';
import type { Observers } from './observation.js';
import { observe } from './observation.js';
import { TENANT_ROUTING_EVENT_SCHEMA_V1 } from './event-schema.js';
import { data } from './provider-support.js';
import { jsonSnapshot } from './json.js';
import { routingFailure } from './errors.js';

type Completion = Omit<TenantRoutingEventV1, 'eventId' | 'schemaVersion' | 'quality'>;
type Entry = { readonly event: TenantRoutingEventV1; readonly bytes: number };

/** One bounded queue and one physically owned export; the injected transport is borrowed. */
export class RoutingEvents {
  private readonly validate = new Ajv2020({
    strict: true,
    ownProperties: true,
    coerceTypes: false,
    allErrors: false,
    messages: false,
    logger: false,
  }).compile(JSON.parse(JSON.stringify(TENANT_ROUTING_EVENT_SCHEMA_V1)));
  private readonly queue: Entry[] = [];
  private readonly controller = new AbortController();
  private pumping: Promise<void> | undefined;
  private active = 0;
  private retainedBytes = 0;
  private exported = 0;
  private dropped = 0;
  private failedExports = 0;
  private closed = false;
  constructor(
    private readonly exporter: TenantRoutingEventExporter,
    private readonly observers: Observers,
  ) {}
  private drop(count: number, reason: 'capacity' | 'invalid' | 'error'): void {
    this.dropped = Math.min(Number.MAX_SAFE_INTEGER, this.dropped + count);
    observe(() =>
      this.observers.telemetry?.addCounter('arkenivajs.routing.events.dropped', count, { reason }),
    );
  }
  track(
    input: Omit<Completion, 'durationMs' | 'status'>,
    completion: Promise<void>,
    duration: () => number,
  ): Readonly<{ finish(status: number): void }> {
    let settled = false,
      finished = false,
      emitted = false,
      status: TenantRoutingEventV1['status'] = 'unknown';
    const publish = () => {
      if (!settled || !finished || emitted) return;
      emitted = true;
      this.complete({ ...input, durationMs: duration(), status });
    };
    void completion
      .then(() => {
        settled = true;
        publish();
      })
      .catch(() => this.drop(1, 'invalid'));
    return Object.freeze({
      finish(code: number) {
        if (finished) return;
        finished = true;
        status = code === 499 || code === 504 ? 'unknown' : code >= 400 ? 'error' : 'ok';
        publish();
      },
    });
  }
  complete(input: Completion): void {
    if (this.closed) {
      this.drop(1, 'error');
      return;
    }
    let entry: Entry;
    try {
      const value = data(input, [
        'requestId',
        'traceId',
        'tenantId',
        'operationId',
        'registryRevision',
        'registryActivationGeneration',
        'implementationId',
        'implementationKind',
        'durationMs',
        'status',
      ]);
      const event = jsonSnapshot(
        {
          ...value,
          schemaVersion: '1.0.0',
          eventId: randomUUID(),
          quality: {
            complete: value.status !== 'unknown',
            missing: value.status === 'unknown' ? ['execution_outcome_unknown'] : [],
          },
        },
        8064,
      ) as unknown as TenantRoutingEventV1;
      if (this.validate(event) !== true) throw routingFailure();
      entry = { event, bytes: Buffer.byteLength(JSON.stringify(event)) + 128 };
    } catch {
      this.drop(1, 'invalid');
      return;
    }
    if (this.queue.length + this.active >= 1024 || this.retainedBytes + entry.bytes > 4194304) {
      this.drop(1, 'capacity');
      return;
    }
    this.queue.push(entry);
    this.retainedBytes += entry.bytes;
    this.start();
  }
  private start(): void {
    if (this.pumping || this.closed || !this.queue.length) return;
    const pending = this.pump();
    this.pumping = pending;
    void pending
      .finally(() => {
        this.pumping = undefined;
        this.start();
      })
      .catch(() => undefined);
  }
  private async pump(): Promise<void> {
    while (this.queue.length && !this.closed) {
      const batch = this.queue.splice(0, 100);
      this.active = batch.length;
      const events = Object.freeze(
        batch.map(({ event }) =>
          this.dropped
            ? (jsonSnapshot(
                {
                  ...event,
                  quality: {
                    complete: false,
                    missing: [...event.quality.missing, 'prior_routing_events_lost'],
                  },
                },
                8192,
              ) as unknown as TenantRoutingEventV1)
            : event,
        ),
      );
      const controller = new AbortController(),
        signal = AbortSignal.any([controller.signal, this.controller.signal]);
      const physical = Promise.resolve().then(() =>
        this.exporter.export(events, { signal, timeoutMs: 5000 }),
      );
      let accepted = false;
      try {
        await within(() => physical, { signal, timeoutMs: 5000 });
        accepted = true;
        this.exported = Math.min(Number.MAX_SAFE_INTEGER, this.exported + batch.length);
        observe(() =>
          this.observers.telemetry?.addCounter('arkenivajs.routing.events.exported', batch.length),
        );
      } catch {
        this.failedExports = Math.min(Number.MAX_SAFE_INTEGER, this.failedExports + 1);
        this.drop(batch.length, 'error');
        observe(() =>
          this.observers.telemetry?.addCounter('arkenivajs.routing.events.failed_exports', 1),
        );
      } finally {
        controller.abort();
        // A public deadline does not free physical exporter admission. Late
        // success cannot acknowledge a batch whose delivery already failed.
        await physical.catch(() => undefined);
        this.active = 0;
        this.retainedBytes -= batch.reduce((bytes, entry) => bytes + entry.bytes, 0);
      }
      if (!accepted && this.closed) break;
    }
  }
  stats(): Readonly<{
    queued: number;
    inFlight: number;
    exported: number;
    dropped: number;
    failedExports: number;
  }> {
    return Object.freeze({
      queued: this.queue.length,
      inFlight: this.active,
      exported: this.exported,
      dropped: this.dropped,
      failedExports: this.failedExports,
    });
  }
  async flush(input: OperationOptions = {}): Promise<void> {
    const fields = data(input, ['signal', 'timeoutMs']),
      timeoutMs = fields.timeoutMs === undefined ? 5000 : fields.timeoutMs;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      (timeoutMs as number) < 1 ||
      (timeoutMs as number) > 120000
    )
      throw routingFailure();
    const signal = fields.signal === undefined ? undefined : captureAbortSignal(fields.signal);
    await within(
      async () => {
        while (this.pumping) await this.pumping;
      },
      { timeoutMs: timeoutMs as number, ...(signal ? { signal } : {}) },
    );
    if (this.dropped || this.failedExports) throw routingFailure('EK_BACKEND_UNAVAILABLE');
  }
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.controller.abort();
    if (this.queue.length) {
      this.drop(this.queue.length, 'error');
      this.retainedBytes -= this.queue.reduce((bytes, entry) => bytes + entry.bytes, 0);
      this.queue.length = 0;
    }
    if (this.pumping) await within(() => this.pumping!, { timeoutMs: 5000 });
  }
}
