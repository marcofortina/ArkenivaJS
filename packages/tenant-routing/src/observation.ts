// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Telemetry, VerifiedTenantContext, UsageMeter, MeterSession } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { SelectedOperation } from './table.js';
import { routingFailure } from './errors.js';

export const OBSERVERS = Symbol('tenant-routing.observers');
export interface Observers {
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter & {
    run<T>(session: MeterSession, work: () => T): T;
    markMissing(
      session: MeterSession,
      reason: 'driver_bytes_unavailable' | 'span_not_instrumented',
    ): void;
  };
}
export const observations: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  const accounting = options.metering?.enabled
    ? options.plugins?.find((plugin) => plugin.capabilities.has('meter'))
    : undefined;
  return {
    id: 'tenant-routing-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [owner?.id, accounting?.id].filter((id): id is string => id !== undefined),
    init(context) {
      const meter = accounting
        ? context.require<NonNullable<Observers['meter']>>(COMPONENTS.meter)
        : undefined;
      if (
        options.metering?.enabled &&
        (!meter || typeof meter.run !== 'function' || typeof meter.markMissing !== 'function')
      )
        throw routingFailure();
      context.provide<Observers>(OBSERVERS, {
        ...(owner ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
        ...(meter ? { meter } : {}),
      });
    },
    close() {},
  };
};

/** Exporter failures cannot authorize, replay or replace business work. */
export function observe(work: () => void): void {
  try {
    work();
  } catch {
    /* The existing provider owns export failure counters. */
  }
}
export function elapsed(telemetry: Telemetry | undefined, name: string, began: number): void {
  observe(() => telemetry?.recordHistogram(name, Math.max(0, performance.now() - began) / 1000));
}

/** Outbound diagnostics come only from the locally established client span. */
export function injectTrace(
  telemetry: Telemetry | undefined,
  headers: Record<string, string>,
): void {
  observe(() => {
    const carrier = (
      telemetry as
        | (Telemetry & { traceHeaders?: () => Readonly<Record<string, string | undefined>> })
        | undefined
    )?.traceHeaders?.();
    for (const name of ['traceparent', 'tracestate']) {
      const value = carrier?.[name];
      if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
        headers[name] = value;
    }
  });
}

/** Only bounded W3C diagnostics may select a remote trace parent. */
export function traceRequest<T>(
  observers: Observers,
  method: string,
  path: string,
  headers: Readonly<Record<string, string | undefined>>,
  work: () => Promise<T>,
): Promise<T> {
  let pending: Promise<T> | undefined;
  const invoke = () =>
    (pending ??= instrumentOperation(
      observers.telemetry,
      'http.server.request',
      { route: path, method },
      work,
      () => {},
    ));
  const telemetry = observers.telemetry as
    | (Telemetry & {
        withRemoteContext?: <R>(carrier: Readonly<Record<string, string>>, work: () => R) => R;
      })
    | undefined;
  try {
    const carrier: Record<string, string> = {};
    for (const name of ['traceparent', 'tracestate']) {
      const value = headers[name];
      if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
        carrier[name] = value;
    }
    void Promise.resolve(telemetry?.withRemoteContext?.(carrier, invoke)).catch(() => undefined);
  } catch {
    /* The owned invocation remains available after a diagnostic failure. */
  }
  return invoke();
}

/** Request outcomes have a fixed series count independent of registry or tenant count. */
export class Observation {
  private readonly began = performance.now();
  private ended = false;
  private kind: 'handler' | 'http' | 'discovery' | 'unselected';
  constructor(
    private readonly observers: Observers,
    discovery = false,
  ) {
    this.kind = discovery ? 'discovery' : 'unselected';
  }
  lookup(selected: SelectedOperation | null, began: number): void {
    elapsed(this.observers.telemetry, 'arkenivajs.routing.lookup.duration', began);
    if (selected) this.kind = selected.implementation.kind;
    observe(() =>
      this.observers.telemetry?.addCounter('arkenivajs.routing.matches', 1, {
        'routing.match': selected ? 'matched' : 'unmatched',
      }),
    );
  }
  async authorize<T>(work: () => Promise<T>): Promise<T> {
    const began = performance.now();
    try {
      return await work();
    } finally {
      elapsed(this.observers.telemetry, 'arkenivajs.routing.authorization.duration', began);
    }
  }
  async execute<T>(
    selected: SelectedOperation,
    tenant: VerifiedTenantContext,
    revision: string,
    generation: number,
    work: () => Promise<T>,
  ): Promise<T> {
    const began = performance.now();
    try {
      return await instrumentOperation(
        this.observers.telemetry,
        'tenant.routing.operation',
        {
          'routing.kind': selected.implementation.kind,
          'tenant.id': tenant.tenantId,
          'routing.operation': selected.operation.id,
          'routing.implementation': selected.implementation.id,
          'routing.revision': revision,
          'routing.activation_generation': generation,
        },
        work,
        () => {},
      );
    } finally {
      observe(() =>
        this.observers.telemetry?.recordHistogram(
          'arkenivajs.routing.implementation.duration',
          Math.max(0, performance.now() - began) / 1000,
          { 'routing.kind': selected.implementation.kind },
        ),
      );
    }
  }
  finish(status: number): void {
    if (this.ended) return;
    this.ended = true;
    const outcome =
      status === 499
        ? 'aborted'
        : status === 504
          ? 'timeout'
          : status >= 500
            ? 'error'
            : status >= 400
              ? 'rejected'
              : 'ok';
    observe(() =>
      this.observers.telemetry?.addCounter('arkenivajs.routing.requests', 1, {
        'routing.kind': this.kind,
        'routing.outcome': outcome,
      }),
    );
    observe(() =>
      this.observers.telemetry?.recordHistogram(
        'arkenivajs.routing.operation.duration',
        Math.max(0, performance.now() - this.began) / 1000,
        { 'routing.kind': this.kind },
      ),
    );
    if (status >= 400)
      observe(() =>
        this.observers.telemetry?.addCounter('arkenivajs.routing.rejected', 1, {
          'routing.outcome': outcome,
        }),
      );
  }
}
