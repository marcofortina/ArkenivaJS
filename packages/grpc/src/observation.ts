// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { Metadata } from '@grpc/grpc-js';

export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
type ContextualTelemetry = Telemetry & {
  traceHeaders?: () => Readonly<{ traceparent?: string; tracestate?: string }>;
  withRemoteContext?: <T>(
    headers: Readonly<Record<string, string | undefined>>,
    work: () => T,
  ) => T;
};
/** Only the approved trace carrier crosses this boundary; it never grants identity. */
export function injectTrace(observers: Observers, metadata: Metadata): Metadata {
  const owned = metadata.clone();
  try {
    const headers = (observers.telemetry as ContextualTelemetry | undefined)?.traceHeaders?.();
    for (const key of ['traceparent', 'tracestate'] as const) {
      const value = headers?.[key];
      if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
        owned.set(key, value);
    }
  } catch {
    /* A failed trace provider cannot alter authorization or repeat an RPC. */
  }
  return owned;
}
export function remoteTrace<T>(
  observers: Observers,
  metadata: Metadata,
  work: () => Promise<T>,
): Promise<T> {
  let task: Promise<T> | undefined;
  const invoke = () => (task ??= Promise.resolve().then(work));
  try {
    const headers: Record<string, string | undefined> = {};
    for (const key of ['traceparent', 'tracestate']) {
      const values = metadata.get(key),
        value = values.length === 1 ? values[0] : undefined;
      if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
        headers[key] = value;
    }
    const result = (observers.telemetry as ContextualTelemetry | undefined)?.withRemoteContext?.(
      headers,
      invoke,
    );
    void Promise.resolve(result).catch(() => undefined);
  } catch {
    /* Preserve at-most-once business work when diagnostic context fails. */
  }
  return invoke();
}
export const OBSERVATION = Symbol('grpc.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'grpc-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [logger?.id, telemetry?.id].filter((id): id is string => id !== undefined),
    init(context) {
      context.provide<Observers>(OBSERVATION, {
        ...(logger ? { logger: context.require<Logger>(COMPONENTS.logger) } : {}),
        ...(telemetry ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
      });
    },
    close() {},
  };
};
export type Operation = 'unary' | 'serverStream' | 'native';
export class Observation {
  readonly started = performance.now();
  readonly correlationId = randomUUID();
  requestBytes = 0;
  responseBytes = 0;
  constructor(
    private readonly observers: Observers,
    private readonly operation: Operation,
    private readonly side: 'client' | 'server',
  ) {}
  active(value: number): void {
    try {
      this.observers.telemetry?.setGauge('grpc.operations.active', value, {
        'grpc.side': this.side,
      });
    } catch {
      /* Diagnostics cannot change physical admission. */
    }
  }
  finish(code: number, active: number): void {
    const outcome =
      code === 0
        ? 'ok'
        : code === 1
          ? 'cancelled'
          : code === 4
            ? 'deadline'
            : code === 7 || code === 16
              ? 'rejected'
              : 'error';
    const attributes = {
        'grpc.operation': this.operation,
        'grpc.side': this.side,
        'grpc.outcome': outcome,
      },
      label = { 'grpc.operation': this.operation, 'grpc.side': this.side };
    const safe = (work: () => unknown) => {
      try {
        void Promise.resolve(work()).catch(() => undefined);
      } catch {
        /* Diagnostics cannot change RPC outcomes. */
      }
    };
    safe(() =>
      this.observers.logger?.debug('gRPC operation completed', {
        operation: this.operation,
        side: this.side,
        outcome,
        correlationId: this.correlationId,
      }),
    );
    safe(() => this.observers.telemetry?.addCounter('grpc.operations', 1, attributes));
    safe(() =>
      this.observers.telemetry?.recordHistogram(
        'grpc.operation.duration.ms',
        performance.now() - this.started,
        attributes,
      ),
    );
    safe(() =>
      this.observers.telemetry?.recordHistogram(
        'grpc.payload.request.bytes',
        this.requestBytes,
        label,
      ),
    );
    safe(() =>
      this.observers.telemetry?.recordHistogram(
        'grpc.payload.response.bytes',
        this.responseBytes,
        label,
      ),
    );
    this.active(active);
    safe(() =>
      this.observers.telemetry?.setGauge('grpc.process.rss.bytes', process.memoryUsage().rss),
    );
  }
}
