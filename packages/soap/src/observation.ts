// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { Call } from './calls.js';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('soap.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((entry) => entry.capabilities.has('logger')),
    telemetry = options.plugins?.find((entry) => entry.capabilities.has('telemetry'));
  return {
    id: 'soap-observation',
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
export type Operation = 'startup' | 'createClient' | 'call' | 'nativeCall';
/** Payloads, endpoints, secret references and identities are never diagnostic fields. */
export function record(
  observers: Observers,
  operation: Operation,
  call: Call,
  outcome: 'ok' | 'error' | 'fault',
  duration: number,
  active: number,
): void {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot alter native outcomes. */
    }
  };
  const attributes = { 'soap.operation': operation, 'soap.outcome': outcome },
    label = { 'soap.operation': operation };
  safe(() =>
    observers.logger?.debug('SOAP operation completed', {
      operation,
      outcome,
      correlationId: call.id,
    }),
  );
  safe(() => observers.telemetry?.addCounter('soap.operations', 1, attributes));
  if (outcome === 'fault') safe(() => observers.telemetry?.addCounter('soap.faults', 1, label));
  safe(() =>
    observers.telemetry?.recordHistogram('soap.operation.duration.ms', duration, attributes),
  );
  safe(() =>
    observers.telemetry?.recordHistogram('soap.payload.request.bytes', call.inputBytes, label),
  );
  safe(() =>
    observers.telemetry?.recordHistogram('soap.payload.response.bytes', call.outputBytes, label),
  );
  safe(() => observers.telemetry?.setGauge('soap.operations.active', active));
  safe(() => observers.telemetry?.setGauge('soap.process.rss.bytes', process.memoryUsage().rss));
}
