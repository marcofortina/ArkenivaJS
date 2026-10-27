// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('xlsx.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'xlsx-observation',
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
/** Workbook diagnostics contain fixed operation names and numeric measurements only. */
export function recorder(observers: Observers) {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change workbook results. */
    }
  };
  return {
    measure(
      name:
        | 'worker.memory.sampled-peak.bytes'
        | 'input.bytes'
        | 'output.bytes'
        | 'first-row.duration.ms'
        | 'cells.per.second'
        | 'cells',
      value: number,
    ) {
      if (!Number.isFinite(value) || value < 0) return;
      safe(() => observers.telemetry?.recordHistogram('xlsx.' + name, value));
    },
    complete(operation: 'open' | 'read' | 'write', outcome: 'ok' | 'error', duration: number) {
      const labels = { 'xlsx.operation': operation, 'xlsx.outcome': outcome };
      safe(() => observers.logger?.debug('Workbook operation completed', { operation, outcome }));
      safe(() =>
        observers.telemetry?.recordHistogram('xlsx.operation.duration.ms', duration, labels),
      );
    },
  };
}
