// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('pdf.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'pdf-observation',
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
/** Document diagnostics accept fixed operations/outcomes and actual numeric observations only. */
export function recorder(observers: Observers) {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change document results. */
    }
  };
  return {
    measure(
      name:
        | 'worker.memory.sampled-peak.bytes'
        | 'input.bytes'
        | 'output.bytes'
        | 'pages.per.second'
        | 'native.duration.ms'
        | 'native.cpu.ms',
      value: number,
    ) {
      if (!Number.isFinite(value) || value < 0) return;
      safe(() => observers.telemetry?.recordHistogram('pdf.' + name, value));
    },
    complete(
      operation: 'create' | 'inspect' | 'extract' | 'merge' | 'add',
      outcome: 'ok' | 'error',
      duration: number,
    ) {
      const labels = { 'pdf.operation': operation, 'pdf.outcome': outcome };
      safe(() => observers.logger?.debug('Document operation completed', { operation, outcome }));
      safe(() =>
        observers.telemetry?.recordHistogram('pdf.operation.duration.ms', duration, labels),
      );
    },
  };
}
