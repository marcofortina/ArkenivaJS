// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { Measurement } from './runtime.js';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('xml.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'xml-observation',
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
/** Numeric native facts and fixed labels exclude document contents, schema IDs, paths and diagnostics. */
export function recorder(observers: Observers): (value: Measurement) => void {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change validation outcomes. */
    }
  };
  return (value) => {
    const attributes = { 'xml.operation': value.operation, 'xml.outcome': value.outcome },
      operation = { 'xml.operation': value.operation };
    safe(() =>
      observers.logger?.debug('XML operation completed', {
        operation: value.operation,
        outcome: value.outcome,
      }),
    );
    safe(() => observers.telemetry?.addCounter('xml.operations', 1, attributes));
    if (value.outcome !== 'ok')
      safe(() => observers.telemetry?.addCounter('xml.rejections', 1, attributes));
    safe(() =>
      observers.telemetry?.recordHistogram(
        'xml.operation.duration.ms',
        value.durationMs,
        attributes,
      ),
    );
    safe(() =>
      observers.telemetry?.recordHistogram('xml.input.bytes', value.inputBytes, operation),
    );
    safe(() =>
      observers.telemetry?.recordHistogram('xml.output.bytes', value.outputBytes, operation),
    );
    if (value.heapBytes > 0)
      safe(() =>
        observers.telemetry?.recordHistogram(
          'xml.worker.heap.used.bytes',
          value.heapBytes,
          operation,
        ),
      );
    safe(() => observers.telemetry?.setGauge('xml.process.rss.bytes', process.memoryUsage().rss));
  };
}
