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
export const OBSERVATION = Symbol('json.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'json-observation',
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
/** Fixed metric labels and approved deployment IDs exclude payloads and caller-selected unknown IDs. */
export function recorder(observers: Observers): (value: Measurement) => void {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change native decisions. */
    }
  };
  return (value) => {
    const attributes = { 'json.operation': value.operation, 'json.outcome': value.outcome },
      operation = { 'json.operation': value.operation };
    safe(() =>
      observers.logger?.debug('JSON operation completed', {
        operation: value.operation,
        outcome: value.outcome,
        ...(value.mappingId
          ? { mappingId: value.mappingId, mappingVersion: value.mappingVersion }
          : {}),
      }),
    );
    safe(() => observers.telemetry?.addCounter('json.operations', 1, attributes));
    if (value.outcome !== 'ok')
      safe(() => observers.telemetry?.addCounter('json.rejections', 1, attributes));
    safe(() =>
      observers.telemetry?.recordHistogram(
        'json.operation.duration.ms',
        value.durationMs,
        attributes,
      ),
    );
    safe(() =>
      observers.telemetry?.recordHistogram('json.input.bytes', value.inputBytes, operation),
    );
    safe(() =>
      observers.telemetry?.recordHistogram('json.output.bytes', value.outputBytes, operation),
    );
    if (value.heapBytes > 0)
      safe(() =>
        observers.telemetry?.recordHistogram(
          'json.worker.heap.used.bytes',
          value.heapBytes,
          operation,
        ),
      );
    safe(() => observers.telemetry?.setGauge('json.process.rss.bytes', process.memoryUsage().rss));
  };
}
