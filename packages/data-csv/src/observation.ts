// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { COMPONENTS } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';

export interface Observation {
  readonly operation: 'parse' | 'stringify';
  readonly outcome: 'ok' | 'error' | 'cancelled';
  readonly rows: number;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly durationMs: number;
  readonly processRssPeakBytes: number;
}
export const OBSERVERS = Symbol('csv.observers');
export const observers: SupportPluginFactory = (options) => {
  const telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'csv-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: telemetry ? [telemetry.id] : [],
    init(context) {
      context.provide<Telemetry | undefined>(
        OBSERVERS,
        telemetry ? context.require(COMPONENTS.telemetry) : undefined,
      );
    },
    close() {},
  };
};
/** Only finite operation/outcome labels are emitted; record data never reaches observers. */
export function observer(
  telemetry: Telemetry | undefined,
): ((value: Observation) => void) | undefined {
  if (!telemetry) return undefined;
  return (value) => {
    const attributes = { 'csv.operation': value.operation, 'csv.outcome': value.outcome },
      safe = (action: () => unknown) => {
        try {
          void Promise.resolve(action()).catch(() => undefined);
        } catch {
          /* Telemetry failure cannot change stream results or repeat a source. */
        }
      };
    safe(() => telemetry.addCounter('csv.operations', 1, attributes));
    safe(() => telemetry.addCounter('csv.rows', value.rows, attributes));
    safe(() => telemetry.addCounter('csv.input.bytes', value.inputBytes, attributes));
    safe(() => telemetry.addCounter('csv.output.bytes', value.outputBytes, attributes));
    safe(() => telemetry.recordHistogram('csv.duration.ms', value.durationMs, attributes));
    safe(() =>
      telemetry.recordHistogram(
        'csv.process.rss.peak.bytes',
        value.processRssPeakBytes,
        attributes,
      ),
    );
    if (value.outcome === 'error') safe(() => telemetry.addCounter('csv.errors', 1, attributes));
  };
}
/** Sample actual process RSS while the consumer owns the iterator, including endpoints. */
export function measureStream(
  operation: Observation['operation'],
  observe: ((value: Observation) => void) | undefined,
  signal: AbortSignal,
) {
  if (!observe) return undefined;
  const started = performance.now();
  let peakRss = process.memoryUsage().rss;
  const timer = setInterval(() => {
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
  }, 10);
  timer.unref();
  const stop = () => clearInterval(timer);
  signal.addEventListener('abort', stop, { once: true });
  return (
    outcome: Observation['outcome'],
    rows: number,
    bytes: { inputBytes: number; outputBytes: number },
  ) => {
    clearInterval(timer);
    signal.removeEventListener('abort', stop);
    observe({
      operation,
      outcome,
      rows,
      ...bytes,
      durationMs: Math.max(0, performance.now() - started),
      processRssPeakBytes: Math.max(peakRss, process.memoryUsage().rss),
    });
  };
}
