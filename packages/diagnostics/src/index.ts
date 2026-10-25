// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance, monitorEventLoopDelay } from 'node:perf_hooks';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import type { Diagnostics, ProcessSnapshot, Plugin } from '@arkenivajs/core';

export type { Diagnostics, ProcessSnapshot } from '@arkenivajs/core';
/** Optional collectors are explicit; the default snapshot starts no histogram. */
export interface DiagnosticsOptions {
  readonly eventLoopUtilization?: boolean;
  readonly eventLoopDelay?: boolean;
  readonly resolutionMs?: number;
}
/** Process-level measurements never represent exact request or tenant resource usage. */
export interface ManagedDiagnostics extends Diagnostics {
  close(): void;
}
/** Units and provenance correspond to the public snapshot field names. */
export const DIAGNOSTIC_SOURCES = Object.freeze({
  cpuUserMicros: Object.freeze({
    scope: 'process',
    source: 'process.cpuUsage().user',
    unit: 'microseconds',
    interval: 'cumulative',
  }),
  cpuSystemMicros: Object.freeze({
    scope: 'process',
    source: 'process.cpuUsage().system',
    unit: 'microseconds',
    interval: 'cumulative',
  }),
  memoryRssBytes: Object.freeze({
    scope: 'process',
    source: 'process.memoryUsage().rss',
    unit: 'bytes',
    interval: 'instantaneous',
  }),
  heapUsedBytes: Object.freeze({
    scope: 'process',
    source: 'process.memoryUsage().heapUsed',
    unit: 'bytes',
    interval: 'instantaneous',
  }),
  eventLoopUtilization: Object.freeze({
    scope: 'process',
    source: 'performance.eventLoopUtilization()',
    unit: 'ratio',
    interval: 'since-last-snapshot',
  }),
  eventLoopDelayP99Ms: Object.freeze({
    scope: 'process',
    source: 'monitorEventLoopDelay().percentile(99)',
    unit: 'milliseconds',
    interval: 'since-last-snapshot',
  }),
});

/** Capture native process values; omit unavailable optional measurements. */
export function createDiagnostics(options: DiagnosticsOptions = {}): ManagedDiagnostics {
  if (
    !options ||
    typeof options !== 'object' ||
    Array.isArray(options) ||
    Object.keys(options).some(
      (key) => !['eventLoopUtilization', 'eventLoopDelay', 'resolutionMs'].includes(key),
    ) ||
    (options.eventLoopDelay !== undefined && typeof options.eventLoopDelay !== 'boolean') ||
    (options.eventLoopUtilization !== undefined &&
      typeof options.eventLoopUtilization !== 'boolean') ||
    (options.resolutionMs !== undefined &&
      (!Number.isSafeInteger(options.resolutionMs) || options.resolutionMs <= 0))
  ) {
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid diagnostics options' });
  }
  const utilization = options.eventLoopUtilization ?? true;
  const histogram = options.eventLoopDelay
    ? monitorEventLoopDelay({ resolution: options.resolutionMs ?? 20 })
    : undefined;
  histogram?.enable();
  let previous = performance.eventLoopUtilization();
  let closed = false;
  return Object.freeze({
    /** Return a frozen instantaneous/cumulative snapshot with an ISO UTC timestamp. */
    snapshot(): ProcessSnapshot {
      if (closed)
        throw new KitError({
          code: 'EK_RESOURCE_CLOSED',
          message: 'Diagnostics collector is closed',
        });
      const cpu = process.cpuUsage();
      const memory = process.memoryUsage();
      const snapshot: {
        timestamp: string;
        processId: number;
        cpuUserMicros: number;
        cpuSystemMicros: number;
        memoryRssBytes: number;
        heapUsedBytes: number;
        eventLoopUtilization?: number;
        eventLoopDelayP99Ms?: number;
      } = {
        timestamp: new Date().toISOString(),
        processId: process.pid,
        cpuUserMicros: cpu.user,
        cpuSystemMicros: cpu.system,
        memoryRssBytes: memory.rss,
        heapUsedBytes: memory.heapUsed,
      };
      if (utilization) {
        const current = performance.eventLoopUtilization();
        const delta = performance.eventLoopUtilization(current, previous);
        previous = current;
        if (delta.active + delta.idle > 0 && Number.isFinite(delta.utilization))
          snapshot.eventLoopUtilization = delta.utilization;
      }
      if (histogram && histogram.count > 0) {
        snapshot.eventLoopDelayP99Ms = histogram.percentile(99) / 1_000_000;
        histogram.reset();
      }
      return Object.freeze(snapshot);
    },
    /** Disable the owned native histogram; repeated close calls have no effect. */
    close(): void {
      if (closed) return;
      closed = true;
      histogram?.disable();
    },
  });
}

/** Install one independent diagnostics collector per application. */
export function diagnosticsPlugin(options: DiagnosticsOptions = {}): Plugin {
  const collectors = new WeakMap<object, ManagedDiagnostics>();
  return {
    id: 'diagnostics',
    version: '0.1.0',
    capabilities: new Set(['diagnostics']),
    init(context) {
      const collector = createDiagnostics(options);
      try {
        context.provide(COMPONENTS.diagnostics, collector);
        collectors.set(context, collector);
      } catch (error) {
        collector.close();
        throw error;
      }
    },
    close(context) {
      collectors.get(context)?.close();
      collectors.delete(context);
    },
  };
}
