// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Plugin, Logger, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { capture, operation, source, failure } from './settings.js';
import { Runtime } from './runtime.js';
import { gzip } from './gzip.js';
import { createZip, iterateZip } from './zip.js';
import type {
  CompressionService,
  DataCompressionPluginSettings,
  ArchiveInputEntry,
} from './contracts.js';
export type * from './contracts.js';

interface Observers {
  readonly logger: Logger | undefined;
  readonly telemetry: Telemetry | undefined;
}
const OBSERVERS = Symbol('compression.observers');
const observers: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'compression-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set([logger?.id, telemetry?.id].filter((id): id is string => id !== undefined)),
    ],
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        logger: logger ? context.require(COMPONENTS.logger) : undefined,
        telemetry: telemetry ? context.require(COMPONENTS.telemetry) : undefined,
      });
    },
    close() {},
  };
};

/** Explicitly registered application-owned compression capability. */
export const COMPRESSION_CAPABILITY: unique symbol = Symbol('arkenivajs.compression');
/** Register bounded native streams and ZIP adapters with the application's existing lifecycle. */
export function dataCompressionPlugin(settings: DataCompressionPluginSettings): Plugin {
  const captured = capture(settings),
    instances = new WeakMap<object, Runtime>();
  const plugin: ComposablePlugin = {
    id: 'data-compression',
    version: '0.1.0',
    capabilities: new Set(['compression']),
    dependencies: ['compression-observers'],
    [SUPPORT_PLUGINS]: [observers],
    init(context) {
      const observer = context.require<Observers>(OBSERVERS),
        safe = (action: () => unknown) => {
          try {
            void Promise.resolve(action()).catch(() => undefined);
          } catch {
            /* Observers never repeat source iteration. */
          }
        },
        runtime = new Runtime(captured, (value) => {
          const attributes = {
            'compression.operation': value.operation,
            'compression.outcome': value.outcome,
          };
          if (observer.telemetry) {
            safe(() =>
              observer.telemetry!.recordHistogram(
                'compression.duration.ms',
                value.durationMs,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.addCounter(
                'compression.compressed.bytes',
                value.compressedBytes,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.addCounter(
                'compression.expanded.bytes',
                value.expandedBytes,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.recordHistogram(
                'compression.ratio',
                value.compressedBytes ? value.expandedBytes / value.compressedBytes : 0,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.recordHistogram(
                'compression.process.cpu.ms',
                value.processCpuMs,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.recordHistogram(
                'compression.process.rss.peak.bytes',
                value.processRssPeakBytes,
                attributes,
              ),
            );
            if (value.durationMs > 0)
              safe(() =>
                observer.telemetry!.recordHistogram(
                  'compression.expanded.bytes_per_second',
                  (value.expandedBytes * 1000) / value.durationMs,
                  attributes,
                ),
              );
          }
          if (observer.logger)
            safe(() =>
              observer.logger!.debug('compression.operation.complete', {
                ...attributes,
                durationMs: value.durationMs,
                compressedBytes: value.compressedBytes,
                expandedBytes: value.expandedBytes,
              }),
            );
        });
      instances.set(context, runtime);
      const service: CompressionService = {
        gzip(input, options) {
          const policy = operation(options, captured);
          return gzip(source(input, captured.maxInputBytes), policy, runtime, false);
        },
        gunzip(input, options) {
          const policy = operation(options, captured);
          return gzip(source(input, captured.maxInputBytes), policy, runtime, true);
        },
        createZip(input, options) {
          const policy = operation(options, captured);
          try {
            if (
              !input ||
              typeof input !== 'object' ||
              (!(Symbol.asyncIterator in input) && !(Symbol.iterator in input))
            )
              throw failure('EK_ARCHIVE_CORRUPT');
          } catch {
            throw failure('EK_ARCHIVE_CORRUPT');
          }
          return createZip(
            input as Iterable<ArchiveInputEntry> | AsyncIterable<ArchiveInputEntry>,
            policy,
            runtime,
          );
        },
        iterateZip(input, options) {
          const policy = operation(options, captured);
          return iterateZip(source(input, captured.maxInputBytes), policy, runtime);
        },
      };
      context.provide(COMPRESSION_CAPABILITY, Object.freeze(service));
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
