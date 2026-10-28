// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry, UsageMeter, MeterSession } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import { instrumentOperation } from '@arkenivajs/core/support';
import type { KafkaHeaders } from './contracts.js';

export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
export const OBSERVATION = Symbol('kafka.observation');
export const observations: SupportPluginFactory = (options) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
      ['meter', COMPONENTS.meter],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = options.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ id: owner.id, capability, key }] : [];
  });
  return {
    id: 'kafka-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map((owner) => owner.id))],
    init(context) {
      context.provide<Observers>(
        OBSERVATION,
        Object.freeze(
          Object.fromEntries(owners.map((owner) => [owner.capability, context.require(owner.key)])),
        ),
      );
    },
    close() {},
  };
};
function runSafely(work: () => unknown, failed: () => void): void {
  try {
    void Promise.resolve(work()).catch(failed);
  } catch {
    failed();
  }
}
/** Attribute values come only from the bounded startup catalog and fixed outcome vocabulary. */
export function recorder(ports: Observers = {}) {
  const consumers = new Map<string, number>();
  const dropped = () => {
    try {
      void Promise.resolve(ports.telemetry?.addCounter('kafka.diagnostics.failures', 1)).catch(
        () => undefined,
      );
    } catch {
      /* Loss reporting cannot recursively report its own failure. */
    }
  };
  const safe = (work: () => unknown) => runSafely(work, dropped);
  return {
    execute<T>(
      cluster: string,
      topic: string,
      operation: 'publish' | 'consume',
      work: () => Promise<T>,
    ): Promise<T> {
      return instrumentOperation(
        ports.telemetry,
        'kafka.' + operation,
        { 'kafka.cluster': cluster, 'kafka.topic': topic },
        work,
        () => safe(() => ports.telemetry?.addCounter('kafka.diagnostics.failures', 1)),
      );
    },
    consumerActive(cluster: string, delta: 1 | -1): void {
      const count = (consumers.get(cluster) ?? 0) + delta;
      consumers.set(cluster, count);
      safe(() =>
        ports.telemetry?.setGauge('kafka.consume.inflight', count, { 'kafka.cluster': cluster }),
      );
    },
    current(): MeterSession | undefined {
      try {
        return ports.meter?.current();
      } catch {
        dropped();
        return undefined;
      }
    },
    bytes(
      direction: 'publish' | 'consume',
      cluster: string,
      topic: string,
      value: Uint8Array | null,
      key: Uint8Array | undefined,
      headers: KafkaHeaders,
      session?: MeterSession,
    ): void {
      let headerBytes = 0;
      for (const [name, entry] of Object.entries(headers)) {
        for (const part of Array.isArray(entry) ? entry : [entry])
          headerBytes +=
            Buffer.byteLength(name) +
            (part === null
              ? 0
              : typeof part === 'string'
                ? Buffer.byteLength(part)
                : part.byteLength);
      }
      for (const [component, count] of [
        ['value', value?.byteLength ?? 0],
        ['key', key?.byteLength ?? 0],
        ['headers', headerBytes],
      ] as const) {
        const name = 'kafka.' + direction + '.' + component + '.bytes';
        safe(() =>
          ports.telemetry?.recordHistogram(name, count, {
            'kafka.cluster': cluster,
            'kafka.topic': topic,
          }),
        );
        safe(() => session?.recordUsage(name, { unit: 'bytes', value: count, source: 'observed' }));
      }
    },
    event(
      cluster: string,
      outcome:
        | 'connected'
        | 'connect-error'
        | 'authentication-error'
        | 'assigned'
        | 'revoked'
        | 'offset-committed'
        | 'offset-error'
        | 'consumer-error'
        | 'lag-unavailable'
        | 'native-uninstrumented',
      topic?: string,
    ): void {
      safe(() =>
        ports.telemetry?.addCounter('kafka.events', 1, {
          'kafka.cluster': cluster,
          'kafka.outcome': outcome,
          ...(topic === undefined ? {} : { 'kafka.topic': topic }),
        }),
      );
      if (outcome === 'native-uninstrumented')
        safe(() => ports.logger?.warn('Native Kafka calls bypass framework instrumentation'));
      else safe(() => ports.logger?.debug('Kafka lifecycle event', { outcome }));
    },
    latency(cluster: string, topic: string, kind: 'delivery' | 'handler', duration: number): void {
      safe(() =>
        ports.telemetry?.recordHistogram('kafka.' + kind + '.duration.ms', duration, {
          'kafka.cluster': cluster,
          'kafka.topic': topic,
        }),
      );
      if (kind === 'delivery')
        safe(() =>
          ports.telemetry?.addCounter('kafka.records.confirmed', 1, {
            'kafka.cluster': cluster,
            'kafka.topic': topic,
          }),
        );
    },
    inFlight(cluster: string, kind: 'publish' | 'consume', value: number): void {
      safe(() =>
        ports.telemetry?.setGauge('kafka.' + kind + '.inflight', value, {
          'kafka.cluster': cluster,
        }),
      );
    },
    lag(cluster: string, topic: string, partition: number, value: bigint): void {
      if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) return;
      safe(() =>
        ports.telemetry?.setGauge('kafka.consumer.lag.records', Number(value), {
          'kafka.cluster': cluster,
          'kafka.topic': topic,
          'kafka.partition': partition,
        }),
      );
    },
  };
}
export type Recorder = ReturnType<typeof recorder>;
