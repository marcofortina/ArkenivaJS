// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('amqp.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'amqp-observation',
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
/** Diagnostics never contain credentials, URIs, topology names, message IDs, headers or payloads. */
export function recorder(observers: Observers) {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot affect broker outcomes. */
    }
  };
  return {
    event(
      outcome:
        | 'connect'
        | 'disconnect'
        | 'reconnect'
        | 'policy'
        | 'delivered'
        | 'acked'
        | 'nacked'
        | 'redelivered'
        | 'handler-error'
        | 'ack-uncertain',
      bytes = 0,
    ) {
      safe(() => observers.telemetry?.addCounter('amqp.events', 1, { 'amqp.outcome': outcome }));
      if (outcome === 'delivered')
        safe(() => observers.telemetry?.recordHistogram('amqp.delivery.bytes', bytes));
    },
    complete(
      operation: 'connect' | 'publish' | 'subscribe' | 'health' | 'unsubscribe',
      outcome: 'ok' | 'error' | 'confirmed' | 'unroutable' | 'unknown',
      duration: number,
    ) {
      safe(() => observers.logger?.debug('AMQP operation completed', { operation, outcome }));
      safe(() =>
        observers.telemetry?.recordHistogram('amqp.operation.duration.ms', duration, {
          'amqp.operation': operation,
          'amqp.outcome': outcome,
        }),
      );
      if (operation === 'publish')
        safe(() =>
          observers.telemetry?.addCounter('amqp.publications', 1, { 'amqp.outcome': outcome }),
        );
    },
    publication(bytes: number, inFlight: number) {
      safe(() => observers.telemetry?.recordHistogram('amqp.publish.bytes', bytes));
      safe(() => observers.telemetry?.setGauge('amqp.publish.inflight', inFlight));
    },
    inFlight(value: number) {
      safe(() => observers.telemetry?.setGauge('amqp.publish.inflight', value));
    },
  };
}
