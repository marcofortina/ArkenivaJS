// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export type Operation =
  | 'begin_login'
  | 'consume_response'
  | 'metadata'
  | 'begin_logout'
  | 'consume_logout_response'
  | 'bootstrap';
export const OBSERVATION = Symbol('saml.observation');
export const observations: SupportPluginFactory = (options) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = options.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ id: owner.id, capability, key }] : [];
  });
  return {
    id: 'saml-observation',
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
const safe = (work: () => unknown) => {
  try {
    void Promise.resolve(work()).catch(() => undefined);
  } catch {
    /* Observation cannot alter authentication or replay work. */
  }
};
export function recorder(ports: Observers) {
  return {
    capacity(count: number) {
      safe(() => ports.telemetry?.setGauge('saml.operations.active', count));
    },
    complete(operation: Operation, duration: number, error?: unknown) {
      const outcome =
        error === undefined
          ? 'ok'
          : error instanceof KitError
            ? ((
                {
                  EK_SAML_SIGNATURE: 'signature',
                  EK_SAML_ASSERTION: 'assertion',
                  EK_SAML_REPLAY: 'replay',
                  EK_SAML_CONFIGURATION: 'configuration',
                  EK_ABORTED: 'cancelled',
                  EK_TIMEOUT: 'timeout',
                } as Record<string, string>
              )[error.code] ?? 'unavailable')
            : 'unavailable';
      const labels = { 'saml.operation': operation, 'saml.outcome': outcome };
      safe(() => ports.telemetry?.addCounter('saml.operations', 1, labels));
      safe(() => ports.telemetry?.recordHistogram('saml.operation.duration.ms', duration, labels));
      safe(() => ports.logger?.debug('SAML operation completed', { operation, outcome }));
    },
  };
}
