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
  | 'begin_authentication'
  | 'consume_authentication'
  | 'metadata'
  | 'verify_federation_trust'
  | 'health'
  | 'bootstrap';
export const OBSERVATION = Symbol('spid.observation');
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
    id: 'spid-observation',
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
    complete(operation: Operation, error?: unknown) {
      const outcome =
        error === undefined
          ? 'ok'
          : error instanceof KitError
            ? ((
                {
                  EK_EID_FEDERATION: 'federation',
                  EK_EID_ASSURANCE: 'assurance',
                  EK_EID_PROFILE: 'configuration',
                  EK_RESOURCE_CLOSED: 'closed',
                  EK_LIFECYCLE_STATE: 'not_ready',
                  EK_ABORTED: 'cancelled',
                  EK_TIMEOUT: 'timeout',
                } as Record<string, string>
              )[error.code] ?? 'unavailable')
            : 'unavailable';
      const labels = { 'spid.operation': operation, 'spid.outcome': outcome };
      if (operation === 'begin_authentication' || operation === 'consume_authentication')
        safe(() => ports.telemetry?.addCounter('spid.handshakes', 1, labels));
      if (outcome === 'federation')
        safe(() => ports.telemetry?.addCounter('spid.trust.failures', 1, labels));
      safe(() => ports.logger?.debug('SPID operation completed', { operation, outcome }));
    },
  };
}
