// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { ItalianIdentitySystem } from './contracts.js';
import { property } from './validation.js';
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
export function observationPlugin(system: ItalianIdentitySystem) {
  const key = Symbol(system + '.observation');
  const factory: SupportPluginFactory = (options) => {
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
      id: system + '-observation',
      version: '0.1.0',
      capabilities: new Set(),
      dependencies: [...new Set(owners.map((owner) => owner.id))],
      init(context) {
        context.provide<Observers>(
          key,
          Object.freeze(
            Object.fromEntries(
              owners.map((owner) => [owner.capability, context.require(owner.key)]),
            ),
          ),
        );
      },
      close() {},
    };
  };
  return { key, factory };
}
const spidObservation = observationPlugin('spid');
export const OBSERVATION = spidObservation.key;
export const observations = spidObservation.factory;
const safe = (work: () => unknown) => {
  try {
    void Promise.resolve(work()).catch(() => undefined);
  } catch {
    /* Observation cannot alter authentication or replay work. */
  }
};
export function recorder(ports: Observers, system: ItalianIdentitySystem = 'spid') {
  return {
    complete(operation: Operation, error?: unknown, durationMs?: number) {
      let outcome = error === undefined ? 'ok' : 'unavailable';
      if (error !== undefined) {
        try {
          const code = property(error, 'code');
          const categories: Readonly<Record<string, string>> = {
            EK_EID_FEDERATION: 'federation',
            EK_EID_ASSURANCE: 'assurance',
            EK_EID_PROFILE: 'configuration',
            EK_RESOURCE_CLOSED: 'closed',
            EK_LIFECYCLE_STATE: 'not_ready',
            EK_ABORTED: 'cancelled',
            EK_TIMEOUT: 'timeout',
          };
          if (typeof code === 'string' && Object.hasOwn(categories, code))
            outcome = categories[code]!;
        } catch {
          // Executable error properties are not diagnostic input.
        }
      }
      const labels = { [system + '.operation']: operation, [system + '.outcome']: outcome };
      if (system === 'cie') {
        if (
          (operation === 'begin_authentication' || operation === 'consume_authentication') &&
          typeof durationMs === 'number' &&
          Number.isFinite(durationMs) &&
          durationMs >= 0
        )
          safe(() =>
            ports.telemetry?.recordHistogram(
              'cie.authentication.duration',
              durationMs / 1000,
              labels,
            ),
          );
        if (['metadata', 'verify_federation_trust', 'health', 'bootstrap'].includes(operation))
          safe(() => ports.telemetry?.addCounter('cie.federation.checks', 1, labels));
        if (outcome !== 'ok') safe(() => ports.telemetry?.addCounter('cie.failures', 1, labels));
        safe(() => ports.logger?.debug('CIE operation completed', { operation, outcome }));
        return;
      }
      if (operation === 'begin_authentication' || operation === 'consume_authentication')
        safe(() => ports.telemetry?.addCounter('spid.handshakes', 1, labels));
      if (outcome === 'federation')
        safe(() => ports.telemetry?.addCounter('spid.trust.failures', 1, labels));
      safe(() => ports.logger?.debug('SPID operation completed', { operation, outcome }));
    },
  };
}
