// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('ldap.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'ldap-observation',
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
/** Fixed names and outcomes only; native diagnostics, DNs and credentials are never accepted. */
export function recorder(observers: Observers) {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change authentication results. */
    }
  };
  return {
    measure(name: 'bind' | 'search' | 'depth', value: number) {
      if (name === 'search')
        safe(() => observers.telemetry?.addCounter('ldap.search.count', value));
      else
        safe(() =>
          observers.telemetry?.recordHistogram(
            name === 'bind' ? 'ldap.bind.duration.ms' : 'ldap.group.depth',
            value,
          ),
        );
    },
    complete(operation: string, outcome: 'ok' | 'error' | 'timeout', duration: number) {
      const labels = { 'ldap.operation': operation, 'ldap.outcome': outcome };
      safe(() => observers.logger?.debug('Directory operation completed', { operation, outcome }));
      safe(() =>
        observers.telemetry?.recordHistogram('ldap.operation.duration.ms', duration, labels),
      );
      if (outcome === 'timeout')
        safe(() => observers.telemetry?.addCounter('ldap.timeouts', 1, labels));
    },
  };
}
