// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('sftp.observation');
export const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'sftp-observation',
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
/** Diagnostics contain fixed operation names, safe outcomes and numeric counts only. */
export function recorder(observers: Observers) {
  const safe = (work: () => unknown) => {
    try {
      void Promise.resolve(work()).catch(() => undefined);
    } catch {
      /* Diagnostics cannot change transfer results. */
    }
  };
  return {
    measure(
      name:
        | 'connections.active'
        | 'operations.active'
        | 'upload.bytes'
        | 'download.bytes'
        | 'command.output.bytes',
      value: number,
    ) {
      if (Number.isFinite(value) && value >= 0)
        safe(() => observers.telemetry?.recordHistogram('sftp.' + name, value));
    },
    complete(
      operation: 'connect' | 'upload' | 'download' | 'list' | 'rename' | 'exec',
      outcome: 'ok' | 'error',
      duration: number,
    ) {
      safe(() => observers.logger?.debug('SSH operation completed', { operation, outcome }));
      safe(() =>
        observers.telemetry?.recordHistogram('sftp.operation.duration.ms', duration, {
          'sftp.operation': operation,
          'sftp.outcome': outcome,
        }),
      );
    },
  };
}
