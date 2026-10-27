// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import type { Logger, Telemetry } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';

export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export function observation(observers: Observers) {
  const record = (operation: 'issue' | 'verify', outcome: 'ok' | 'error', duration?: number) => {
    const labels = { 'security.http.operation': operation, 'security.http.outcome': outcome };
    try {
      if (outcome === 'error')
        observers.telemetry?.addCounter('security.http.csrf.rejections', 1, labels);
      if (duration !== undefined)
        observers.telemetry?.recordHistogram('security.http.duration.ms', duration, labels);
    } catch {
      /* Observer failure never changes an authorization decision. */
    }
    try {
      observers.logger?.debug('HTTP security operation completed', { operation, outcome });
    } catch {
      /* No request, token, cookie, identity or provider exception is diagnostic data. */
    }
  };
  return {
    reject() {
      record('verify', 'error');
    },
    async run<T>(operation: 'issue' | 'verify', work: () => Promise<T>): Promise<T> {
      const started = performance.now();
      let outcome: 'ok' | 'error' = 'error';
      try {
        const result = await instrumentOperation(
          observers.telemetry,
          'security.http.csrf',
          { 'security.http.operation': operation },
          work,
          () => {
            try {
              observers.logger?.warn('HTTP security instrumentation unavailable', { operation });
            } catch {
              /* Authorization remains independent of diagnostics. */
            }
          },
        );
        outcome = 'ok';
        return result;
      } finally {
        record(operation, outcome, performance.now() - started);
      }
    },
  };
}
