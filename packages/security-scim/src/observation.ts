// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry, UsageMeter } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
export interface Label {
  operation: 'list' | 'get' | 'create' | 'replace' | 'patch' | 'delete' | 'discovery' | 'invalid';
  resource: 'Users' | 'Groups' | 'discovery' | 'unknown';
}
export const OBSERVATION = Symbol('scim.observation');
export const observations: SupportPluginFactory = (options) => {
  const owners = (
    [
      ['telemetry', COMPONENTS.telemetry],
      ['meter', COMPONENTS.meter],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = options.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ id: owner.id, capability, key }] : [];
  });
  return {
    id: 'scim-observation',
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
function safe(work: () => unknown): void {
  try {
    void Promise.resolve(work()).catch(() => undefined);
  } catch {
    /* Diagnostics cannot authorize provisioning or repeat storage mutations. */
  }
}
export function recorder(ports: Observers) {
  return {
    active(count: number): void {
      safe(() => ports.telemetry?.setGauge('scim.operations.active', count));
    },
    payload(label: Label, direction: 'request' | 'response', bytes: number): void {
      safe(() =>
        ports.telemetry?.recordHistogram('scim.payload.json.bytes', bytes, {
          'scim.operation': label.operation,
          'scim.resource': label.resource,
          'scim.direction': direction,
        }),
      );
    },
    complete(
      label: Label,
      duration: number,
      code: string | undefined,
      status: number | undefined,
      uncertain: boolean,
    ): void {
      const outcome = uncertain
        ? 'unknown'
        : code === 'EK_ABORTED'
          ? 'cancelled'
          : code === 'EK_TIMEOUT'
            ? 'timeout'
            : status === 409
              ? 'conflict'
              : status === 412
                ? 'precondition'
                : status !== undefined && status < 400
                  ? 'ok'
                  : status !== undefined && status < 500
                    ? 'rejected'
                    : 'unavailable';
      const attributes = {
        'scim.operation': label.operation,
        'scim.resource': label.resource,
        'scim.outcome': outcome,
      };
      safe(() => ports.telemetry?.addCounter('scim.operations', 1, attributes));
      safe(() =>
        ports.telemetry?.recordHistogram('scim.operation.duration.ms', duration, attributes),
      );
      safe(() =>
        ports.logger?.debug('SCIM operation completed', {
          operation: label.operation,
          resource: label.resource,
          outcome,
        }),
      );
    },
  };
}
