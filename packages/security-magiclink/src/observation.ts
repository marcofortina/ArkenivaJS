// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { MagicLinkIntent } from './contracts.js';

export interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export interface Label {
  readonly operation: 'startup' | 'issue' | 'consume' | 'revoke';
  readonly purpose: MagicLinkIntent | 'none';
}
export const OBSERVATION = Symbol('magiclink.observation');
export const observations: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'magiclink-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      context.provide<Telemetry | undefined>(
        OBSERVATION,
        owner ? context.require<Telemetry>(COMPONENTS.telemetry) : undefined,
      );
    },
    close() {},
  };
};
function safe(work: () => unknown): void {
  try {
    void Promise.resolve(work()).catch(() => undefined);
  } catch {
    /* Diagnostics never authorize or repeat credential work. */
  }
}
export function active(observers: Observers, value: number): void {
  safe(() => observers.telemetry?.setGauge('magiclink.operations.active', value));
}
/** Credentials, URL fragments, account bindings, digests and key references are never event fields. */
export function record(
  observers: Observers,
  label: Label,
  code: string | undefined,
  duration: number,
  correlationId: string,
): void {
  const outcome =
    code === undefined
      ? 'ok'
      : code === 'EK_MAGICLINK_EXPIRED'
        ? 'expired'
        : code === 'EK_MAGICLINK_REPLAY'
          ? 'replay'
          : code === 'EK_MAGICLINK_INVALID'
            ? 'rejected'
            : 'error';
  const attributes = {
      'magiclink.operation': label.operation,
      'magiclink.intent': label.purpose,
      'magiclink.outcome': outcome,
    },
    purpose = { 'magiclink.intent': label.purpose };
  safe(() =>
    observers.logger?.debug('Magic link operation completed', {
      operation: label.operation,
      intent: label.purpose,
      outcome,
      correlationId,
    }),
  );
  safe(() => observers.telemetry?.addCounter('magiclink.operations', 1, attributes));
  safe(() =>
    observers.telemetry?.recordHistogram('magiclink.operation.duration.ms', duration, attributes),
  );
  if (code === undefined && label.operation === 'issue')
    safe(() => observers.telemetry?.addCounter('magiclink.issued', 1, purpose));
  if (code === undefined && label.operation === 'consume')
    safe(() => observers.telemetry?.addCounter('magiclink.consumed', 1, purpose));
  if (outcome === 'expired')
    safe(() => observers.telemetry?.addCounter('magiclink.expired', 1, purpose));
  if (outcome === 'replay')
    safe(() => observers.telemetry?.addCounter('magiclink.replays', 1, purpose));
  safe(() =>
    observers.telemetry?.setGauge('magiclink.process.rss.bytes', process.memoryUsage().rss),
  );
}
