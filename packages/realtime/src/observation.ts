// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';

export type DisconnectReason =
  | 'closed'
  | 'shutdown'
  | 'backpressure'
  | 'authorization'
  | 'idle'
  | 'provider'
  | 'invalid_message';
export interface Ports {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
}
export const OBSERVATION = Symbol('realtime.observation');
export const observationSupport: SupportPluginFactory = (root) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
    ] as const
  ).flatMap(([capability, key]) => {
    const owner = root.plugins?.find((plugin) => plugin.capabilities.has(capability));
    return owner ? [{ capability, key, id: owner.id }] : [];
  });
  return {
    id: 'realtime-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map((owner) => owner.id))],
    init(context) {
      context.provide<Ports>(
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
    /* Diagnostics never alter stream delivery or authorization. */
  }
};
/** Only aggregate, closed-cardinality diagnostics leave the transport owner. */
export class Observation {
  private readonly active = { websocket: 0, sse: 0 };
  private readonly queued = { websocket: 0, sse: 0 };
  constructor(readonly ports: Ports) {}
  connected(protocol: 'websocket' | 'sse'): void {
    this.active[protocol]++;
    safe(() =>
      this.ports.telemetry?.setGauge('realtime.connections.active', this.active[protocol], {
        'realtime.protocol': protocol,
      }),
    );
  }
  queue(protocol: 'websocket' | 'sse', delta: number): void {
    this.queued[protocol] += delta;
    safe(() =>
      this.ports.telemetry?.setGauge('realtime.queue.bytes', this.queued[protocol], {
        'realtime.protocol': protocol,
      }),
    );
  }
  bytes(protocol: 'websocket' | 'sse', side: 'send' | 'receive', count: number): void {
    safe(() =>
      this.ports.telemetry?.addCounter(
        side === 'send' ? 'realtime.sent.bytes' : 'realtime.received.bytes',
        count,
        { 'realtime.protocol': protocol },
      ),
    );
  }
  disconnected(protocol: 'websocket' | 'sse', reason: DisconnectReason): void {
    this.active[protocol]--;
    safe(() =>
      this.ports.telemetry?.setGauge('realtime.connections.active', this.active[protocol], {
        'realtime.protocol': protocol,
      }),
    );
    safe(() =>
      this.ports.telemetry?.addCounter('realtime.disconnects', 1, {
        'realtime.protocol': protocol,
        'realtime.reason': reason,
      }),
    );
    safe(() => this.ports.logger?.debug('Realtime connection closed', { protocol, reason }));
  }
}
