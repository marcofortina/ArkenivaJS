// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { AsyncResource } from 'node:async_hooks';
import type { Logger, Telemetry, UsageMeter } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import type { SocketServerKind } from './contracts.js';
import { failure } from './policy.js';

interface Scope {
  withoutScope<T>(work: () => T): T;
}
export interface Observation {
  origin<T>(work: () => T): T;
  run<T>(kind: SocketServerKind, work: () => Promise<T> | T): Promise<T>;
  event(kind: SocketServerKind, event: string, value?: number, outcome?: string): void;
  duration(
    kind: SocketServerKind,
    event: 'handler' | 'handshake',
    milliseconds: number,
    outcome: 'ok' | 'error',
  ): void;
}
export const OBSERVATION = Symbol('socket.observation');
/** Optional already-owned observers; no implicit logging, SDK or metering implementation. */
export const observationPlugin: SupportPluginFactory = (options) => {
  const resources = new WeakMap<object, AsyncResource>();
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry')),
    meter = options.plugins?.find((plugin) => plugin.capabilities.has('meter'));
  return {
    id: 'socket-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set(
        [logger?.id, telemetry?.id, meter?.id].filter((id): id is string => id !== undefined),
      ),
    ],
    init(context) {
      const log = logger ? context.require<Logger & Scope>(COMPONENTS.logger) : undefined,
        trace = telemetry ? context.require<Telemetry & Scope>(COMPONENTS.telemetry) : undefined,
        accounting = meter ? context.require<UsageMeter & Scope>(COMPONENTS.meter) : undefined,
        scopes = [log, trace, accounting].filter((value) => value !== undefined);
      if (scopes.some((value) => typeof value.withoutScope !== 'function'))
        throw failure('EK_PLUGIN_DEPENDENCY');
      const resource = new AsyncResource('arkenivajs.socket.owner');
      resources.set(context, resource);
      const dropped = () => {
        try {
          void Promise.resolve(trace?.addCounter('socket.observation.dropped', 1)).catch(
            () => undefined,
          );
        } catch {
          /* Drop reporting cannot recursively fail. */
        }
      };
      const safe = (action: () => unknown) => {
        try {
          const result = action();
          if (result !== undefined) void Promise.resolve(result).catch(dropped);
        } catch {
          dropped();
        }
      };
      function detached<T>(work: () => T): T {
        let called = false,
          result: T | undefined;
        const enter = (index: number): T => {
          if (index === scopes.length) {
            if (called || accounting?.current() !== undefined) throw failure('EK_SOCKET_STATE');
            called = true;
            return (result = work());
          }
          let entered = false;
          return scopes[index]!.withoutScope(() => {
            if (entered) throw failure('EK_SOCKET_STATE');
            entered = true;
            return enter(index + 1);
          });
        };
        try {
          enter(0);
        } catch (cause) {
          if (!called) throw cause;
          dropped();
        }
        if (!called) throw failure('EK_SOCKET_STATE');
        return result!;
      }
      const attributes = (kind: SocketServerKind, event: string, outcome: string) =>
        Object.freeze({ 'socket.kind': kind, 'socket.event': event, 'socket.outcome': outcome });
      const gauges = new Map<string, number>();
      context.provide<Observation>(OBSERVATION, {
        origin(work) {
          return resource.runInAsyncScope(() => detached(work));
        },
        async run(kind, work) {
          return resource.runInAsyncScope(() =>
            detached(() =>
              instrumentOperation(
                trace,
                'socket.handler',
                attributes(kind, 'handler', 'ok'),
                work,
                dropped,
              ),
            ),
          );
        },
        event(kind, event, value = 1, outcome = 'ok') {
          safe(() =>
            detached(() => {
              const attrs = attributes(kind, event, outcome);
              if (event === 'read' || event === 'write')
                safe(() => trace?.addCounter('socket.payload.bytes', value, attrs));
              else if (event === 'pending' || event === 'active') {
                const key = kind + '/' + event,
                  total = Math.max(0, (gauges.get(key) ?? 0) + value);
                gauges.set(key, total);
                safe(() =>
                  trace?.setGauge(
                    event === 'pending' ? 'socket.pending.bytes' : 'socket.active.connections',
                    total,
                    attrs,
                  ),
                );
              } else safe(() => trace?.addCounter('socket.event.count', value, attrs));
              if (event === 'error' || event === 'dropped' || event === 'rejected')
                safe(() => log?.warn('socket.operation.rejected', attrs));
            }),
          );
        },
        duration(kind, event, milliseconds, outcome) {
          safe(() =>
            detached(() =>
              trace?.recordHistogram(
                `socket.${event}.duration.ms`,
                milliseconds,
                attributes(kind, event, outcome),
              ),
            ),
          );
        },
      });
    },
    close(context) {
      resources.get(context)?.emitDestroy();
      resources.delete(context);
    },
  };
};
