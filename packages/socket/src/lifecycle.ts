// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type {
  SocketServerBinding,
  SocketServerHandle,
  SocketServerKind,
  SocketServerState,
  SocketStats,
} from './contracts.js';
import { failure, operation } from './policy.js';

export interface Counters {
  acceptedConnections: number;
  activeConnections: number;
  rejectedConnections: number;
  receivedApplicationBytes: number;
  sentApplicationBytes: number;
  droppedDatagrams: number;
  errors: number;
}
export const counters = (): Counters => ({
  acceptedConnections: 0,
  activeConnections: 0,
  rejectedConnections: 0,
  receivedApplicationBytes: 0,
  sentApplicationBytes: 0,
  droppedDatagrams: 0,
  errors: 0,
});
export interface Driver {
  open(signal: AbortSignal): Promise<SocketServerBinding>;
  drain(): Promise<void>;
  force(): void;
}
/** One admission state machine owns every native listener and cancellation path. */
export function lifecycle(
  name: string,
  kind: SocketServerKind,
  shutdownMs: number,
  stats: Counters,
  driver: Driver,
): SocketServerHandle {
  let state: SocketServerState = 'CREATED',
    binding: SocketServerBinding | undefined,
    starting: Promise<SocketServerBinding> | undefined,
    stopping: Promise<void> | undefined;
  const lifetime = new AbortController();
  async function bounded<T>(
    work: () => Promise<T>,
    input: OperationOptions | undefined,
  ): Promise<T> {
    const policy = operation(input, shutdownMs);
    if (policy.signal?.aborted) throw failure('EK_ABORTED');
    const deadline = performance.now() + policy.timeoutMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancel = () => {};
    try {
      return await Promise.race([
        Promise.resolve()
          .then(work)
          .then((value) => {
            if (performance.now() >= deadline) {
              lifetime.abort();
              driver.force();
              throw failure('EK_TIMEOUT');
            }
            return value;
          }),
        new Promise<never>((_, reject) => {
          cancel = () => {
            lifetime.abort();
            driver.force();
            reject(failure('EK_ABORTED'));
          };
          policy.signal?.addEventListener('abort', cancel, { once: true });
          timer = setTimeout(() => {
            lifetime.abort();
            driver.force();
            reject(failure('EK_TIMEOUT'));
          }, policy.timeoutMs);
          if (policy.signal?.aborted) cancel();
        }),
      ]);
    } finally {
      clearTimeout(timer);
      policy.signal?.removeEventListener('abort', cancel);
    }
  }
  return Object.freeze({
    name,
    kind,
    get state() {
      return state;
    },
    get boundAddress() {
      return binding;
    },
    start(input?: OperationOptions) {
      operation(input, shutdownMs);
      if (state === 'LISTENING') return Promise.resolve(binding!);
      if (starting && state === 'CREATED') return starting;
      if (state !== 'CREATED') return Promise.reject(failure('EK_SOCKET_STATE'));
      starting = bounded(() => driver.open(lifetime.signal), input).then(
        (value) => {
          if (state !== 'CREATED' || lifetime.signal.aborted) {
            driver.force();
            throw failure('EK_SOCKET_CLOSED');
          }
          binding = value;
          state = 'LISTENING';
          return value;
        },
        (cause) => {
          if (state === 'CREATED') state = 'FAILED';
          lifetime.abort();
          driver.force();
          throw cause;
        },
      );
      return starting;
    },
    stop(input?: OperationOptions) {
      const policy = operation(input, shutdownMs);
      if (state === 'CLOSED')
        return policy.signal?.aborted ? Promise.reject(failure('EK_ABORTED')) : Promise.resolve();
      if (stopping) return stopping;
      state = 'DRAINING';
      stopping = bounded(async () => {
        if (starting) await starting.catch(() => undefined);
        await driver.drain();
      }, input).finally(() => {
        lifetime.abort();
        driver.force();
        state = 'CLOSED';
      });
      return stopping;
    },
    stats(): SocketStats {
      return Object.freeze({ ...stats, state, observedAt: new Date().toISOString() });
    },
  });
}
