// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import dgram from 'node:dgram';
import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type {
  UdpDatagram,
  UdpDatagramHandler,
  UdpSocketHandle,
  SocketNetworkAddress,
} from './contracts.js';
import { address, addressKey, capture, failure, operation, payload } from './policy.js';
import { counters, lifecycle } from './lifecycle.js';
import type { Observation } from './observation.js';

type Policy = ReturnType<typeof capture>;
/** Native datagram ownership authenticates only the reply target, never the sender's identity. */
export function udpServer(
  input: Policy,
  handler: UdpDatagramHandler,
  observation: Observation,
): UdpSocketHandle {
  if (!('family' in input)) throw failure('EK_SOCKET_CONFIG');
  const policy = input;
  const stats = counters(),
    queue: UdpDatagram[] = [],
    origins = new WeakMap<
      object,
      { remote: SocketNetworkAddress; received: number; sent: number; active: boolean }
    >(),
    pending = new Set<Promise<void>>();
  let socket: dgram.Socket | undefined,
    active = 0,
    activeBytes = 0,
    queuedBytes = 0,
    draining = false,
    closing: Promise<void> | undefined;
  const force = () => {
    draining = true;
    if (queue.length) {
      stats.droppedDatagrams += queue.length;
      observation.event('udp', 'dropped', queue.length, 'capacity');
    }
    queue.length = 0;
    queuedBytes = 0;
    if (socket) {
      try {
        socket.close();
      } catch {
        /* Unbound native sockets are already closed. */
      }
    }
  };
  const pump = () => {
    while (
      !draining &&
      active < policy.maxConcurrentHandlers &&
      queue.length &&
      activeBytes + queue[0]!.bytes.length <= 16777216
    ) {
      const value = queue.shift()!,
        origin = origins.get(value)!;
      active++;
      activeBytes += value.bytes.length;
      queuedBytes -= value.bytes.length;
      const started = performance.now();
      let outcome: 'ok' | 'error' = 'ok';
      const work = Promise.resolve()
        .then(() => observation.run('udp', () => handler(value, handle)))
        .catch(() => {
          outcome = 'error';
          stats.errors++;
          observation.event('udp', 'error', 1, 'error');
        })
        .finally(() => {
          origin.active = false;
          active--;
          activeBytes -= origin.received;
          pending.delete(work);
          observation.duration('udp', 'handler', Math.max(0, performance.now() - started), outcome);
          pump();
        });
      pending.add(work);
    }
  };
  const base = lifecycle(policy.name, 'udp', policy.shutdownTimeoutMs, stats, {
    open(signal) {
      return observation.origin(
        () =>
          new Promise((resolve, reject) => {
            if (signal.aborted) {
              reject(failure('EK_ABORTED'));
              return;
            }
            socket = dgram.createSocket({
              type: policy.family,
              ...(policy.family === 'udp6' ? { ipv6Only: policy.ipv6Only } : {}),
              signal,
            });
            let bound = false;
            socket.on('error', (cause) => {
              stats.errors++;
              if (!bound) reject(failure('EK_SOCKET_BIND', cause));
            });
            socket.on('close', () => {
              if (!bound) reject(failure('EK_SOCKET_CLOSED'));
            });
            socket.on('message', (bytes, remote) => {
              stats.receivedApplicationBytes += bytes.length;
              observation.event('udp', 'received');
              observation.event('udp', 'read', bytes.length);
              if (
                draining ||
                bytes.length > policy.maxDatagramBytes ||
                queue.length >= policy.maxQueuedDatagrams ||
                queuedBytes + bytes.length > 8388608
              ) {
                stats.droppedDatagrams++;
                observation.event('udp', 'dropped', 1, 'capacity');
                return;
              }
              try {
                const peer = address({
                    address: remote.address,
                    port: remote.port,
                    family: remote.family,
                  }),
                  value = Object.freeze({
                    bytes: Uint8Array.from(bytes),
                    remote: peer,
                    receivedAt: new Date().toISOString(),
                  });
                origins.set(value, { remote: peer, received: bytes.length, sent: 0, active: true });
                queue.push(value);
                queuedBytes += bytes.length;
                pump();
              } catch {
                stats.errors++;
                stats.droppedDatagrams++;
                observation.event('udp', 'dropped', 1, 'error');
              }
            });
            socket.bind({ address: policy.host, port: policy.port, exclusive: true }, () => {
              if (signal.aborted || draining) {
                force();
                reject(failure('EK_ABORTED'));
                return;
              }
              bound = true;
              const native = socket!.address();
              resolve(
                Object.freeze({
                  kind: 'udp',
                  network: address({
                    address: native.address,
                    port: native.port,
                    family: native.family,
                  }),
                }),
              );
            });
          }),
      );
    },
    async drain() {
      draining = true;
      stats.droppedDatagrams += queue.length;
      if (queue.length) observation.event('udp', 'dropped', queue.length, 'capacity');
      queue.length = 0;
      queuedBytes = 0;
      if (!closing)
        closing = (async () => {
          // Running callbacks may finish bounded replies while new datagrams are rejected.
          await Promise.allSettled([...pending]);
          if (socket)
            await new Promise<void>((resolve) => {
              socket!.once('close', resolve);
              try {
                socket!.close();
              } catch {
                resolve();
              }
            });
        })();
      await closing;
    },
    force,
  });
  let sends = 0,
    sendBytes = 0;
  async function send(
    target: SocketNetworkAddress,
    bytes: Buffer,
    input?: OperationOptions,
  ): Promise<void> {
    const options = operation(input, policy.shutdownTimeoutMs);
    if (options.signal?.aborted) throw failure('EK_ABORTED');
    if ((base.state !== 'LISTENING' && base.state !== 'DRAINING') || !socket)
      throw failure('EK_SOCKET_CLOSED');
    if (target.family !== (policy.family === 'udp4' ? 'IPv4' : 'IPv6'))
      throw failure('EK_SOCKET_DATAGRAM');
    if (sends >= policy.maxConcurrentHandlers || sendBytes + bytes.length > 16777216)
      throw failure('EK_SOCKET_CAPACITY');
    const started = performance.now();
    sends++;
    sendBytes += bytes.length;
    let timer: ReturnType<typeof setTimeout> | undefined,
      cancel = () => {};
    try {
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (error?: unknown) => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve();
        };
        cancel = () => finish(failure('EK_ABORTED'));
        options.signal?.addEventListener('abort', cancel, { once: true });
        timer = setTimeout(() => finish(failure('EK_TIMEOUT')), options.timeoutMs);
        if (options.signal?.aborted) {
          sends--;
          sendBytes -= bytes.length;
          cancel();
          return;
        }
        try {
          socket!.send(bytes, target.port, target.address, (error) => {
            sends--;
            sendBytes -= bytes.length;
            if (error) {
              stats.errors++;
              finish(failure('EK_SOCKET_IO', error));
            } else {
              stats.sentApplicationBytes += bytes.length;
              observation.event('udp', 'sent');
              observation.event('udp', 'write', bytes.length);
              finish(
                performance.now() - started >= options.timeoutMs
                  ? failure('EK_TIMEOUT')
                  : undefined,
              );
            }
          });
        } catch (cause) {
          sends--;
          sendBytes -= bytes.length;
          stats.errors++;
          finish(failure('EK_SOCKET_IO', cause));
        }
      });
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', cancel);
    }
  }
  const handle: UdpSocketHandle = Object.freeze({
    get name() {
      return base.name;
    },
    get kind() {
      return base.kind;
    },
    get state() {
      return base.state;
    },
    get boundAddress() {
      return base.boundAddress;
    },
    start: base.start,
    stop: base.stop,
    stats: base.stats,
    async reply(input: UdpDatagram, data: Uint8Array, options?: OperationOptions) {
      const origin = input && typeof input === 'object' ? origins.get(input) : undefined;
      if (!origin || !origin.active) throw failure('EK_SOCKET_DATAGRAM');
      const bytes = payload(
        data,
        Math.min(policy.maxReplyBytes, origin.received * policy.maxReplyAmplificationFactor) -
          origin.sent,
        'EK_SOCKET_DATAGRAM',
      );
      // Reserve the total amplification budget before awaiting a native send callback.
      origin.sent += bytes.length;
      await send(origin.remote, bytes, options);
    },
    async sendTo(input: SocketNetworkAddress, data: Uint8Array, options?: OperationOptions) {
      const target = address(input);
      if (!policy.allowlist.has(addressKey(target))) throw failure('EK_SOCKET_DATAGRAM');
      await send(target, payload(data, policy.maxReplyBytes, 'EK_SOCKET_DATAGRAM'), options);
    },
  });
  return handle;
}
