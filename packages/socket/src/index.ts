// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin, PluginContext } from '@arkenivajs/core';
import { APPLICATION_SIGNAL } from '@arkenivajs/core';
import { ACTIVATE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import type {
  SocketListenerDefinition,
  SocketPluginOptions,
  SocketServerHandle,
  SocketService,
  TcpSocketOptions,
  TlsSocketOptions,
  UnixSocketOptions,
  UdpSocketOptions,
  SocketPeerHandler,
  UdpDatagramHandler,
} from './contracts.js';
import { array, capture, failure, fields } from './policy.js';
import type { Captured } from './policy.js';
import { streamServer } from './stream.js';
import { udpServer } from './udp.js';
import { OBSERVATION, observationPlugin } from './observation.js';
import type { Observation } from './observation.js';
export type * from './contracts.js';
export {
  DEFAULT_SOCKET_MAX_CONNECTIONS,
  DEFAULT_SOCKET_IDLE_TIMEOUT_MS,
  DEFAULT_SOCKET_MAX_PENDING_WRITE_BYTES,
  DEFAULT_SOCKET_SHUTDOWN_TIMEOUT_MS,
  DEFAULT_SOCKET_TLS_HANDSHAKE_TIMEOUT_MS,
  DEFAULT_UDP_MAX_DATAGRAM_BYTES,
  DEFAULT_UDP_MAX_CONCURRENT_HANDLERS,
  DEFAULT_UDP_MAX_QUEUED_DATAGRAMS,
  DEFAULT_UDP_MAX_REPLY_BYTES,
} from './policy.js';

export const SOCKET_CAPABILITY: unique symbol = Symbol('arkenivajs.socket');
/** Native listeners are explicit application resources; imports and factory validation never bind. */
export function socketPlugin(input?: SocketPluginOptions): Plugin {
  const settings = fields(input === undefined ? {} : input, ['listeners']),
    names = new Set<string>(),
    endpoints = new Set<string>();
  const definitions = array(settings.listeners === undefined ? [] : settings.listeners, 128).map(
    (value) => {
      const definition = fields(value, ['kind', 'options', 'handler']);
      if (
        !['tcp', 'tls', 'unix', 'udp'].includes(definition.kind as string) ||
        typeof definition.handler !== 'function'
      )
        throw failure('EK_SOCKET_CONFIG');
      const kind = definition.kind as SocketListenerDefinition['kind'],
        policy = capture(kind, definition.options);
      if (names.has(policy.name)) throw failure('EK_SOCKET_CONFIG');
      names.add(policy.name);
      const endpoint =
        'path' in policy
          ? 'unix/' + policy.path
          : policy.port === 0
            ? undefined
            : `${kind === 'udp' ? 'udp' : 'stream'}/${policy.host}/${policy.port}`;
      if (endpoint && endpoints.has(endpoint)) throw failure('EK_SOCKET_CONFIG');
      if (endpoint) endpoints.add(endpoint);
      return {
        kind,
        policy,
        handler: definition.handler as SocketPeerHandler | UdpDatagramHandler,
      };
    },
  );
  const instances = new WeakMap<PluginContext, { start(): Promise<void>; stop(): Promise<void> }>();
  const plugin: ComposablePlugin = {
    id: 'socket',
    version: '0.1.0',
    capabilities: new Set(['socket']),
    dependencies: ['socket-observation'],
    [SUPPORT_PLUGINS]: [observationPlugin],
    init(context) {
      const handles: SocketServerHandle[] = [],
        ownedNames = new Set<string>();
      const applicationSignal = context.require<AbortSignal>(APPLICATION_SIGNAL);
      const observation = context.require<Observation>(OBSERVATION);
      let open = true,
        ready = false,
        stopping: Promise<void> | undefined;
      function create(
        policy: Captured,
        handler: SocketPeerHandler | UdpDatagramHandler,
        initial = false,
      ) {
        if (!open) throw failure('EK_SOCKET_CLOSED');
        if (!initial && !ready) throw failure('EK_SOCKET_STATE');
        if (ownedNames.has(policy.name) || handles.length >= 128 || typeof handler !== 'function')
          throw failure('EK_SOCKET_CONFIG');
        if (
          !('path' in policy) &&
          policy.port === 0 &&
          context.options.service.environment !== 'test'
        )
          throw failure('EK_SOCKET_CONFIG');
        ownedNames.add(policy.name);
        const handle =
          policy.kind === 'udp'
            ? udpServer(policy, handler as UdpDatagramHandler, observation)
            : streamServer(policy, handler as SocketPeerHandler, observation);
        handles.push(handle);
        return handle;
      }
      for (const definition of definitions) create(definition.policy, definition.handler, true);
      const service: SocketService = Object.freeze({
        createTcpServer: (value: TcpSocketOptions, handler: SocketPeerHandler) =>
          create(capture('tcp', value), handler),
        createTlsServer: (value: TlsSocketOptions, handler: SocketPeerHandler) =>
          create(capture('tls', value), handler),
        createUnixServer: (value: UnixSocketOptions, handler: SocketPeerHandler) =>
          create(capture('unix', value), handler),
        createUdpServer: (value: UdpSocketOptions, handler: UdpDatagramHandler) =>
          create(capture('udp', value), handler) as ReturnType<SocketService['createUdpServer']>,
        list() {
          if (!open) throw failure('EK_SOCKET_CLOSED');
          return Object.freeze(
            handles.map((handle) =>
              Object.freeze({
                name: handle.name,
                kind: handle.kind,
                state: handle.state,
                ...(handle.boundAddress ? { binding: handle.boundAddress } : {}),
              }),
            ),
          );
        },
      });
      context.provide(SOCKET_CAPABILITY, service);
      instances.set(context, {
        async start() {
          try {
            for (const handle of handles) await handle.start({ signal: applicationSignal });
            ready = true;
          } catch (cause) {
            await this.stop().catch(() => undefined);
            throw cause;
          }
        },
        stop() {
          if (stopping) return stopping;
          open = false;
          ready = false;
          const abort = new AbortController(),
            timeout = 30000,
            timer = setTimeout(() => abort.abort(), timeout),
            signal = AbortSignal.any([abort.signal, applicationSignal]);
          stopping = (async () => {
            const failures: unknown[] = [];
            for (const handle of [...handles].reverse())
              try {
                await handle.stop({ timeoutMs: timeout, signal });
              } catch (cause) {
                failures.push(cause);
              }
            if (failures.length) throw failure('EK_SOCKET_IO');
          })().finally(() => clearTimeout(timer));
          return stopping;
        },
      });
    },
    async [ACTIVATE_PLUGIN](context) {
      await instances.get(context)?.start();
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.stop();
    },
    async close(context) {
      await instances.get(context)?.stop();
      instances.delete(context);
    },
  };
  return plugin;
}
