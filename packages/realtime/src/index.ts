// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
export { SseCursorError } from './validation.js';
import websocket from '@fastify/websocket';
import { fastifySSE as sse } from '@fastify/sse';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { APPLICATION_SIGNAL, COMPONENTS, KitError } from '@arkenivajs/core';
import type {
  Plugin,
  AuthService,
  VerifiedTenantContext,
  OperationOptions,
  MessageBus,
  RedisProvider,
} from '@arkenivajs/core';
import {
  PREPARE_PLUGIN,
  DRAIN_PLUGIN,
  SUPPORT_PLUGINS,
  within,
  captureAbortSignal,
  instrumentOperation,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { ManagedApiServer } from '@arkenivajs/api';
import type {
  RealtimePluginSettings,
  RealtimeService,
  RealtimePolicy,
  RealtimeSession,
  SseSource,
} from './contracts.js';
import { capture, policy, path, source } from './settings.js';
import { fields, bytes, name, positive, failure, SseCursorError } from './validation.js';
import { requestIdentity, authenticate, tenantKey, verifiedTenant } from './identity.js';
import { Connection } from './runtime.js';
import { streamSse } from './sse.js';
import { websocketSession } from './websocket.js';
import { Broadcast, natsBackend, redisBackend } from './pubsub.js';
import type { BroadcastBackend } from './pubsub.js';
import { REDIS_PUBSUB_CAPABILITY } from '@arkenivajs/database-redis/pubsub';
import type { RedisPubsubProvider } from '@arkenivajs/database-redis/pubsub';
import { Observation, OBSERVATION, observationSupport } from './observation.js';
import type { Ports } from './observation.js';

export const REALTIME_CAPABILITY: unique symbol = Symbol('arkenivajs.realtime');
const AUTH = Symbol('realtime.authentication');
const BROADCAST = Symbol('realtime.broadcast');
const authentication: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('auth'));
  return {
    id: 'realtime-authentication',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      if (!owner) throw failure('EK_REALTIME_AUTH');
      context.provide<AuthService>(AUTH, context.require<AuthService>(COMPONENTS.auth));
    },
    close() {},
  };
};
type Route =
  | { kind: 'sse'; path: string; policy: RealtimePolicy; source: SseSource }
  | {
      kind: 'websocket';
      path: string;
      policy: RealtimePolicy;
      handler: (session: RealtimeSession) => Promise<void>;
    };
function status(error: unknown): { status: number; error: KitError } {
  if (error instanceof SseCursorError)
    return { status: error.reason === 'expired' ? 410 : 409, error };
  const code = error instanceof KitError ? error.code : 'EK_BACKEND_UNAVAILABLE';
  if (code === 'EK_REALTIME_AUTH') return { status: 401, error: failure(code) };
  if (code === 'EK_AUTH_FORBIDDEN') return { status: 403, error: failure(code) };
  if (code === 'EK_TIMEOUT') return { status: 504, error: failure(code) };
  if (code === 'EK_REALTIME_BACKPRESSURE') return { status: 429, error: failure(code) };
  return { status: 503, error: failure('EK_BACKEND_UNAVAILABLE') };
}

/** Register native protocol routes before the existing API listener activates. */
export function realtimePlugin(input: RealtimePluginSettings): Plugin {
  const settings = capture(input),
    prepared = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, { close(): Promise<void> }>();
  const broadcastSupport: SupportPluginFactory = (root) => {
    const selected = settings.pubsub;
    const owner =
      selected &&
      root.plugins?.find((entry) =>
        selected.provider === 'nats'
          ? entry.id === selected.connectionName && entry.capabilities.has('messaging')
          : entry.capabilities.has('redis.pubsub'),
      );
    if (
      selected &&
      (!owner ||
        (selected.provider === 'redis' &&
          root.databases?.[selected.connectionName]?.driver !== 'redis'))
    )
      throw failure();
    return {
      id: 'realtime-broadcast',
      version: '0.1.0',
      capabilities: new Set(),
      dependencies: owner ? [owner.id] : [],
      init(context) {
        if (!selected) return;
        if (!owner) throw failure('EK_UNSUPPORTED_CAPABILITY');
        if (selected.provider === 'nats')
          context.provide(
            BROADCAST,
            natsBackend(context.require<MessageBus>(COMPONENTS.messaging)),
          );
        else {
          const subscriptions = context.require<RedisPubsubProvider>(REDIS_PUBSUB_CAPABILITY);
          if (subscriptions.connectionName !== selected.connectionName) throw failure();
          context.provide(
            BROADCAST,
            redisBackend(context.require<RedisProvider>(COMPONENTS.redis), subscriptions),
          );
        }
      },
      close() {},
    };
  };
  const plugin: ComposablePlugin = {
    id: 'realtime',
    version: '0.1.0',
    capabilities: new Set(['realtime']),
    dependencies: ['api', 'realtime-authentication', 'realtime-broadcast', 'realtime-observation'],
    [SUPPORT_PLUGINS]: [authentication, broadcastSupport, observationSupport],
    [PREPARE_PLUGIN](context) {
      prepared.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const ready = prepared.get(context.options);
      if (settings.testOnly && context.options.service.environment !== 'test') throw failure();
      if (!ready) throw failure();
      const api = context.require<ManagedApiServer>(COMPONENTS.api),
        server = api.native(),
        auth = context.require<AuthService>(AUTH),
        owner = context.require<AbortSignal>(APPLICATION_SIGNAL);
      if (!server.hasDecorator('websocketServer')) {
        await server.register(websocket, {
          options: { maxPayload: 1048576, perMessageDeflate: false },
          errorHandler(_error, socket) {
            socket.terminate();
          },
        });
      }
      const observation = new Observation(context.require<Ports>(OBSERVATION));
      const routes: Route[] = settings.routes.map((route) =>
        route.kind === 'sse'
          ? {
              kind: 'sse',
              path: route.path,
              policy: settings.policies.get(route.policyKey)!,
              source: settings.sources.get(route.sourceKey)!,
            }
          : {
              kind: 'websocket',
              path: route.path,
              policy: settings.policies.get(route.policyKey)!,
              handler: settings.handlers.get(route.handlerKey)!,
            },
      );
      const connections = new Set<Connection>(),
        byRequest = new WeakMap<object, Connection>(),
        tenantCounts = new Map<string, number>(),
        admissions = new Set<Promise<unknown>>(),
        stop = new AbortController();
      const track = <T>(task: Promise<T>): Promise<T> => {
        admissions.add(task);
        const release = () => admissions.delete(task);
        void task.then(release, release);
        return task;
      };
      const broadcast = settings.pubsub
        ? new Broadcast(
            context.require<BroadcastBackend>(BROADCAST),
            settings.runtime.maxInputBytes,
            settings.runtime.timeoutMs,
            track,
          )
        : undefined;
      let registrationOpen = true,
        closed = false,
        sourceCleanupFailed = false,
        closing: Promise<void> | undefined;
      const register = (route: Route) => {
        if (closed) throw failure('EK_REALTIME_CLOSED');
        if (!registrationOpen || ready()) throw failure('EK_LIFECYCLE_STATE');
        if (routes.some((existing) => existing.path === route.path) || routes.length >= 64)
          throw failure();
        routes.push(route);
      };
      const close = () =>
        (closing ??= (async () => {
          closed = true;
          registrationOpen = false;
          stop.abort();
          for (const connection of connections) connection.close(true, 'shutdown');
          const closingBroadcast = broadcast?.close();
          await within(
            () =>
              Promise.all([
                Promise.all([...connections].map((connection) => connection.completion)),
                Promise.allSettled([...admissions]),
                closingBroadcast,
              ]).then(() => {
                if (sourceCleanupFailed) throw failure('EK_BACKEND_UNAVAILABLE');
              }),
            { timeoutMs: settings.runtime.timeoutMs },
          );
        })());
      instances.set(context, { close });
      const service: RealtimeService = Object.freeze({
        websocket(
          routePath: string,
          inputPolicy: RealtimePolicy,
          handler: (session: RealtimeSession) => Promise<void>,
        ) {
          if (typeof handler !== 'function') throw failure();
          register({
            kind: 'websocket',
            path: path(routePath),
            policy: policy(inputPolicy),
            handler,
          });
        },
        sse(routePath: string, inputPolicy: RealtimePolicy, inputSource: SseSource) {
          const selected = source(inputSource);
          if (selected.testOnly && context.options.service.environment !== 'test') throw failure();
          register({
            kind: 'sse',
            path: path(routePath),
            policy: policy(inputPolicy),
            source: selected,
          });
        },
        async publish(
          channel: string,
          input: Uint8Array,
          tenant: VerifiedTenantContext,
          options?: OperationOptions,
        ) {
          const selectedChannel = name(channel),
            payload = bytes(input, settings.runtime.maxInputBytes);
          const selected = fields(options ?? {}, ['timeoutMs', 'signal']);
          if (selected.timeoutMs !== undefined)
            positive(selected.timeoutMs, settings.runtime.timeoutMs);
          const signal =
            selected.signal === undefined ? undefined : captureAbortSignal(selected.signal);
          if (signal?.aborted) throw failure('EK_ABORTED');
          if (closed) throw failure('EK_REALTIME_CLOSED');
          if (!ready()) throw failure('EK_LIFECYCLE_STATE');
          if (!verifiedTenant(auth, tenant)) throw failure('EK_REALTIME_AUTH');
          if (!broadcast) throw failure('EK_UNSUPPORTED_CAPABILITY');
          if (connections.size + admissions.size >= settings.runtime.maxConcurrent)
            throw failure('EK_REALTIME_BACKPRESSURE');
          const controller = new AbortController(),
            combined = AbortSignal.any([
              owner,
              stop.signal,
              controller.signal,
              ...(signal ? [signal] : []),
            ]);
          const timeoutMs =
            selected.timeoutMs === undefined
              ? settings.runtime.timeoutMs
              : (selected.timeoutMs as number);
          const actual = track(
            instrumentOperation(
              observation.ports.telemetry,
              'realtime.publish',
              {},
              () =>
                broadcast.publish(selectedChannel, payload, tenant, {
                  signal: combined,
                  timeoutMs,
                }),
              () => {},
            ),
          );
          try {
            await within(() => actual, { signal: combined, timeoutMs });
          } catch (error) {
            if (
              error instanceof KitError &&
              ['EK_ABORTED', 'EK_TIMEOUT', 'EK_REALTIME_BACKPRESSURE'].includes(error.code)
            )
              throw failure(error.code);
            throw failure('EK_BACKEND_UNAVAILABLE');
          } finally {
            controller.abort();
          }
        },
        close,
      });
      server.register(
        async (child) => {
          child.setErrorHandler((error, request, reply) => {
            const connection = byRequest.get(request);
            connection?.close();
            if (reply.raw.headersSent) {
              reply.raw.destroy();
              return;
            }
            const selected = status(error);
            reply.header('content-type', 'application/json').header('cache-control', 'no-store');
            void reply
              .code(selected.status)
              .send({ error: { code: selected.error.code, message: selected.error.message } });
          });
          registrationOpen = false;
          for (const route of routes) {
            if (server.hasRoute({ method: 'GET', url: route.path })) throw failure();
            const preflight = async (request: FastifyRequest, reply: FastifyReply) => {
              if (closed || !ready() || owner.aborted) throw failure('EK_REALTIME_CLOSED');
              if (connections.size + admissions.size >= settings.runtime.maxConcurrent)
                throw failure('EK_REALTIME_BACKPRESSURE');
              const snapshot = requestIdentity(request, settings);
              const controller = new AbortController(),
                signal = AbortSignal.any([owner, stop.signal, controller.signal]);
              const disconnected = () => controller.abort();
              request.raw.once('aborted', disconnected);
              reply.raw.once('close', disconnected);
              const actual = track(
                instrumentOperation(
                  observation.ports.telemetry,
                  'realtime.admit',
                  { 'realtime.protocol': route.kind },
                  () =>
                    authenticate(auth, settings, snapshot, {
                      signal,
                      timeoutMs: settings.runtime.timeoutMs,
                    }),
                  () => {},
                ),
              );
              let tenant: VerifiedTenantContext;
              try {
                tenant = await within(() => actual, {
                  signal,
                  timeoutMs: settings.runtime.timeoutMs,
                });
              } finally {
                controller.abort();
                request.raw.off('aborted', disconnected);
                reply.raw.off('close', disconnected);
              }
              if (closed || owner.aborted || request.raw.aborted || reply.raw.destroyed)
                throw failure('EK_REALTIME_CLOSED');
              const key = tenantKey(tenant),
                used = tenantCounts.get(key) ?? 0;
              if (used >= route.policy.maxConnectionsPerTenant)
                throw failure('EK_REALTIME_BACKPRESSURE');
              const connection = new Connection(
                request,
                reply,
                tenant,
                route.policy,
                settings,
                auth,
                snapshot,
                owner,
                (cleanupFailed) => {
                  sourceCleanupFailed ||= cleanupFailed;
                  connections.delete(connection);
                  const remaining = (tenantCounts.get(key) ?? 1) - 1;
                  if (remaining) tenantCounts.set(key, remaining);
                  else tenantCounts.delete(key);
                },
                observation,
                route.kind,
              );
              tenantCounts.set(key, used + 1);
              connections.add(connection);
              byRequest.set(request, connection);
              if (route.kind === 'websocket' && broadcast) await broadcast.join(connection);
            };
            if (route.kind === 'sse') {
              await child.register(async (sseScope) => {
                await sseScope.register(sse, {
                  heartbeatInterval: route.policy.heartbeatMs,
                  serializer: (data: unknown) => {
                    if (typeof data !== 'string') throw failure();
                    return data;
                  },
                });
                sseScope.get(
                  route.path,
                  {
                    onRequest: preflight,
                    sse: { kind: 'only', maxBufferBytes: route.policy.maxBufferBytes },
                  },
                  async (request, reply) => {
                    const connection = byRequest.get(request)!;
                    try {
                      await connection.watch(streamSse(connection, route.source));
                      return reply;
                    } catch (error) {
                      connection.close();
                      throw error;
                    }
                  },
                );
              });
            } else {
              child.get(
                route.path,
                { onRequest: preflight, websocket: true },
                (socket, request) => {
                  const connection = byRequest.get(request)!;
                  const endpoint = websocketSession(socket, connection),
                    session = endpoint.session;
                  broadcast?.bind(connection, endpoint.deliver);
                  void connection.watch(Promise.resolve().then(() => route.handler(session))).then(
                    () => connection.close(),
                    () => connection.close(),
                  );
                },
              );
            }
          }
        },
        { logLevel: 'silent' },
      );
      context.provide(REALTIME_CAPABILITY, service);
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.close();
    },
    async close(context) {
      try {
        await instances.get(context)?.close();
      } finally {
        instances.delete(context);
      }
    },
  };
  return plugin;
}
