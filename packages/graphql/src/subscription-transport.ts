// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { IncomingMessage } from 'node:http';
import { AsyncResource } from 'node:async_hooks';
import type { GraphQLSchema } from 'graphql';
import { GraphQLError } from 'graphql';
import type WebSocket from 'ws';
import type { WebSocketServer } from 'ws';
import type { AuthService, Telemetry } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';
import { OwnedContexts } from './contexts.js';
import type { Operation } from './operation.js';
import type { SubscriptionExecution } from './subscription-execution.js';
import { SubscriptionConnection } from './subscription-connection.js';
import { assertMetadata } from './metadata.js';
import { subscriptionError } from './subscription-output.js';
import { observe, traceRequest } from './observation.js';
import { traceSubscriptionScope } from './subscription-observation.js';

/** Shared native upgrade dispatch receives only privately admitted requests on this application's route. */
export class SubscriptionTransport {
  private readonly requests = new WeakMap<IncomingMessage, string>();
  private readonly carriers = new WeakMap<
    WebSocket,
    Readonly<Record<string, string | string[] | undefined>>
  >();
  private readonly parents = new WeakMap<WebSocket, AsyncResource>();
  private readonly sockets = new WeakMap<WebSocket, SubscriptionConnection>();
  private readonly contexts = new OwnedContexts<SubscriptionConnection>();
  private readonly connections = new Set<SubscriptionConnection>();
  private closed = false;
  private degraded = false;
  private closing: Promise<void> | undefined;
  private readonly measured = new Map<
    SubscriptionConnection,
    { active: number; admission: number; writes: number }
  >();
  private readonly totals = { active: 0, admission: 0, writes: 0 };

  constructor(
    server: FastifyInstance,
    schema: GraphQLSchema,
    private readonly settings: CapturedSettings,
    authority: AuthService,
    owner: AbortSignal,
    scopes: OwnedContexts<Operation>,
    executions: OwnedContexts<SubscriptionExecution>,
    private readonly ready: () => boolean,
    entered: (scope: Operation) => void,
    private readonly started: () => void = () => {},
    private readonly telemetry?: Telemetry,
  ) {
    if (!settings.subscriptions || !settings.security.auth.required || server.server.listening)
      throw failure();
    const native = server.getDecorator<WebSocketServer>('websocketServer');
    const connection = (socket: WebSocket, request: IncomingMessage) => {
      const requestId = this.requests.get(request);
      if (requestId === undefined) return;
      this.requests.delete(request);
      try {
        this.available();
        const connection: SubscriptionConnection = new SubscriptionConnection(
          socket,
          schema,
          settings,
          authority,
          requestId,
          scopes,
          executions,
          owner,
          entered,
          {
            changed: () => this.report(connection),
            event: (result) =>
              observe(() =>
                this.telemetry?.addCounter('arkenivajs.graphql.subscription.events', 1, {
                  'graphql.result': result,
                }),
              ),
            scope: (scope) =>
              traceSubscriptionScope(this.telemetry, this.parents.get(socket), scope),
          },
        );
        this.connections.add(connection);
        this.sockets.set(socket, connection);
        this.carriers.set(socket, {
          traceparent: request.headers.traceparent,
          tracestate: request.headers.tracestate,
        });
        this.report(connection);
        void connection.completion.then(() => {
          if (connection.stats().failed) this.degraded = true;
          this.connections.delete(connection);
          this.parents.get(socket)?.emitDestroy();
          this.parents.delete(socket);
          this.carriers.delete(socket);
          this.report(connection, true);
        });
      } catch {
        socket.terminate();
      }
    };
    native.on('connection', connection);
    // Keep guarding already-admitted upgrades until the underlying listener itself is closed.
    server.addHook('onClose', async () => {
      native.off('connection', connection);
    });
    observe(() =>
      this.telemetry?.setGauge('arkenivajs.graphql.active_subscriptions', 0, {
        'graphql.subscription_type': 'websocket',
      }),
    );
    for (const queue of ['admission', 'writes'])
      observe(() =>
        this.telemetry?.setGauge('arkenivajs.graphql.subscription.queued', 0, {
          'graphql.queue_class': queue,
        }),
      );
  }

  /** Maintain aggregate gauges in constant work per ownership change, without per-client series. */
  private report(connection: SubscriptionConnection, removed = false) {
    if (!this.telemetry || (!removed && !this.connections.has(connection))) return;
    const previous = this.measured.get(connection) ?? { active: 0, admission: 0, writes: 0 };
    const state = connection.stats();
    const next = removed
      ? { active: 0, admission: 0, writes: 0 }
      : {
          active: state.wireOpen ? 1 : 0,
          admission: state.pendingFrames,
          writes: state.pendingWrites,
        };
    if (removed) this.measured.delete(connection);
    else this.measured.set(connection, next);
    for (const key of ['active', 'admission', 'writes'] as const) {
      if (next[key] === previous[key]) continue;
      this.totals[key] += next[key] - previous[key];
      if (key === 'active')
        observe(() =>
          this.telemetry!.setGauge('arkenivajs.graphql.active_subscriptions', this.totals.active, {
            'graphql.subscription_type': 'websocket',
          }),
        );
      else
        observe(() =>
          this.telemetry!.setGauge('arkenivajs.graphql.subscription.queued', this.totals[key], {
            'graphql.queue_class': key,
          }),
        );
    }
  }

  private available() {
    if (this.closed || this.degraded || !this.ready()) throw failure('EK_GQL_SUBSCRIPTION');
    if (this.connections.size >= this.settings.subscriptions!.maxConnections)
      throw failure('EK_GQL_BACKPRESSURE');
  }

  handshake(request: FastifyRequest) {
    this.available();
    if (
      request.method !== 'GET' ||
      request.raw.url !== this.settings.path ||
      request.protocol !== 'https' ||
      !('encrypted' in request.raw.socket) ||
      request.raw.socket.encrypted !== true ||
      request.headers.upgrade?.toLowerCase() !== 'websocket' ||
      request.headers['sec-websocket-protocol'] !== 'graphql-transport-ws' ||
      request.headers.cookie !== undefined ||
      typeof request.headers.origin !== 'string' ||
      !this.settings.subscriptions!.allowedOrigins.includes(request.headers.origin)
    )
      throw failure('EK_GQL_FORBIDDEN');
    this.requests.set(request.raw, request.id);
  }

  async context(socket: WebSocket) {
    const connection = this.sockets.get(socket);
    if (!connection || this.closed || this.degraded) throw failure('EK_GQL_AUTH');
    await traceRequest(
      { ...(this.telemetry ? { telemetry: this.telemetry } : {}), detailed: false },
      'GET',
      this.settings.path,
      this.carriers.get(socket) ?? {},
      async () => {
        await connection.authenticate();
        if (connection.stats().closed) throw failure('EK_GQL_AUTH');
        if (this.telemetry)
          this.parents.set(socket, new AsyncResource('GraphqlSubscriptionConnection'));
      },
    );
    this.carriers.delete(socket);
    const context = {},
      release = this.contexts.bind(context, () => connection);
    void connection.completion.then(release);
    return context;
  }

  install(engine: FastifyInstance['graphql']) {
    const connection = (context: object) => {
      const owner = this.contexts.get(context);
      if (!owner) throw failure('EK_GQL_FORBIDDEN');
      return owner;
    };
    engine.addHook('preSubscriptionParsing', (_schema, _source, context: object, id) => {
      connection(context).parsed(String(id));
    });
    engine.addHook('preSubscriptionExecution', async (_schema, _document, context: object, id) => {
      try {
        assertMetadata();
        this.started();
        await connection(context).start(context, String(id));
      } catch (error) {
        const safe = subscriptionError(
          error instanceof KitError ? { extensions: { code: error.code } } : error,
          this.settings.security.limits.maxResultBytes,
        );
        throw new GraphQLError(safe.message, { extensions: safe.extensions });
      }
    });
    engine.addHook('onSubscriptionResolution', (execution, context: object, id) => {
      connection(context).resolution(execution, String(id));
    });
    engine.addHook('onSubscriptionEnd', (context: object, id) => {
      connection(context).stop(String(id));
    });
  }

  stats() {
    return Object.freeze({
      connections: this.connections.size,
      activeSubscriptions: [...this.connections].reduce(
        (total, connection) => total + connection.stats().activeOperations,
        0,
      ),
      ready: !this.closed && !this.degraded && this.ready(),
      degraded: this.degraded,
    });
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    for (const connection of this.connections) void connection.close();
    return (this.closing = within(
      () =>
        Promise.all([...this.connections].map((connection) => connection.completion)).then(
          () => undefined,
        ),
      { timeoutMs: this.settings.security.limits.maxOperationMs },
    ));
  }
}
