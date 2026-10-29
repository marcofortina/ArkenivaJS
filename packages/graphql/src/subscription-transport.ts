// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { IncomingMessage } from 'node:http';
import type { GraphQLSchema } from 'graphql';
import { GraphQLError } from 'graphql';
import type WebSocket from 'ws';
import type { WebSocketServer } from 'ws';
import type { AuthService } from '@arkenivajs/core';
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

/** Shared native upgrade dispatch receives only privately admitted requests on this application's route. */
export class SubscriptionTransport {
  private readonly requests = new WeakMap<IncomingMessage, string>();
  private readonly sockets = new WeakMap<WebSocket, SubscriptionConnection>();
  private readonly contexts = new OwnedContexts<SubscriptionConnection>();
  private readonly connections = new Set<SubscriptionConnection>();
  private closed = false;
  private degraded = false;
  private closing: Promise<void> | undefined;

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
        const connection = new SubscriptionConnection(
          socket,
          schema,
          settings,
          authority,
          requestId,
          scopes,
          executions,
          owner,
          entered,
        );
        this.connections.add(connection);
        this.sockets.set(socket, connection);
        void connection.completion.then(() => {
          if (connection.stats().failed) this.degraded = true;
          this.connections.delete(connection);
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
    await connection.authenticate();
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
