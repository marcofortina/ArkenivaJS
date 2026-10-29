// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { MessageType } from 'graphql-ws';
import type { Message } from 'graphql-ws';
import type { GraphQLSchema } from 'graphql';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlRequestContext } from './contracts.js';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';
import { subscriptionDocument } from './subscription-document.js';

type State = 'new' | 'authenticating' | 'authenticated' | 'ready' | 'closed';
interface Admitted {
  readonly document: ReturnType<typeof subscriptionDocument>;
  parsing: boolean;
  stopping: boolean;
}

/** Reservations precede native dispatch and remain owned until the physical operation retires. */
export class SubscriptionAdmission {
  private state: State = 'new';
  private context: GraphqlRequestContext | undefined;
  private token: string | undefined;
  private readonly operations = new Map<string, Admitted>();
  private pending = 0;
  private pings = 0;
  private initialization = false;
  private readonly limits: NonNullable<CapturedSettings['subscriptions']>;

  constructor(
    private readonly schema: GraphQLSchema,
    private readonly settings: CapturedSettings,
    private readonly authority: AuthService,
  ) {
    if (!settings.subscriptions) throw failure();
    this.limits = settings.subscriptions;
  }

  stats() {
    return Object.freeze({ activeOperations: this.operations.size, pendingFrames: this.pending });
  }
  authorization(): string {
    if (this.state !== 'authenticating' || this.token === undefined) throw failure('EK_GQL_AUTH');
    return this.token;
  }
  authenticate(context: GraphqlRequestContext) {
    if (this.state !== 'authenticating') throw failure('EK_GQL_SUBSCRIPTION');
    if (!context.identity || !context.auth) throw failure('EK_GQL_AUTH');
    try {
      if (this.authority.tenantFrom(context.identity) !== context.auth)
        throw failure('EK_GQL_AUTH');
    } catch {
      throw failure('EK_GQL_AUTH');
    }
    if (context.signal.aborted) throw failure('EK_GQL_TIMEOUT');
    this.context = Object.freeze({
      requestId: context.requestId,
      signal: context.signal,
      identity: context.identity,
      auth: context.auth,
    });
    this.token = undefined;
    this.state = 'authenticated';
  }
  acknowledge() {
    if (this.state !== 'authenticated' || !this.initialization)
      throw failure('EK_GQL_SUBSCRIPTION');
    this.initialization = false;
    this.pending--;
    this.state = 'ready';
  }
  private capacity() {
    if (this.pending >= this.limits.maxQueuedEventsPerConnection)
      throw failure('EK_GQL_BACKPRESSURE');
  }
  accept(frame: Message): false | undefined {
    if (this.state === 'closed') throw failure('EK_GQL_SUBSCRIPTION');
    switch (frame.type) {
      case MessageType.ConnectionInit:
        if (this.state !== 'new') throw failure('EK_GQL_SUBSCRIPTION');
        if (typeof frame.payload?.authorization !== 'string') throw failure('EK_GQL_AUTH');
        this.capacity();
        this.token = frame.payload.authorization;
        this.initialization = true;
        this.pending++;
        this.state = 'authenticating';
        return undefined;
      case MessageType.Subscribe: {
        if (this.state !== 'ready' || !this.context) throw failure('EK_GQL_AUTH');
        if (this.operations.has(frame.id)) throw failure('EK_GQL_SUBSCRIPTION');
        if (this.operations.size >= this.limits.maxOperationsPerConnection)
          throw failure('EK_GQL_BACKPRESSURE');
        this.capacity();
        const document = subscriptionDocument(
          frame.payload,
          this.schema,
          this.settings,
          this.context,
          this.authority,
        );
        this.operations.set(frame.id, { document, parsing: true, stopping: false });
        this.pending++;
        return undefined;
      }
      case MessageType.Complete: {
        const operation = this.operations.get(frame.id);
        if (!operation || operation.stopping) return false;
        this.capacity();
        operation.stopping = true;
        this.pending++;
        return undefined;
      }
      case MessageType.Ping:
        this.capacity();
        this.pings++;
        this.pending++;
        return undefined;
      case MessageType.Pong:
        return false;
      default:
        throw failure('EK_GQL_SUBSCRIPTION');
    }
  }
  parsed(id: string) {
    const operation = this.operations.get(id);
    if (!operation || this.state !== 'ready') throw failure('EK_GQL_SUBSCRIPTION');
    if (operation.parsing) {
      operation.parsing = false;
      this.pending--;
    }
    return operation.document;
  }
  sentPong() {
    if (this.pings > 0) {
      this.pings--;
      this.pending--;
    }
  }
  retire(id: string) {
    const operation = this.operations.get(id);
    if (!operation) return;
    this.operations.delete(id);
    if (operation.parsing) this.pending--;
    if (operation.stopping) this.pending--;
  }
  close() {
    this.state = 'closed';
    this.token = undefined;
    this.context = undefined;
    this.pending -= this.pings + Number(this.initialization);
    this.pings = 0;
    this.initialization = false;
  }
}
