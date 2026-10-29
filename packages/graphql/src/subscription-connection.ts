// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { GraphQLSchema, ExecutionResult } from 'graphql';
import { MessageType } from 'graphql-ws';
import type { Message } from 'graphql-ws';
import type WebSocket from 'ws';
import type { AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';
import { OwnedContexts } from './contexts.js';
import { Operation } from './operation.js';
import { SubscriptionAdmission } from './subscription-admission.js';
import { SubscriptionExecution } from './subscription-execution.js';
import { SubscriptionEgress } from './subscription-egress.js';
import { installSubscriptionIngress } from './subscription-ingress.js';
import { sealSubscriptionResult } from './subscription-output.js';
import { subscriptionTimer } from './subscription-timer.js';
import { observe } from './observation.js';
import type { Observation } from './observation.js';

interface Reservation {
  stopping: boolean;
  pendingEvent: boolean;
  execution?: SubscriptionExecution;
  release?: () => void;
  observation?: Observation;
}

/** One native connection retains authentication, starts, source handles and physical cleanup. */
export class SubscriptionConnection {
  readonly completion: Promise<void>;
  private resolveCompletion!: () => void;
  private readonly controller = new AbortController();
  private readonly admission: SubscriptionAdmission;
  private readonly egress: SubscriptionEgress;
  private readonly operations = new Map<string, Reservation>();
  private readonly verifying = new Set<Operation>();
  private readonly initializer: () => void;
  private revalidation: (() => void) | undefined;
  private termination: (() => void) | undefined;
  private heartbeat: (() => void) | undefined;
  private assertion: string | undefined;
  private principal: VerifiedTenantContext | undefined;
  private closed = false;
  private wireClosed = false;
  private failed = false;
  private readonly aborted: () => void;

  constructor(
    private readonly socket: WebSocket,
    schema: GraphQLSchema,
    private readonly settings: CapturedSettings,
    private readonly authority: AuthService,
    private readonly requestId: string,
    private readonly scopes: OwnedContexts<Operation>,
    private readonly executions: OwnedContexts<SubscriptionExecution>,
    private readonly owner: AbortSignal,
    private readonly entered: (scope: Operation) => void = () => {},
    private readonly signals: {
      changed?(): void;
      event?(result: 'deliver' | 'drop'): void;
      authenticated?(principal: VerifiedTenantContext): void;
      scope?(scope: Operation, phase: 'source' | 'event'): Promise<void>;
      observation?(): Observation;
      operation?(): void;
      rejected?(): void;
    } = {},
  ) {
    if (!settings.subscriptions || !settings.security.auth.required) throw failure();
    if (
      !Number.isSafeInteger(
        (settings.security.limits.maxResultBytes + 2048) *
          settings.subscriptions.maxQueuedEventsPerConnection,
      )
    )
      throw failure();
    this.admission = new SubscriptionAdmission(schema, settings, authority);
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    this.aborted = () => {
      void this.close();
    };
    this.initializer = subscriptionTimer(settings.security.limits.maxOperationMs, () => {
      void this.close();
    });
    owner.addEventListener('abort', this.aborted, { once: true });
    socket.once('close', () => {
      this.wireClosed = true;
      this.termination?.();
      void this.close();
      observe(() => this.signals.changed?.());
      this.finish();
    });
    socket.on('error', () => {
      void this.close();
    });
    this.egress = new SubscriptionEgress(
      socket,
      {
        maxResultBytes: settings.security.limits.maxResultBytes,
        maxQueuedEvents: settings.subscriptions.maxQueuedEventsPerConnection,
        timeoutMs: settings.security.limits.maxOperationMs,
      },
      (message) => this.sent(message),
      () => this.signals.changed?.(),
    );
    installSubscriptionIngress(socket, settings.security.limits, (message) => this.accept(message));
    if (owner.aborted) void this.close();
  }

  private accept(message: Message): false | undefined {
    if (message.type === MessageType.Pong) {
      this.heartbeat?.();
      this.heartbeat = undefined;
    }
    let observation: Observation | undefined;
    if (message.type === MessageType.Subscribe) {
      observe(() => this.signals.operation?.());
      observe(() => {
        observation = this.signals.observation?.();
      });
    }
    let accepted: false | undefined;
    try {
      accepted = this.admission.accept(message);
    } catch (error) {
      if (message.type === MessageType.Subscribe) {
        observation?.reject(error);
        observation?.finish(400);
        observe(() => this.signals.rejected?.());
      }
      throw error;
    }
    if (accepted === false) return false;
    if (message.type === MessageType.Subscribe) {
      observation?.budget('subscription', this.admission.complexity(message.id));
      this.operations.set(message.id, {
        stopping: false,
        pendingEvent: false,
        ...(observation ? { observation } : {}),
      });
    } else if (message.type === MessageType.Complete) {
      const reservation = this.operations.get(message.id);
      if (reservation) {
        reservation.stopping = true;
        // Stop business work now, but keep its ID/queue credit until the native stop is consumed.
        void reservation.execution?.close();
      }
    }
    observe(() => this.signals.changed?.());
    return undefined;
  }

  private sent(message: Message) {
    if (this.closed) throw failure('EK_GQL_SUBSCRIPTION');
    if (message.type === MessageType.ConnectionAck) {
      this.admission.acknowledge();
      this.initializer();
      this.schedule();
    } else if (message.type === MessageType.Pong) this.admission.sentPong();
    else if (message.type === MessageType.Next) {
      const reservation = this.operations.get(message.id);
      if (reservation?.pendingEvent) {
        reservation.pendingEvent = false;
        observe(() => this.signals.event?.('deliver'));
      }
    } else if (message.type === MessageType.Ping && !this.heartbeat) {
      this.heartbeat = subscriptionTimer(this.settings.security.limits.maxOperationMs, () => {
        void this.close();
      });
    } else if (message.type === MessageType.Error || message.type === MessageType.Complete) {
      this.retire(message.id);
      // Native start errors do not retire their internal subscription context until wire closure.
      if (message.type === MessageType.Error) void this.close();
    }
    observe(() => this.signals.changed?.());
  }

  private async verify(assertion: string) {
    if (this.closed) throw failure('EK_GQL_AUTH');
    const scope = new Operation(
      { requestId: this.requestId },
      this.settings.security.limits,
      this.controller.signal,
    );
    this.verifying.add(scope);
    void scope.completion.then(() => {
      this.verifying.delete(scope);
      this.finish();
    });
    try {
      this.entered(scope);
      const identity = await scope.run(() =>
        this.authority.verifyBearer(assertion, {
          signal: scope.controller.signal,
          timeoutMs: scope.limits.maxOperationMs,
        }),
      );
      scope.check();
      const policy = this.settings.security.auth;
      if (!policy.required) throw failure('EK_GQL_AUTH');
      for (const required of policy.scopes ?? []) this.authority.requireScope(identity, required);
      if (policy.assurance) this.authority.requireAssurance(identity, policy.assurance);
      const principal = this.authority.tenantFrom(identity);
      if (
        this.closed ||
        (this.principal &&
          (principal.tenantId !== this.principal.tenantId ||
            identity.issuer !== this.principal.identity.issuer ||
            identity.subject !== this.principal.identity.subject))
      )
        throw failure('EK_GQL_AUTH');
      return principal;
    } catch {
      if (!this.closed && !this.owner.aborted)
        for (const reservation of this.operations.values())
          reservation.observation?.reject(failure('EK_GQL_AUTH'));
      void this.close();
      throw failure('EK_GQL_AUTH');
    } finally {
      scope.end();
    }
  }

  async authenticate(): Promise<void> {
    const assertion = this.admission.authorization();
    const principal = await this.verify(assertion);
    this.signals.authenticated?.(principal);
    this.assertion = assertion;
    this.principal = principal;
    this.admission.authenticate({
      requestId: this.requestId,
      signal: this.controller.signal,
      identity: principal.identity,
      auth: principal,
    });
  }

  private schedule() {
    if (this.closed) return;
    this.revalidation = subscriptionTimer(this.settings.subscriptions!.revalidateIntervalMs, () => {
      void this.verify(this.assertion!).then(
        () => this.schedule(),
        () => {
          void this.close();
        },
      );
    });
  }

  parsed(id: string) {
    const document = this.admission.parsed(id);
    observe(() => this.signals.changed?.());
    return document;
  }

  async start(context: object, id: string) {
    const reservation = this.operations.get(id);
    if (
      this.closed ||
      !reservation ||
      reservation.stopping ||
      reservation.execution ||
      !this.principal ||
      !this.assertion
    )
      throw failure('EK_GQL_SUBSCRIPTION');
    const document = this.admission.parsed(id);
    const execution = new SubscriptionExecution(
      this.settings,
      this.authority,
      this.assertion,
      this.principal,
      {
        requestId: this.requestId,
        ...(document.input.operationName === undefined
          ? {}
          : { operationName: document.input.operationName }),
      },
      this.controller.signal,
      this.entered,
      () => {
        reservation.pendingEvent = true;
      },
      this.signals.scope,
      reservation.observation,
    );
    reservation.execution = execution;
    execution.bind(context, this.scopes);
    reservation.release = this.executions.bind(context, () => execution);
    try {
      await execution.prepare();
      if (this.closed || reservation.stopping) throw failure('EK_GQL_SUBSCRIPTION');
    } catch (error) {
      reservation.observation?.reject(error);
      this.retire(id);
      throw error;
    }
  }

  resolution(execution: ExecutionResult, id: string) {
    const reservation = this.operations.get(id);
    if (this.closed || !reservation?.execution || reservation.stopping)
      throw failure('EK_GQL_SUBSCRIPTION');
    const scope = reservation.execution.current;
    if (!scope) throw failure('EK_GQL_SUBSCRIPTION');
    try {
      scope.check();
      sealSubscriptionResult(execution, this.settings.security.limits.maxResultBytes);
      scope.check();
    } catch (error) {
      scope.failed = true;
      scope.observation?.reject(error);
      throw error;
    }
  }

  stop(id: string) {
    const reservation = this.operations.get(id);
    if (!reservation) return;
    reservation.stopping = true;
    // Native stop consumption alone cannot free an ID before a late terminal wire response.
    void reservation.execution?.close();
  }

  private retire(id: string) {
    const reservation = this.operations.get(id);
    if (!reservation) return;
    reservation.stopping = true;
    const interrupted = reservation.pendingEvent;
    if (interrupted) {
      reservation.pendingEvent = false;
      observe(() => this.signals.event?.('drop'));
    }
    const release = () => {
      if (this.operations.get(id) !== reservation) return;
      reservation.release?.();
      reservation.observation?.finish(
        interrupted && !reservation.observation.isRejected() ? 499 : 200,
      );
      if (reservation.observation?.isRejected()) observe(() => this.signals.rejected?.());
      this.operations.delete(id);
      this.admission.retire(id);
      observe(() => this.signals.changed?.());
      if (reservation.execution?.retirementFailed()) {
        this.failed = true;
        void this.close();
      }
      this.finish();
    };
    if (reservation.execution) void reservation.execution.close().then(release);
    else release();
  }

  stats() {
    return Object.freeze({
      ...this.admission.stats(),
      pendingWrites: this.egress.stats().pendingWrites,
      wireOpen: !this.wireClosed,
      closed: this.closed,
      failed: this.failed,
    });
  }

  close(): Promise<void> {
    if (this.closed) return this.completion;
    this.closed = true;
    this.assertion = undefined;
    this.initializer();
    this.revalidation?.();
    this.heartbeat?.();
    this.owner.removeEventListener('abort', this.aborted);
    this.admission.close();
    this.controller.abort();
    for (const scope of this.verifying) {
      scope.abort();
      scope.end();
    }
    for (const id of this.operations.keys()) this.retire(id);
    if (!this.wireClosed) {
      this.termination = subscriptionTimer(
        Math.min(1000, this.settings.security.limits.maxOperationMs),
        () => this.socket.terminate(),
      );
      this.socket.close(4400, 'EK_GQL_SUBSCRIPTION');
    }
    this.finish();
    observe(() => this.signals.changed?.());
    return this.completion;
  }

  private finish() {
    if (this.closed && this.wireClosed && this.verifying.size === 0 && this.operations.size === 0)
      this.resolveCompletion();
  }
}
