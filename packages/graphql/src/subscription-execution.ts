// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { GraphQLResolveInfo } from 'graphql';
import type { AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import type { GraphqlRequestContext, GraphqlSubscriptionSource } from './contracts.js';
import type { CapturedSettings } from './policy.js';
import { failure } from './policy.js';
import { Operation } from './operation.js';
import { OwnedContexts } from './contexts.js';
import { bindMetadata } from './metadata.js';
import { authorizedField, fieldInfo } from './fields.js';
import { SubscriptionStream } from './subscription-stream.js';

/** One source owns independent start and per-delivery policy/deadline/cache scopes. */
export class SubscriptionExecution implements AsyncIterableIterator<unknown> {
  current: Operation | undefined;
  readonly completion: Promise<void>;
  private resolveCompletion!: () => void;
  private readonly controller = new AbortController();
  private readonly signal: AbortSignal;
  private readonly scopes = new Set<Operation>();
  private readonly bindings: (() => void)[] = [];
  private initial: Operation | undefined;
  private event: Operation | undefined;
  private preparation: Promise<void> | undefined;
  private stream: SubscriptionStream | undefined;
  private closed = false;
  private reading = false;
  private readonly aborted: () => void;

  constructor(
    private readonly settings: CapturedSettings,
    private readonly authority: AuthService,
    private readonly authorization: string,
    private readonly principal: VerifiedTenantContext,
    private readonly metadata: Omit<GraphqlRequestContext, 'signal' | 'identity' | 'auth'>,
    owner: AbortSignal,
    private readonly entered?: (scope: Operation) => void,
  ) {
    try {
      if (authority.tenantFrom(principal.identity) !== principal) throw failure('EK_GQL_AUTH');
    } catch {
      throw failure('EK_GQL_AUTH');
    }
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    this.signal = AbortSignal.any([owner, this.controller.signal]);
    this.aborted = () => {
      void this.close();
    };
    this.signal.addEventListener('abort', this.aborted, { once: true });
    if (this.signal.aborted) void this.close();
  }
  [Symbol.asyncIterator]() {
    return this;
  }
  hasFailure() {
    return this.stream?.hasFailure() ?? false;
  }
  retirementFailed() {
    return this.stream?.retirementFailed() ?? false;
  }

  bind(context: object, scopes: OwnedContexts<Operation>) {
    if (this.closed) throw failure('EK_GQL_SUBSCRIPTION');
    const release = scopes.bind(context, () => this.current);
    try {
      const metadata = bindMetadata(context, () =>
        this.current
          ? {
              scope: this.current,
              settings: this.settings,
              authorizeIntrospection() {
                throw failure('EK_GQL_FORBIDDEN');
              },
            }
          : undefined,
      );
      this.bindings.push(release, metadata);
    } catch (error) {
      release();
      throw error;
    }
  }
  private async fresh(): Promise<Operation> {
    if (this.closed) throw failure('EK_GQL_SUBSCRIPTION');
    const scope = new Operation(this.metadata, this.settings.security.limits, this.signal);
    this.scopes.add(scope);
    void scope.completion.then(() => this.scopes.delete(scope));
    try {
      this.entered?.(scope);
      const identity = await scope.run(() =>
        this.authority.verifyBearer(this.authorization, {
          signal: scope.controller.signal,
          timeoutMs: scope.limits.maxOperationMs,
        }),
      );
      scope.check();
      if (this.settings.security.auth.required) {
        for (const required of this.settings.security.auth.scopes ?? [])
          this.authority.requireScope(identity, required);
        if (this.settings.security.auth.assurance)
          this.authority.requireAssurance(identity, this.settings.security.auth.assurance);
      }
      const tenant = this.authority.tenantFrom(identity);
      if (
        identity.issuer !== this.principal.identity.issuer ||
        identity.subject !== this.principal.identity.subject ||
        tenant.tenantId !== this.principal.tenantId
      )
        throw failure('EK_GQL_AUTH');
      Object.defineProperty(scope, 'context', {
        value: Object.freeze({ ...scope.context, identity, auth: tenant }),
      });
      return scope;
    } catch (error) {
      scope.end();
      if (error instanceof KitError && error.code === 'EK_GQL_BACKPRESSURE') throw error;
      throw failure(scope.controller.signal.aborted ? 'EK_GQL_TIMEOUT' : 'EK_GQL_AUTH');
    }
  }
  prepare(): Promise<void> {
    if (this.closed) return Promise.reject(failure('EK_GQL_SUBSCRIPTION'));
    return (this.preparation ??= this.fresh().then(
      (scope) => {
        if (this.closed) {
          scope.abort();
          scope.end();
          throw failure('EK_GQL_TIMEOUT');
        }
        this.initial = scope;
        this.current = scope;
      },
      (error: unknown) => {
        void this.close();
        throw error;
      },
    ));
  }
  async openSource(
    parent: unknown,
    args: Record<string, unknown>,
    info: GraphQLResolveInfo,
    subscribe: GraphqlSubscriptionSource,
  ): Promise<this> {
    const scope = this.initial;
    if (this.closed || !scope || this.current !== scope || this.stream)
      throw failure('EK_GQL_SUBSCRIPTION');
    const stream = new SubscriptionStream(
      (signal) =>
        subscribe(parent, args, Object.freeze({ ...scope.context, signal }), fieldInfo(info)),
      this.signal,
    );
    this.stream = stream;
    try {
      await authorizedField(scope, this.settings, parent, args, info, undefined, () =>
        stream.open(),
      );
      this.current = undefined;
      scope.end();
      return this;
    } catch (error) {
      void this.close();
      throw error;
    }
  }
  async next(): Promise<IteratorResult<unknown>> {
    if (this.closed) return { done: true, value: undefined };
    if (this.reading) throw failure('EK_GQL_BACKPRESSURE');
    this.reading = true;
    try {
      if (!this.stream) throw failure('EK_GQL_SUBSCRIPTION');
      if (this.event) {
        this.event.end();
        await this.event.completion;
        this.event = undefined;
      }
      this.current = undefined;
      const result = await this.stream.next();
      if (this.closed || result.done) {
        void this.close();
        return { done: true, value: undefined };
      }
      const event = await this.fresh();
      if (this.closed) {
        event.abort();
        event.end();
        return { done: true, value: undefined };
      }
      this.event = event;
      this.current = event;
      return result;
    } catch {
      void this.close();
      throw failure('EK_GQL_SUBSCRIPTION');
    } finally {
      this.reading = false;
    }
  }
  async return(): Promise<IteratorResult<unknown>> {
    await this.close();
    return { done: true, value: undefined };
  }
  close(): Promise<void> {
    if (this.closed) return this.completion;
    this.closed = true;
    this.current = undefined;
    this.signal.removeEventListener('abort', this.aborted);
    this.controller.abort();
    for (const release of this.bindings.splice(0)) release();
    this.stream?.stop();
    for (const scope of this.scopes) {
      scope.abort();
      scope.end();
    }
    void Promise.all([
      ...[...this.scopes].map((scope) => scope.completion),
      ...(this.stream ? [this.stream.completion] : []),
    ]).then(() => this.resolveCompletion());
    return this.completion;
  }
}
