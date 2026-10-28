// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import type { SupportPluginFactory } from '@arkenivajs/core/support';
import { instrumentOperation } from '@arkenivajs/core/support';
import type { GraphqlOperationKind } from './contracts.js';

export const OBSERVERS = Symbol('graphql.observers');
export interface Observers {
  readonly telemetry?: Telemetry;
  readonly detailed: boolean;
}
export const observations: SupportPluginFactory = (options) => {
  const provider = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'graphql-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: provider ? [provider.id] : [],
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        ...(provider ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
        detailed: options.telemetry?.mode === 'detailed',
      });
    },
    close() {},
  };
};

/** Diagnostic failures never authorize, repeat or replace application work. */
export function observe(work: () => void) {
  try {
    work();
  } catch {
    /* The existing telemetry provider owns exporter failure accounting. */
  }
}

/** Retain the existing HTTP span semantics while forwarding only the bounded W3C carrier. */
export async function traceRequest<T>(
  observers: Observers,
  method: string,
  path: string,
  headers: Readonly<Record<string, string | string[] | undefined>>,
  work: () => T | Promise<T>,
): Promise<T> {
  let task: Promise<T> | undefined;
  const invoke = () =>
    (task ??= instrumentOperation(
      observers.telemetry,
      'http.server.request',
      { route: path, method },
      work,
      () => {},
    ));
  const contextual = observers.telemetry as
    | (Telemetry & {
        withRemoteContext?: <R>(
          headers: Readonly<Record<string, string | undefined>>,
          work: () => R,
        ) => R;
      })
    | undefined;
  try {
    const carrier: Record<string, string> = {};
    for (const key of ['traceparent', 'tracestate']) {
      const value = headers[key];
      if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
        carrier[key] = value;
    }
    const contextualTask = contextual?.withRemoteContext?.(carrier, invoke);
    void Promise.resolve(contextualTask).catch(() => undefined);
  } catch {
    /* The owned work promise retains its original result after provider failure. */
  }
  return invoke();
}

export function traceOperation<T>(
  observers: Observers,
  kind: GraphqlOperationKind | undefined,
  work: () => T | Promise<T>,
): Promise<T> {
  return instrumentOperation(
    observers.telemetry,
    kind ? `graphql.${kind}` : 'graphql.invalid',
    { 'graphql.kind': kind ?? 'invalid' },
    work,
    () => {},
  );
}

/** Aggregate dimensions contain no documents, operation names, identifiers or arguments. */
export class Observation {
  private readonly began = performance.now();
  private ended = false;
  private kind: GraphqlOperationKind | 'invalid' = 'invalid';
  private outcome = 'ok';
  private category: string | undefined;
  constructor(private readonly observers: Observers) {}

  budget(kind: GraphqlOperationKind, complexity: number) {
    this.kind = kind;
    observe(() =>
      this.observers.telemetry?.recordHistogram(
        'arkenivajs.graphql.operation.complexity',
        complexity,
        { 'graphql.kind': kind },
      ),
    );
  }
  reject(error: unknown) {
    const code = error instanceof KitError ? error.code : 'EK_GQL_VALIDATION';
    this.outcome =
      code === 'EK_GQL_TIMEOUT' ? 'timeout' : code === 'EK_GQL_EXECUTION' ? 'error' : 'rejected';
    this.category =
      code === 'EK_GQL_TIMEOUT' || code === 'EK_GQL_EXECUTION'
        ? undefined
        : code === 'EK_GQL_FORBIDDEN' || code === 'EK_GQL_AUTH'
          ? 'authorization'
          : code === 'EK_GQL_COMPLEXITY'
            ? 'complexity'
            : code === 'EK_GQL_INPUT_LIMIT' || code === 'EK_GQL_RESPONSE_LIMIT'
              ? 'size'
              : 'policy';
  }
  loader(size: number) {
    observe(() =>
      this.observers.telemetry?.recordHistogram('arkenivajs.graphql.loader.batch_size', size),
    );
  }
  startField() {
    return this.observers.detailed ? performance.now() : undefined;
  }
  field(began: number | undefined, metadata: boolean) {
    if (began === undefined) return;
    observe(() =>
      this.observers.telemetry?.recordHistogram(
        'arkenivajs.graphql.field.duration',
        Math.max(0, performance.now() - began) / 1000,
        { 'graphql.field_group': metadata ? 'metadata' : 'business' },
      ),
    );
  }
  finish(status: number) {
    if (this.ended) return;
    this.ended = true;
    if (status === 499) this.outcome = 'aborted';
    else if (status >= 400 && this.outcome === 'ok') this.outcome = 'rejected';
    observe(() =>
      this.observers.telemetry?.addCounter('arkenivajs.graphql.requests', 1, {
        'graphql.kind': this.kind,
        'graphql.outcome': this.outcome,
      }),
    );
    observe(() =>
      this.observers.telemetry?.recordHistogram(
        'arkenivajs.graphql.operation.duration',
        Math.max(0, performance.now() - this.began) / 1000,
        { 'graphql.kind': this.kind },
      ),
    );
    if (this.category)
      observe(() =>
        this.observers.telemetry?.addCounter('arkenivajs.graphql.denied', 1, {
          'graphql.category': this.category!,
        }),
      );
  }
}
