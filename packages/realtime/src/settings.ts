// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  RealtimePluginSettings,
  RealtimePolicy,
  RealtimeStartupRoute,
  SseSource,
  RealtimeIdentityAuthority,
  RealtimeSession,
} from './contracts.js';
import { types } from 'node:util';
import { fields, list, text, name, positive, method, property, failure } from './validation.js';

export function policy(input: RealtimePolicy): Readonly<RealtimePolicy> {
  const value = fields(input, [
    'requireAuth',
    'maxConnectionsPerTenant',
    'maxMessageBytes',
    'maxBufferBytes',
    'heartbeatMs',
    'idleTimeoutMs',
  ]);
  if (value.requireAuth !== true) throw failure();
  const result = {
    requireAuth: true as const,
    maxConnectionsPerTenant: positive(value.maxConnectionsPerTenant, 10000),
    maxMessageBytes: positive(value.maxMessageBytes, 1048576),
    maxBufferBytes: positive(value.maxBufferBytes, 4194304),
    heartbeatMs: positive(value.heartbeatMs, 30000),
    idleTimeoutMs: positive(value.idleTimeoutMs, 3600000),
  };
  if (result.maxBufferBytes < result.maxMessageBytes || result.heartbeatMs >= result.idleTimeoutMs)
    throw failure();
  return Object.freeze(result);
}
export function path(input: unknown): string {
  const result = text(input, 256);
  if (!/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(result)) throw failure();
  return result;
}
function catalog<T>(input: unknown, capture: (value: unknown) => T): ReadonlyMap<string, T> {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw failure();
  const keys = Reflect.ownKeys(input);
  if (
    keys.length > 64 ||
    keys.some((key) => typeof key !== 'string' || !/^[a-z][a-zA-Z0-9_-]{0,63}$/.test(key as string))
  )
    throw failure();
  const value = fields(input, keys as string[]);
  return new Map(Object.entries(value).map(([key, v]) => [key, capture(v)]));
}
export function source(input: SseSource): Readonly<SseSource> & { readonly testOnly: boolean } {
  const kind = property(input, 'kind'),
    usage = property(input, 'usage');
  if (kind !== 'durable' && kind !== 'pubsub') throw failure();
  if (usage !== undefined && usage !== 'production' && usage !== 'test-only') throw failure();
  const subscribe = method<SseSource['subscribe']>(input, 'subscribe')!,
    validateCursor = method<NonNullable<SseSource['validateCursor']>>(
      input,
      'validateCursor',
      false,
    );
  return Object.freeze({
    kind,
    testOnly: usage === 'test-only',
    subscribe,
    ...(validateCursor ? { validateCursor } : {}),
  });
}
export function capture(input: RealtimePluginSettings) {
  const value = fields(input, [
    'routes',
    'websocketHandlers',
    'sseSources',
    'policies',
    'pubsub',
    'policy',
    'allowedOrigins',
    'identityAuthority',
  ]);
  const policies = catalog(value.policies, (v) => policy(v as RealtimePolicy));
  const sources = catalog(value.sseSources, (v) => source(v as SseSource));
  const handlers = catalog(value.websocketHandlers, (v) => {
    if (typeof v !== 'function' || types.isProxy(v)) throw failure();
    return v as (session: RealtimeSession) => Promise<void>;
  });
  const routes = list(value.routes, 64).map((input) => {
    const data = fields(input, ['kind', 'path', 'handlerKey', 'sourceKey', 'policyKey']),
      routePath = path(data.path),
      policyKey = name(data.policyKey, 64);
    if (!policies.has(policyKey)) throw failure();
    if (data.kind === 'websocket' && data.sourceKey === undefined) {
      const handlerKey = name(data.handlerKey, 64);
      if (!handlers.has(handlerKey)) throw failure();
      return Object.freeze({ kind: 'websocket' as const, path: routePath, handlerKey, policyKey });
    }
    if (data.kind === 'sse' && data.handlerKey === undefined) {
      const sourceKey = name(data.sourceKey, 64);
      if (!sources.has(sourceKey)) throw failure();
      return Object.freeze({ kind: 'sse' as const, path: routePath, sourceKey, policyKey });
    }
    throw failure();
  });
  if (new Set(routes.map((route) => route.path)).size !== routes.length) throw failure();
  const bounded = fields(value.policy, [
    'maxConcurrent',
    'timeoutMs',
    'maxInputBytes',
    'maxOutputBytes',
  ]);
  const runtime = Object.freeze({
    maxConcurrent: positive(bounded.maxConcurrent, 10000),
    timeoutMs: positive(bounded.timeoutMs, 30000),
    maxInputBytes: positive(bounded.maxInputBytes ?? 1048576, 4194304),
    maxOutputBytes: positive(bounded.maxOutputBytes ?? 1048576, 4194304),
  });
  const origins = Object.freeze(
    list(value.allowedOrigins ?? [], 64).map((input) => {
      const origin = text(input, 2048),
        url = new URL(origin);
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin) throw failure();
      return origin;
    }),
  );
  let authority: RealtimeIdentityAuthority | undefined;
  let testOnly = [...sources.values()].some((source) => source.testOnly);
  if (value.identityAuthority !== undefined)
    authority = Object.freeze({
      authenticate: method<RealtimeIdentityAuthority['authenticate']>(
        value.identityAuthority,
        'authenticate',
      )!,
    });
  if (value.identityAuthority !== undefined) {
    const usage = property(value.identityAuthority, 'usage');
    if (usage !== undefined && usage !== 'production' && usage !== 'test-only') throw failure();
    testOnly ||= usage === 'test-only';
  }
  let pubsub: RealtimePluginSettings['pubsub'];
  if (value.pubsub !== undefined) {
    const data = fields(value.pubsub, ['provider', 'connectionName']);
    if (data.provider !== 'redis' && data.provider !== 'nats') throw failure();
    pubsub = Object.freeze({
      provider: data.provider,
      connectionName: name(data.connectionName, 64),
    });
  }
  return Object.freeze({
    routes: Object.freeze(routes) as readonly RealtimeStartupRoute[],
    policies,
    sources,
    handlers,
    runtime,
    origins,
    authority,
    pubsub,
    testOnly,
  });
}
export type Settings = ReturnType<typeof capture>;
