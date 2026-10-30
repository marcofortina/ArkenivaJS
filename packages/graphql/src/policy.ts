// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
import type {
  GraphqlAuthenticationPolicy,
  GraphqlExecutionLimits,
  GraphqlPluginSettings,
} from './contracts.js';

export function failure(code: ErrorCode = 'EK_GQL_CONFIG'): KitError {
  const messages: Partial<Record<ErrorCode, string>> = {
    EK_GQL_CONFIG: 'Invalid GraphQL configuration',
    EK_GQL_SCHEMA: 'Invalid GraphQL schema or field mapping',
    EK_GQL_VALIDATION: 'Invalid GraphQL operation',
    EK_GQL_AUTH: 'GraphQL authentication is required',
    EK_GQL_FORBIDDEN: 'GraphQL access is forbidden',
    EK_GQL_EXECUTION: 'GraphQL field execution failed',
    EK_GQL_INPUT_LIMIT: 'GraphQL input exceeds its limit',
    EK_GQL_COMPLEXITY: 'GraphQL operation exceeds its work budget',
    EK_GQL_TIMEOUT: 'GraphQL operation exceeded its deadline',
    EK_GQL_RESPONSE_LIMIT: 'GraphQL response exceeds its limit',
  };
  return new KitError({ code, message: messages[code] ?? 'GraphQL operation failed' });
}

/** Capture declarations without invoking accessors or proxy traps. */
export function record(value: unknown, allowed?: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    ![null, Object.prototype].includes(Object.getPrototypeOf(value))
  )
    throw failure();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      (allowed && !allowed.includes(key)) ||
      !descriptor ||
      !('value' in descriptor)
    )
      throw failure();
    result[key] = descriptor.value;
  }
  return result;
}

export function text(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.includes('\0')) throw failure();
  return value;
}

export function integer(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw failure();
  return value as number;
}

function strings(value: unknown): readonly string[] {
  // Array.isArray throws for revoked proxies; reject them before inspecting the list.
  if (types.isProxy(value) || !Array.isArray(value)) throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== value.length + 1) throw failure();
  const entries = Array.from({ length: value.length }, (_, i) => {
    const descriptor = descriptors[String(i)];
    if (!descriptor || !('value' in descriptor)) throw failure();
    return text(descriptor.value);
  });
  if (new Set(entries).size !== entries.length) throw failure();
  return Object.freeze(entries);
}

function subscription(input: unknown): NonNullable<GraphqlPluginSettings['subscriptions']> {
  const value = record(input, [
    'enabled',
    'pubsub',
    'maxConnections',
    'maxOperationsPerConnection',
    'maxQueuedEventsPerConnection',
    'revalidateIntervalMs',
    'allowedOrigins',
  ]);
  if (value.enabled !== true) throw failure();
  const maxConnections = integer(value.maxConnections),
    maxOperationsPerConnection = integer(value.maxOperationsPerConnection);
  if (maxConnections > 1000 || maxOperationsPerConnection > 50) throw failure();
  const provider = value.pubsub;
  if (!provider || typeof provider !== 'object' || types.isProxy(provider)) throw failure();
  const property = (name: string) => {
    let current: object | null = provider;
    let depth = 0;
    while (current) {
      if (++depth > 32) throw failure();
      if (types.isProxy(current)) throw failure();
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor) {
        if (!('value' in descriptor)) throw failure();
        return descriptor.value as unknown;
      }
      current = Object.getPrototypeOf(current);
    }
    return undefined;
  };
  const method = (name: string) => {
    const candidate = property(name);
    if (typeof candidate !== 'function' || types.isProxy(candidate)) throw failure();
    return Function.prototype.bind.call(candidate, provider);
  };
  const distribution = property('distribution'),
    securityLevel = property('securityLevel'),
    usage = property('usage');
  if (
    (distribution !== undefined && distribution !== 'process' && distribution !== 'shared') ||
    (securityLevel !== undefined &&
      securityLevel !== 'test-only' &&
      securityLevel !== 'production') ||
    (usage === 'test-only' && securityLevel === 'production')
  )
    throw failure();
  const pubsub = Object.freeze({
    ...(distribution === undefined ? {} : { distribution: distribution as 'process' | 'shared' }),
    securityLevel: (securityLevel ?? 'test-only') as 'test-only' | 'production',
    subscribe: method('subscribe'),
    publish: method('publish'),
    close: method('close'),
  });
  const allowedOrigins = strings(value.allowedOrigins);
  if (
    !allowedOrigins.length ||
    allowedOrigins.some((origin) => {
      try {
        const parsed = new URL(origin);
        return (
          !['http:', 'https:'].includes(parsed.protocol) ||
          parsed.origin !== origin ||
          !!parsed.username ||
          !!parsed.password
        );
      } catch {
        return true;
      }
    })
  )
    throw failure();
  return Object.freeze({
    enabled: true,
    pubsub,
    maxConnections,
    maxOperationsPerConnection,
    maxQueuedEventsPerConnection: integer(value.maxQueuedEventsPerConnection),
    revalidateIntervalMs: integer(value.revalidateIntervalMs),
    allowedOrigins,
  });
}

const defaults: Readonly<GraphqlExecutionLimits> = Object.freeze({
  maxDocumentBytes: 65536,
  maxVariablesBytes: 65536,
  maxResultBytes: 1048576,
  maxDepth: 8,
  maxComplexity: 500,
  maxAliases: 20,
  maxFieldExecutions: 2000,
  maxCollectionItems: 100,
  maxOperationMs: 30000,
});

export type CapturedSettings = Readonly<
  GraphqlPluginSettings & {
    path: string;
    security: GraphqlPluginSettings['security'] & {
      auth: GraphqlAuthenticationPolicy;
      limits: GraphqlExecutionLimits;
      introspection: 'disabled' | 'authenticated';
    };
  }
>;

export function capture(input: GraphqlPluginSettings): CapturedSettings {
  const value = record(input, [
    'path',
    'schema',
    'resolvers',
    'loaders',
    'security',
    'subscriptions',
  ]);
  const path = value.path === undefined ? '/graphql' : text(value.path);
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(path) || ['/livez', '/readyz'].includes(path))
    throw failure();
  const security = record(value.security, [
    'auth',
    'authorizeField',
    'limits',
    'introspection',
    'introspectionScope',
    'developerIDE',
    'allowGetQueries',
    'allowBatchedHttpRequests',
  ]);
  if (typeof security.authorizeField !== 'function') throw failure();
  const auth =
    security.auth === undefined
      ? { required: true }
      : record(security.auth, ['required', 'scopes', 'assurance', 'publicRootFields', 'reason']);
  let capturedAuth: GraphqlAuthenticationPolicy;
  if (auth.required === true) {
    if (
      auth.publicRootFields !== undefined ||
      auth.reason !== undefined ||
      (auth.assurance !== undefined &&
        !['single-factor', 'mfa', 'phishing-resistant'].includes(auth.assurance as string))
    )
      throw failure();
    capturedAuth = Object.freeze({
      required: true,
      ...(auth.scopes === undefined ? {} : { scopes: strings(auth.scopes) }),
      ...(auth.assurance === undefined
        ? {}
        : { assurance: auth.assurance as 'single-factor' | 'mfa' | 'phishing-resistant' }),
    });
  } else if (auth.required === false) {
    if (auth.scopes !== undefined || auth.assurance !== undefined) throw failure();
    const publicRootFields = strings(auth.publicRootFields);
    if (
      !publicRootFields.length ||
      publicRootFields.some((field) => !/^Query\.[_A-Za-z][_0-9A-Za-z]*$/.test(field))
    )
      throw failure();
    capturedAuth = Object.freeze({ required: false, publicRootFields, reason: text(auth.reason) });
  } else throw failure();
  const overrides =
    security.limits === undefined ? {} : record(security.limits, Object.keys(defaults));
  const limits = Object.freeze(
    Object.fromEntries(
      Object.entries(defaults).map(([key, fallback]) => [
        key,
        overrides[key] === undefined ? fallback : integer(overrides[key]),
      ]),
    ) as unknown as GraphqlExecutionLimits,
  );
  for (const name of ['developerIDE', 'allowGetQueries'])
    if (security[name] !== undefined && typeof security[name] !== 'boolean') throw failure();
  if (
    security.allowBatchedHttpRequests !== undefined &&
    security.allowBatchedHttpRequests !== false
  )
    throw failure();
  const introspection = security.introspection ?? 'disabled';
  if (
    !['disabled', 'authenticated'].includes(introspection as string) ||
    (introspection === 'disabled' && security.introspectionScope !== undefined)
  )
    throw failure();
  const introspectionScope =
    introspection === 'authenticated' ? text(security.introspectionScope) : undefined;
  const mappings = (input: unknown, loader: boolean) => {
    const result: Record<string, Record<string, unknown>> = Object.create(null);
    for (const [type, fields] of Object.entries(record(input))) {
      const captured: Record<string, unknown> = Object.create(null);
      for (const [name, resolver] of Object.entries(record(fields))) {
        if (loader) {
          const definition = record(resolver, ['load', 'cache', 'maxBatchSize']);
          if (
            typeof definition.load !== 'function' ||
            (definition.cache !== undefined && typeof definition.cache !== 'boolean')
          )
            throw failure();
          const maxBatchSize =
            definition.maxBatchSize === undefined ? 100 : integer(definition.maxBatchSize);
          if (maxBatchSize > 1000) throw failure();
          captured[name] = Object.freeze({
            load: definition.load,
            cache: definition.cache ?? true,
            maxBatchSize,
          });
        } else if (typeof resolver === 'function') captured[name] = resolver;
        else {
          const definition = record(resolver, ['subscribe', 'resolve']);
          if (
            typeof definition.subscribe !== 'function' ||
            (definition.resolve !== undefined && typeof definition.resolve !== 'function')
          )
            throw failure();
          captured[name] = Object.freeze(definition);
        }
      }
      result[type] = Object.freeze(captured);
    }
    return Object.freeze(result);
  };
  return Object.freeze({
    path,
    schema: text(value.schema),
    resolvers: mappings(value.resolvers, false) as GraphqlPluginSettings['resolvers'],
    ...(value.loaders === undefined
      ? {}
      : {
          loaders: mappings(value.loaders, true) as NonNullable<GraphqlPluginSettings['loaders']>,
        }),
    security: Object.freeze({
      ...security,
      auth: capturedAuth,
      limits,
      introspection,
      ...(introspectionScope === undefined ? {} : { introspectionScope }),
    }) as CapturedSettings['security'],
    ...(value.subscriptions === undefined
      ? {}
      : { subscriptions: subscription(value.subscriptions) }),
  });
}
