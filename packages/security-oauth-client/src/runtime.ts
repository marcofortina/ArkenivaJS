// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type {
  OAuthClientPluginSettings,
  SecretProvider,
  SecurityTransactionalStore,
  TrustedSecurityAuthority,
} from './contracts.js';
import { data, failure, integer, invalid, text, strings } from './validation.js';

function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw invalid();
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw invalid();
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field)) throw invalid();
      return field.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current) throw invalid();
  return undefined;
}
function method<T extends (...args: never[]) => unknown>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function' || types.isProxy(value)) throw invalid();
  // Callable metadata cannot replace the configured function or its original receiver.
  const invoke = (...args: Parameters<T>): ReturnType<T> =>
    Reflect.apply(value, input, args) as ReturnType<T>;
  return invoke as T;
}
/** Bind every required method once; request objects cannot replace application providers. */
export function captureSettings(input: OAuthClientPluginSettings) {
  try {
    const value = data(input, [
        'clients',
        'secretProvider',
        'stateStore',
        'authority',
        'maxStateTtlMs',
        'stateEncryptionKeyRefs',
        'stateMacKeyRefs',
        'refreshTtlMs',
        'allowInsecureLoopback',
      ]),
      storage = data(value.stateStore, ['store', 'securityLevel', 'operationTimeoutMs']);
    if (
      !['production', 'test-only'].includes(storage.securityLevel as string) ||
      !Array.isArray(value.clients) ||
      value.clients.length < 1 ||
      value.clients.length > 32 ||
      Reflect.ownKeys(value.clients).length !== value.clients.length + 1
    )
      throw invalid();
    if (
      value.allowInsecureLoopback !== undefined &&
      typeof value.allowInsecureLoopback !== 'boolean'
    )
      throw invalid();
    const ids = new Set<string>(),
      audiences = new Set<string>(),
      allOrigins = new Set<string>();
    const url = (input: unknown, originOnly = false) => {
      text(input, 2048);
      const parsed = new URL(input);
      const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(parsed.hostname);
      if (
        parsed.username ||
        parsed.password ||
        parsed.hash ||
        !(
          parsed.protocol === 'https:' ||
          (parsed.protocol === 'http:' && value.allowInsecureLoopback === true && loopback)
        )
      )
        throw invalid();
      if (originOnly && parsed.origin !== input) throw invalid();
      return parsed;
    };
    const clients = Object.freeze(
      Array.from({ length: value.clients.length }, (_, index) => {
        const field = Object.getOwnPropertyDescriptor(value.clients, index);
        if (!field || !('value' in field)) throw invalid();
        const row = data(field.value, [
          'id',
          'issuer',
          'clientId',
          'clientSecretRef',
          'redirectUri',
          'allowedAudiences',
          'allowedScopes',
          'allowedEndpointOrigins',
          'idTokenAlgorithm',
        ]);
        text(row.id, 128);
        text(row.clientId, 256);
        if (ids.has(row.id)) throw invalid();
        ids.add(row.id);
        const issuer = url(row.issuer);
        if (issuer.search) throw invalid();
        const redirect = url(row.redirectUri);
        for (const name of [
          'code',
          'state',
          'iss',
          'error',
          'error_description',
          'error_uri',
          'response_mode',
        ])
          if (redirect.searchParams.has(name)) throw invalid();
        if (row.clientSecretRef !== undefined) text(row.clientSecretRef, 256);
        const allowedAudiences = strings(row.allowedAudiences, 16, 512),
          allowedScopes = strings(row.allowedScopes, 64, 128);
        if (!allowedAudiences.length || !allowedScopes.length) throw invalid();
        for (const audience of allowedAudiences) {
          if (audiences.has(audience)) throw invalid();
          audiences.add(audience);
        }
        const origins =
          row.allowedEndpointOrigins === undefined
            ? [issuer.origin]
            : strings(row.allowedEndpointOrigins, 16, 2048);
        if (!origins.length || !origins.includes(issuer.origin)) throw invalid();
        for (const origin of origins) {
          url(origin, true);
          allOrigins.add(origin);
        }
        const algorithm = row.idTokenAlgorithm === undefined ? 'RS256' : row.idTokenAlgorithm;
        if (!['RS256', 'PS256', 'ES256', 'EdDSA'].includes(algorithm as string)) throw invalid();
        return Object.freeze({
          id: row.id,
          issuer: row.issuer as string,
          clientId: row.clientId,
          redirectUri: row.redirectUri as string,
          allowedAudiences,
          allowedScopes,
          origins: Object.freeze([...origins]),
          idTokenAlgorithm: algorithm as 'RS256' | 'PS256' | 'ES256' | 'EdDSA',
          ...(row.clientSecretRef === undefined
            ? {}
            : { clientSecretRef: row.clientSecretRef as string }),
        });
      }),
    );
    const encryptionRefs = strings(value.stateEncryptionKeyRefs, 8, 256),
      macRefs = strings(value.stateMacKeyRefs, 8, 256);
    if (
      !encryptionRefs.length ||
      !macRefs.length ||
      encryptionRefs.some((ref) => macRefs.includes(ref))
    )
      throw invalid();
    const store = Object.freeze(
      Object.fromEntries(
        [
          'read',
          'claimOnce',
          'compareAndSet',
          'atomicBatch',
          'listByOwner',
          'bumpOwnerEpoch',
          'currentOwnerEpoch',
        ].map((name) => [name, method(storage.store, name)]),
      ),
    ) as unknown as SecurityTransactionalStore;
    const usages = [
      storage.securityLevel,
      property(storage.store, 'securityLevel'),
      property(value.secretProvider, 'usage'),
      property(value.authority, 'usage'),
    ];
    for (const usage of usages)
      if (usage !== undefined && usage !== 'production' && usage !== 'test-only') throw invalid();
    return Object.freeze({
      clients,
      origins: Object.freeze([...allOrigins]),
      store,
      encryptionRefs,
      macRefs,
      getSecret: method<SecretProvider['get']>(value.secretProvider, 'get'),
      require: method<TrustedSecurityAuthority['require']>(value.authority, 'require'),
      timeoutMs: integer(storage.operationTimeoutMs, 120000),
      stateTtlMs: integer(value.maxStateTtlMs, 600000),
      refreshTtlMs: integer(
        value.refreshTtlMs === undefined ? 86400000 : value.refreshTtlMs,
        2592000000,
      ),
      allowLoopback: value.allowInsecureLoopback === true,
      testOnly: usages.includes('test-only'),
    });
  } catch {
    throw invalid();
  }
}
export type Settings = ReturnType<typeof captureSettings>;
export interface Call {
  check(): void;
  options(): OperationOptions;
  step<T>(code: ErrorCode, work: (options: OperationOptions) => Promise<T>): Promise<T>;
}
function signal(input: unknown): asserts input is AbortSignal {
  try {
    if (!(input instanceof AbortSignal)) throw invalid();
    let current: object | null = input;
    while (current !== AbortSignal.prototype) {
      if (!current) throw invalid();
      for (const name of ['aborted', 'reason', 'addEventListener', 'removeEventListener'])
        if (Object.getOwnPropertyDescriptor(current, name)) throw invalid();
      current = Object.getPrototypeOf(current) as object | null;
    }
    Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!.call(input);
  } catch {
    throw invalid();
  }
}
/** Fixed 32-operation admission, shared deadline, no queue and no late acknowledgement. */
export function runtime(settings: Settings) {
  const shutdown = new AbortController(),
    active = new Set<AbortController>(),
    pending = new Set<Promise<unknown>>();
  let closed = false;
  return {
    abort() {
      closed = true;
      shutdown.abort();
    },
    async close() {
      closed = true;
      shutdown.abort();
      await Promise.allSettled([...pending]);
    },
    async run<T>(
      input: OperationOptions | undefined,
      write: boolean,
      work: (call: Call) => Promise<T>,
    ): Promise<T> {
      if (closed) throw failure('EK_RESOURCE_CLOSED');
      const opts = data(input === undefined ? {} : input, ['signal', 'timeoutMs']),
        timeoutMs =
          opts.timeoutMs === undefined
            ? settings.timeoutMs
            : integer(opts.timeoutMs, settings.timeoutMs);
      if (opts.signal !== undefined) signal(opts.signal);
      if ((opts.signal as AbortSignal | undefined)?.aborted) throw failure('EK_ABORTED');
      if (active.size >= 32) throw failure('EK_BACKEND_UNAVAILABLE');
      const controller = new AbortController(),
        combined = AbortSignal.any([
          shutdown.signal,
          controller.signal,
          ...(opts.signal ? [opts.signal as AbortSignal] : []),
        ]),
        deadline = performance.now() + timeoutMs;
      const check = () => {
        if (closed) throw failure('EK_RESOURCE_CLOSED');
        if (combined.aborted) throw failure('EK_ABORTED');
        if (performance.now() >= deadline) throw failure('EK_TIMEOUT');
      };
      const options = () => {
        check();
        return Object.freeze({
          signal: combined,
          timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())),
        });
      };
      active.add(controller);
      const task = Promise.resolve().then(async () => {
        try {
          check();
          const result = await work({
            check,
            options,
            async step(code, fn) {
              const operation = options();
              try {
                const result = await fn(operation);
                check();
                return result;
              } catch {
                check();
                throw failure(code);
              }
            },
          });
          check();
          return result;
        } finally {
          active.delete(controller);
          pending.delete(task);
        }
      });
      pending.add(task);
      void task.catch(() => undefined);
      try {
        return await within(() => task, { signal: combined, timeoutMs });
      } catch (error) {
        if (error instanceof KitError && error.code === 'EK_UNSUPPORTED_CAPABILITY') throw error;
        const code = error instanceof KitError ? error.code : 'EK_OAUTH_POLICY';
        throw failure(
          code,
          write &&
            [
              'EK_OAUTH_STATE',
              'EK_OAUTH_EXCHANGE',
              'EK_OAUTH_PROVIDER',
              'EK_ABORTED',
              'EK_TIMEOUT',
              'EK_RESOURCE_CLOSED',
            ].includes(code),
        );
      } finally {
        controller.abort();
      }
    },
  };
}
