// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type {
  ApiKeyPluginSettings,
  KeyedDigestProvider,
  SecurityTransactionalStore,
  TrustedSecurityAuthority,
} from './contracts.js';
import { data, failure, integer, invalid, text } from './validation.js';

function property(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object') throw invalid();
  let current: object | null = input;
  while (current) {
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field)) throw invalid();
      return field.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}
function method<T>(input: unknown, name: string): T {
  const value = property(input, name);
  if (typeof value !== 'function') throw invalid();
  return value.bind(input) as T;
}
/** Bind every required method once; request objects cannot replace application providers. */
export function captureSettings(input: ApiKeyPluginSettings) {
  try {
    const value = data(input, [
        'store',
        'hmac',
        'hmacKeyRef',
        'authority',
        'maxActiveKeysPerSubject',
        'maxVerifyAttemptsPerMinute',
      ]),
      storage = data(value.store, ['store', 'securityLevel', 'operationTimeoutMs']);
    if (
      !['production', 'test-only'].includes(storage.securityLevel as string) ||
      property(value.hmac, 'algorithm') !== 'HMAC-SHA256'
    )
      throw invalid();
    text(value.hmacKeyRef, 256);
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
      property(value.hmac, 'usage'),
      property(value.authority, 'usage'),
    ];
    for (const usage of usages)
      if (usage !== undefined && usage !== 'production' && usage !== 'test-only') throw invalid();
    return Object.freeze({
      store,
      hmac: Object.freeze({
        algorithm: 'HMAC-SHA256' as const,
        digest: method<KeyedDigestProvider['digest']>(value.hmac, 'digest'),
        verify: method<KeyedDigestProvider['verify']>(value.hmac, 'verify'),
      }),
      require: method<TrustedSecurityAuthority['require']>(value.authority, 'require'),
      keyRef: value.hmacKeyRef,
      timeoutMs: integer(storage.operationTimeoutMs, 120000),
      maxKeys: integer(value.maxActiveKeysPerSubject, 1000),
      maxAttempts: integer(value.maxVerifyAttemptsPerMinute, 100000),
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
    active = new Set<AbortController>();
  let closed = false;
  return {
    close() {
      closed = true;
      shutdown.abort();
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
        }
      });
      try {
        return await within(() => task, { signal: combined, timeoutMs });
      } catch (error) {
        const code = error instanceof KitError ? error.code : 'EK_APIKEY_INVALID';
        throw failure(
          code,
          write &&
            ['EK_APIKEY_STORE', 'EK_ABORTED', 'EK_TIMEOUT', 'EK_RESOURCE_CLOSED'].includes(code),
        );
      } finally {
        controller.abort();
      }
    },
  };
}
