// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import type {
  CacheProvider,
  RedisProvider,
  OperationOptions,
  Telemetry,
  Logger,
  VerifiedTenantContext,
  ApplicationOptions,
  Plugin,
} from '@arkenivajs/core';
import {
  within,
  instrumentOperation,
  copyData,
  PREPARE_PLUGIN,
  ACTIVATE_PLUGIN,
  SUPPORT_PLUGINS,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import { cacheSerializer } from './json.js';

export type { CacheProvider } from '@arkenivajs/core';
/** JSON and TTL policy belongs to the application, independently of the native Redis client's lifetime. */
export interface RedisCacheOptions {
  readonly namespace?: string;
  /** Null explicitly opts into non-expiring entries; the safe default is 30 seconds. */
  readonly defaultTtlMs?: number | null;
  readonly telemetry?: Telemetry;
  readonly logger?: Logger;
}
/** Closing a cache stops its own facade and waits for its calls; the application still owns Redis. */
export interface ManagedCache extends CacheProvider {
  close(): Promise<void>;
  stats(): Readonly<{ pending: number; operations: number; observerFailures: number }>;
}
/** Supply the application-owned verifier from its managed authentication service, never a request callback. */
export interface CacheTenantVerifier {
  isVerifiedTenant(value: unknown): value is VerifiedTenantContext;
}

function cacheKey(key: string): string {
  if (
    typeof key !== 'string' ||
    !key ||
    Buffer.byteLength(key) > 2048 ||
    /[\0\r\n]/.test(key) ||
    Buffer.from(key).toString('utf8') !== key
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Cache key requires bounded valid UTF-8',
    });
  return key;
}
function operationOptions(
  input?: OperationOptions,
  allowTtl = false,
): OperationOptions & { timeoutMs: number } {
  if (
    input !== undefined &&
    (!input ||
      typeof input !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input)) ||
      Reflect.ownKeys(input).some(
        (key) =>
          typeof key !== 'string' ||
          !['timeoutMs', 'signal', ...(allowTtl ? ['ttlMs'] : [])].includes(key) ||
          !('value' in Object.getOwnPropertyDescriptor(input, key)!),
      ))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Cache options require explicit supported data fields',
    });
  const timeoutMs = input?.timeoutMs === undefined ? 15000 : input.timeoutMs,
    signal = input?.signal;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    (signal !== undefined && !(signal instanceof AbortSignal))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Cache operation requires a positive timeout and valid signal',
    });
  return { timeoutMs, ...(signal ? { signal } : {}) };
}

function cachePolicy(input: Pick<RedisCacheOptions, 'namespace' | 'defaultTtlMs'>) {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid Redis cache policy' });
  const namespace = input.namespace === undefined ? 'cache:v1:' : input.namespace,
    ttl = input.defaultTtlMs === undefined ? 30000 : input.defaultTtlMs;
  if (
    typeof namespace !== 'string' ||
    !/^[A-Za-z0-9:_-]{1,128}(?![\s\S])/.test(namespace) ||
    (ttl !== null && (!Number.isSafeInteger(ttl) || ttl <= 0))
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid Redis cache policy' });
  return { namespace, ttl };
}

/** Redis acceptance and deletion counts remain authoritative; no local fallback or write replay is used. */
export function createRedisCache(
  redis: RedisProvider,
  input: RedisCacheOptions = {},
): ManagedCache {
  const { namespace, ttl } = cachePolicy(input),
    telemetry = input.telemetry,
    logger = input.logger;
  if (
    !redis ||
    typeof redis.get !== 'function' ||
    typeof redis.set !== 'function' ||
    typeof redis.del !== 'function'
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid Redis cache policy' });
  const serializer = cacheSerializer(),
    stop = new AbortController(),
    pending = new Set<Promise<unknown>>(),
    attempts = new Set<object>();
  let closed = false,
    operations = 0,
    observerFailures = 0,
    closing: Promise<void> | undefined;
  const open = () => {
    if (closed) throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Cache is closed' });
  };
  const diagnostic = (work: () => void) => {
    try {
      work();
    } catch {
      observerFailures++;
    }
  };
  async function run<T>(
    name: 'get' | 'set' | 'delete',
    options: OperationOptions | undefined,
    work: (options: OperationOptions) => Promise<T>,
  ): Promise<T> {
    open();
    if (attempts.size >= 128)
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Cache operation capacity is exhausted',
      });
    const captured = operationOptions(options, name === 'set'),
      controller = new AbortController(),
      signal = AbortSignal.any([
        controller.signal,
        stop.signal,
        ...(captured.signal ? [captured.signal] : []),
      ]),
      token = {},
      admitted = performance.now();
    let began = false,
      completed = false,
      answer: T,
      failure: KitError | undefined;
    attempts.add(token);
    const execute = async () => {
      if (signal.aborted)
        throw new KitError({
          code: 'EK_ABORTED',
          message: 'Cache operation aborted',
          cause: signal.reason,
        });
      const remaining = Math.ceil(captured.timeoutMs - (performance.now() - admitted));
      if (remaining <= 0)
        throw new KitError({ code: 'EK_TIMEOUT', message: 'Cache operation timed out' });
      began = true;
      operations++;
      const started = performance.now();
      const raw = Promise.resolve().then(() => work({ timeoutMs: remaining, signal }));
      pending.add(raw);
      void raw.then(
        () => pending.delete(raw),
        () => pending.delete(raw),
      );
      try {
        answer = await raw;
        completed = true;
        return answer;
      } catch (cause) {
        diagnostic(() => logger?.warn('Cache operation failed', { operation: name }));
        failure =
          cause instanceof KitError
            ? cause
            : new KitError({
                code: 'EK_BACKEND_UNAVAILABLE',
                message: 'Cache backend operation failed',
                cause,
              });
        throw failure;
      } finally {
        attempts.delete(token);
        diagnostic(() =>
          telemetry?.recordHistogram(
            'cache.' + name + '.duration',
            (performance.now() - started) / 1000,
          ),
        );
      }
    };
    try {
      return await within(
        () =>
          instrumentOperation(telemetry, 'cache.' + name, {}, execute, () => {
            observerFailures++;
          }),
        { ...captured, signal },
      );
    } catch (cause) {
      // The Redis provider owns native cancellation and uncertain write outcomes; never replay a submitted call.
      controller.abort(cause);
      if (completed) {
        observerFailures++;
        return answer!;
      }
      if (failure) throw failure;
      throw new KitError({
        code:
          cause instanceof KitError && cause.code === 'EK_TIMEOUT' ? 'EK_TIMEOUT' : 'EK_ABORTED',
        message:
          began && name !== 'get' ? 'Cache write outcome is unknown' : 'Cache operation stopped',
        cause,
        details: began && name !== 'get' ? { outcome: 'unknown' } : {},
      });
    } finally {
      if (!began) attempts.delete(token);
    }
  }
  return Object.freeze({
    async get<T>(key: string, options?: OperationOptions): Promise<T | null> {
      open();
      const name = namespace + cacheKey(key);
      return run('get', options, async (operation) => {
        const value = await redis.get(name, operation);
        return value === null ? null : (serializer.decode(value) as T);
      });
    },
    async set<T>(
      key: string,
      value: T,
      options?: OperationOptions & { ttlMs?: number },
    ): Promise<void> {
      open();
      operationOptions(options, true);
      if (
        options?.ttlMs !== undefined &&
        (!Number.isSafeInteger(options.ttlMs) || options.ttlMs <= 0)
      )
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Cache TTL must be positive integer milliseconds',
        });
      const name = namespace + cacheKey(key),
        text = serializer.encode(value),
        selected = options?.ttlMs ?? ttl;
      if (selected !== null && (!Number.isSafeInteger(selected) || selected <= 0))
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Cache TTL must be positive integer milliseconds',
        });
      return run('set', options, async (operation) => {
        const accepted = await redis.set(name, text, {
          ...operation,
          ...(selected === null ? {} : { ttlMs: selected }),
        });
        if (accepted !== true)
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Cache write was not accepted',
          });
      });
    },
    async delete(key: string, options?: OperationOptions): Promise<boolean> {
      open();
      const name = namespace + cacheKey(key);
      return run('delete', options, async (operation) => {
        const removed = await redis.del([name], operation);
        if (removed !== 0 && removed !== 1)
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Cache backend returned an invalid deletion count',
          });
        return removed === 1;
      });
    },
    close() {
      if (closing) return closing;
      closed = true;
      stop.abort(new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Cache is closing' }));
      closing = within(
        async () => {
          await Promise.allSettled([...pending]);
        },
        { timeoutMs: 5000 },
      );
      return closing;
    },
    stats: () => Object.freeze({ pending: attempts.size, operations, observerFailures }),
  });
}

/** Capture tenant verification without invoking mutable callable metadata. */
function tenantVerifier(auth: unknown): (value: unknown) => boolean {
  const invalid = () =>
    new KitError({
      code: 'EK_TENANT_UNVERIFIED',
      message: 'Tenant cache requires a trusted tenant verifier',
    });
  if (!auth || typeof auth !== 'object' || types.isProxy(auth)) throw invalid();
  let current: object | null = auth,
    callback: unknown;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current)) throw invalid();
    const field = Object.getOwnPropertyDescriptor(current, 'isVerifiedTenant');
    if (field) {
      if (!('value' in field)) throw invalid();
      callback = field.value;
      break;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (typeof callback !== 'function' || types.isProxy(callback)) throw invalid();
  return (value) => {
    const decision: unknown = Reflect.apply(callback, auth, [value]);
    // Invalid asynchronous verification cannot authorize access or leak an unhandled rejection.
    if (types.isPromise(decision))
      void Reflect.apply(Promise.prototype.then, decision, [undefined, () => undefined]);
    return decision === true;
  };
}

/** Bind cache authority once to an actual verified tenant; method arguments cannot select another tenant. */
export function tenantCache(
  cache: CacheProvider,
  auth: CacheTenantVerifier,
  tenant: VerifiedTenantContext,
): CacheProvider {
  const verify = tenantVerifier(auth);
  if (
    !verify(tenant) ||
    typeof tenant.tenantId !== 'string' ||
    !tenant.tenantId ||
    Buffer.byteLength(tenant.tenantId) > 256 ||
    Buffer.from(tenant.tenantId).toString('utf8') !== tenant.tenantId
  )
    throw new KitError({
      code: 'EK_TENANT_UNVERIFIED',
      message: 'Tenant cache requires verified tenant authority',
    });
  const prefix = 'tenant:' + Buffer.from(tenant.tenantId).toString('base64url') + ':';
  const key = (value: string) => {
    if (!verify(tenant))
      throw new KitError({
        code: 'EK_TENANT_UNVERIFIED',
        message: 'Tenant cache authority is no longer verified',
      });
    if (typeof value === 'string' && value.startsWith('tenant:'))
      throw new KitError({
        code: 'EK_AUTH_FORBIDDEN',
        message: 'Tenant cache accepts logical keys only',
      });
    return prefix + cacheKey(value);
  };
  return Object.freeze({
    get: async <T>(value: string, options?: OperationOptions) => cache.get<T>(key(value), options),
    set: async <T>(value: string, data: T, options?: OperationOptions & { ttlMs?: number }) =>
      cache.set(key(value), data, options),
    delete: async (value: string, options?: OperationOptions) => cache.delete(key(value), options),
  });
}

const OBSERVATION = Symbol('cache.observation');
const observations: SupportPluginFactory = (root) => {
  const owners = (
    [
      ['logger', COMPONENTS.logger],
      ['telemetry', COMPONENTS.telemetry],
    ] as const
  ).flatMap(([name, key]) => {
    const owner = root.plugins?.find((plugin) => plugin.capabilities.has(name));
    return owner ? [{ name, key, id: owner.id }] : [];
  });
  return {
    id: 'cache-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [...new Set(owners.map((owner) => owner.id))],
    init(context) {
      context.provide(
        OBSERVATION,
        Object.freeze(
          Object.fromEntries(owners.map((owner) => [owner.name, context.require(owner.key)])),
        ),
      );
    },
    close() {},
  };
};
/** Compose the cache explicitly with its declared Redis owner; optional native drivers remain separately installed. */
export function cachePlugin(
  options: Pick<RedisCacheOptions, 'namespace' | 'defaultTtlMs'> & {
    readonly redisDependency?: string;
  } = {},
): Plugin {
  options = Object.freeze(copyData(options));
  cachePolicy(options);
  if (
    options.redisDependency !== undefined &&
    (typeof options.redisDependency !== 'string' ||
      !/^[a-z][a-z0-9.-]{0,79}(?![\s\S])/.test(options.redisDependency))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid Redis cache dependency owner',
    });
  if (
    Object.keys(options).some(
      (key) => !['namespace', 'defaultTtlMs', 'redisDependency'].includes(key),
    )
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid cache plugin option' });
  const owners = new WeakMap<
    ApplicationOptions,
    { cache: ManagedCache | undefined; active: boolean; closed: boolean }
  >();
  const plugin: ComposablePlugin = {
    id: 'cache',
    version: '0.1.0',
    capabilities: new Set(['cache']),
    dependencies: [options.redisDependency ?? 'database-redis', 'cache-observation'],
    [SUPPORT_PLUGINS]: [observations],
    [PREPARE_PLUGIN](context) {
      const owner = { active: false, closed: false, cache: undefined as ManagedCache | undefined };
      owners.set(context.options, owner);
      const current = () => {
        if (owner.closed)
          throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Cache is closed' });
        if (!owner.active || !owner.cache || !['READY', 'DRAINING'].includes(context.state()))
          throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'Cache is not active' });
        return owner.cache;
      };
      const facade: CacheProvider = Object.freeze({
        get: async <T>(key: string, operation?: OperationOptions) =>
          current().get<T>(key, operation),
        set: async <T>(key: string, value: T, operation?: OperationOptions & { ttlMs?: number }) =>
          current().set(key, value, operation),
        delete: async (key: string, operation?: OperationOptions) =>
          current().delete(key, operation),
      });
      return new Map([[COMPONENTS.cache, facade]]);
    },
    init(context) {
      owners.get(context.options)!.cache = createRedisCache(
        context.require<RedisProvider>(COMPONENTS.redis),
        { ...options, ...context.require<RedisCacheOptions>(OBSERVATION) },
      );
    },
    [ACTIVATE_PLUGIN](context) {
      owners.get(context.options)!.active = true;
    },
    async close(context) {
      const owner = owners.get(context.options);
      if (!owner) return;
      owner.closed = true;
      owner.active = false;
      await owner.cache?.close();
      owners.delete(context.options);
    },
  };
  return plugin;
}
