// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { HealthRegistry, OperationOptions, Telemetry, Logger } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';

export interface HealthCheck {
  readonly name: string;
  /** Return true only after the actual dependency confirms the required readiness condition. */
  readonly check: (options: OperationOptions) => Promise<boolean> | boolean;
}
export interface HealthOptions {
  readonly checks?: readonly HealthCheck[];
  readonly timeoutMs?: number;
  readonly isReady?: () => boolean;
  readonly telemetry?: Telemetry;
  readonly logger?: Logger;
}
export interface ManagedHealthRegistry extends HealthRegistry {
  start(): Promise<void>;
  close(): Promise<void>;
  stats(): Readonly<{ pendingChecks: number; failedChecks: number; observerFailures: number }>;
}
type Readiness = Awaited<ReturnType<HealthRegistry['ready']>>;
type Probe = { readonly result: Readiness; readonly causes: readonly unknown[] };
const notReady = (): Readiness =>
  Object.freeze({ status: 'not_ready', failing: Object.freeze(['application']) });

/** Read bounded data descriptors without executing application-owned accessors or proxy traps. */
export function healthProperty(input: unknown, name: string): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input))
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health policy metadata' });
  let current: object | null = input;
  for (let depth = 0; current && depth < 32; depth++) {
    if (types.isProxy(current))
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health policy metadata' });
    const field = Object.getOwnPropertyDescriptor(current, name);
    if (field) {
      if (!('value' in field))
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Invalid health policy metadata',
        });
      return field.value;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  if (current)
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health policy metadata' });
  return undefined;
}

/** Capture the original callable and receiver without consulting mutable function metadata. */
export function captureHealthChecks<T extends (...args: never[]) => unknown>(input: unknown) {
  if (input === undefined) return Object.freeze([]) as readonly { name: string; check: T }[];
  if (types.isProxy(input) || !Array.isArray(input) || input.length > 32)
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health probe list' });
  const captured: { name: string; check: T }[] = [],
    names = new Set<string>();
  for (let index = 0; index < input.length; index++) {
    const field = Object.getOwnPropertyDescriptor(input, String(index));
    if (!field || !('value' in field))
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health probe list' });
    const entry: unknown = field.value,
      name = healthProperty(entry, 'name'),
      callback = healthProperty(entry, 'check');
    if (
      typeof name !== 'string' ||
      !/^[a-z][a-z0-9.-]{0,95}(?![\s\S])/.test(name) ||
      name === 'application' ||
      names.has(name) ||
      typeof callback !== 'function' ||
      types.isProxy(callback)
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Health checks require unique bounded names and callbacks',
      });
    names.add(name);
    const check = ((...args: Parameters<T>) => Reflect.apply(callback, entry, args)) as T;
    captured.push(Object.freeze({ name, check }));
  }
  return Object.freeze(captured);
}

/** Capture bounded probe metadata without invoking callbacks or opening resources. */
export function healthPolicy(
  options: Omit<HealthOptions, 'checks'> & {
    readonly checks?: readonly { readonly name: string; readonly check: unknown }[];
  },
) {
  const configuredTimeout = healthProperty(options, 'timeoutMs'),
    timeoutMs = configuredTimeout === undefined ? 1000 : configuredTimeout,
    isReady = healthProperty(options, 'isReady');
  if (
    typeof timeoutMs !== 'number' ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 5000 ||
    (isReady !== undefined && (typeof isReady !== 'function' || types.isProxy(isReady)))
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid health registry policy' });
  return Object.freeze({
    timeoutMs,
    checks: captureHealthChecks<HealthCheck['check']>(healthProperty(options, 'checks')),
    isReady:
      isReady === undefined ? undefined : () => Reflect.apply(isReady, options, []) as unknown,
    telemetry: healthProperty(options, 'telemetry') as Telemetry | undefined,
    logger: healthProperty(options, 'logger') as Logger | undefined,
  });
}

/** One registry owns bounded readonly probes; liveness never depends on an external backend. */
export function createHealthRegistry(options: HealthOptions = {}): ManagedHealthRegistry {
  const policy = healthPolicy(options),
    stop = new AbortController(),
    pending = new Map<string, Promise<boolean>>();
  let closed = false,
    started = false,
    failedChecks = 0,
    observerFailures = 0,
    starting: Promise<void> | undefined,
    closing: Promise<void> | undefined,
    probing: Promise<Probe> | undefined;
  const diagnostic = (work: () => void) => {
    try {
      work();
    } catch {
      observerFailures++;
    }
  };
  const lifecycleReady = () => {
    if (!started || closed) return false;
    try {
      return policy.isReady === undefined || policy.isReady() === true;
    } catch {
      observerFailures++;
      return false;
    }
  };
  async function check(entry: HealthCheck, causes: unknown[]): Promise<boolean> {
    if (pending.has(entry.name)) {
      causes.push(new Error('The previous health probe has not settled'));
      return false;
    }
    const controller = new AbortController(),
      signal = AbortSignal.any([stop.signal, controller.signal]);
    const raw = Promise.resolve().then(async () => {
      if (signal.aborted)
        throw new KitError({ code: 'EK_ABORTED', message: 'Health probe aborted' });
      const result = await entry.check({ timeoutMs: policy.timeoutMs, signal });
      if (typeof result !== 'boolean')
        throw new Error('The dependency returned invalid health evidence');
      return result;
    });
    pending.set(entry.name, raw);
    const remove = () => {
      if (pending.get(entry.name) === raw) pending.delete(entry.name);
    };
    void raw.then(remove, remove);
    try {
      const ready = await within(() => raw, { timeoutMs: policy.timeoutMs, signal });
      if (!ready) causes.push(new Error('The dependency did not confirm readiness'));
      return ready;
    } catch (cause) {
      controller.abort(cause);
      causes.push(cause);
      return false;
    } finally {
      controller.abort(
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Health probe scope ended' }),
      );
    }
  }
  const probe = (): Promise<Probe> => {
    if (probing) return probing;
    probing = Promise.resolve()
      .then(async () => {
        const began = performance.now(),
          causes: unknown[] = [];
        const observed = await Promise.all(
            policy.checks.map(async (entry) => ({
              name: entry.name,
              ready: await check(entry, causes),
            })),
          ),
          failing = Object.freeze(
            observed.filter((entry) => !entry.ready).map((entry) => entry.name),
          );
        failedChecks += failing.length;
        diagnostic(() =>
          policy.telemetry?.recordHistogram(
            'health.ready.duration',
            (performance.now() - began) / 1000,
          ),
        );
        if (failing.length)
          diagnostic(() =>
            policy.logger?.warn('Dependency readiness failed', { failingCount: failing.length }),
          );
        return {
          result: Object.freeze({
            status: failing.length ? ('not_ready' as const) : ('ready' as const),
            failing,
          }),
          causes: Object.freeze(causes),
        };
      })
      .finally(() => {
        probing = undefined;
      });
    return probing;
  };
  return Object.freeze({
    live: () => ({ status: 'live' as const }),
    async ready(): Promise<Readiness> {
      if (!lifecycleReady()) return notReady();
      const { result } = await probe();
      return lifecycleReady() ? result : notReady();
    },
    start() {
      if (closed)
        return Promise.reject(
          new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Health registry is closed' }),
        );
      if (starting) return starting;
      starting = (async () => {
        const observed = await probe();
        if (closed)
          throw new KitError({
            code: 'EK_RESOURCE_CLOSED',
            message: 'Health registry closed during startup',
          });
        if (observed.result.status !== 'ready')
          throw new KitError({
            code: 'EK_HEALTH_NOT_READY',
            message: 'Dependency readiness did not pass startup',
            cause: new AggregateError(observed.causes),
          });
        started = true;
      })();
      return starting;
    },
    close() {
      if (closing) return closing;
      closed = true;
      stop.abort(
        new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Health registry is closing' }),
      );
      closing = (async () => {
        try {
          await within(
            async () => {
              await Promise.allSettled([...pending.values()]);
            },
            { timeoutMs: 5000 },
          );
        } catch (cause) {
          throw new KitError({
            code: 'EK_HEALTH_NOT_READY',
            message: 'Health probe cleanup did not finish',
            cause,
            details: { cleanupFailed: true },
          });
        }
      })();
      return closing;
    },
    stats: () => Object.freeze({ pendingChecks: pending.size, failedChecks, observerFailures }),
  });
}
