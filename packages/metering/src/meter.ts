// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import {
  KitError,
  DEFAULT_METER_QUEUE_CAPACITY,
  METER_EVENT_SCHEMA_VERSION,
} from '@arkenivajs/core';
import type {
  ApplicationOptions,
  OperationOptions,
  Telemetry,
  VerifiedTenantContext,
  UsageMeter,
  MeterSession,
  MeteringEvent,
  MeterEndReceipt,
  MeterResultStatus,
  UsageQuantity,
} from '@arkenivajs/core';
import { copyData, freezeData, SEMVER_PATTERN, within } from '@arkenivajs/core/support';

export type {
  UsageMeter,
  MeterSession,
  MeteringEvent,
  MeterEndReceipt,
  MeterResultStatus,
  UsageQuantity,
} from '@arkenivajs/core';
/** Stable observation gaps; optional trace sampling alone is never a metering gap. */
export type MeteringGap =
  | 'exporter_unavailable'
  | 'driver_bytes_unavailable'
  | 'span_not_instrumented'
  | 'meter_queue_overflow'
  | 'downstream_unobserved'
  | 'aborted_before_close';
/** Owned independent event transport; resolution acknowledges the entire immutable batch. */
export interface MeterExporter {
  readonly kind: 'jsonl' | 'http';
  export(events: readonly MeteringEvent[], options: OperationOptions): Promise<void>;
  close(options?: OperationOptions): Promise<void>;
}
/** Trusted runtime provenance checker, bound to the verifier that minted the tenant. */
export interface TenantVerifier {
  isVerifiedTenant(value: unknown): value is VerifiedTenantContext;
}
/** Bounded process-local accounting; transport ownership transfers to the created meter. */
export interface MeterOptions {
  readonly service: ApplicationOptions['service'];
  readonly auth: TenantVerifier;
  readonly exporter?: MeterExporter;
  readonly enabled?: boolean;
  readonly queueCapacity?: number;
  readonly queueByteCapacity?: number;
  readonly maxActiveSessions?: number;
  readonly batchSize?: number;
  readonly exportTimeoutMs?: number;
  readonly maxAttempts?: number;
  readonly retryDelayMs?: number;
  readonly flushIntervalMs?: number;
  readonly usageDefinitions?: Readonly<Record<string, UsageQuantity['unit']>>;
  readonly instanceId?: string;
  readonly workload?: NonNullable<MeteringEvent['k8s']>;
  readonly telemetry?: Telemetry;
  readonly currentTraceId?: () => string | undefined;
}
/** Explicit scope controls for adapters; untrusted callers cannot manufacture owned sessions. */
export interface ManagedUsageMeter extends UsageMeter {
  run<T>(session: MeterSession, work: () => T): T;
  /** Background consumers must not inherit the registering request's tenant accounting scope. */
  withoutScope<T>(work: () => T): T;
  markMissing(session: MeterSession, reason: MeteringGap): void;
  close(options?: OperationOptions): Promise<void>;
}
type Input = Parameters<UsageMeter['start']>[0];
type State = {
  tenant: VerifiedTenantContext;
  operation: string;
  operationId: string;
  requestId?: string;
  traceId?: string;
  parent?: State;
  began: number;
  startedAt: number;
  ended: boolean;
  activeChildren: number;
  droppedChildCount: number;
  missing: Set<MeteringGap>;
  counters: Record<string, UsageQuantity>;
  error?: 'error' | 'aborted';
  session: MeterSession;
};
const dimensionName = /^[a-z][a-z0-9_.]{1,79}(?![\s\S])/;
const gaps: readonly MeteringGap[] = [
  'exporter_unavailable',
  'driver_bytes_unavailable',
  'span_not_instrumented',
  'meter_queue_overflow',
  'downstream_unobserved',
  'aborted_before_close',
];
const invalid = (message: string) => new KitError({ code: 'EK_CONFIG_INVALID', message });
const sessionError = (message: string) => new KitError({ code: 'EK_METER_SESSION', message });
const bounded = (value: number, min: number, max: number) =>
  Number.isSafeInteger(value) && value >= min && value <= max;
const token = (value: unknown, limit: number): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= limit &&
  [...value].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127);
const defaultDimensions = Object.freeze({
  'http.requests': 'operations',
  'tenant.routing.operations': 'operations',
  'http.request.bytes': 'bytes',
  'http.response.bytes': 'bytes',
  'graphql.operations': 'operations',
  'graphql.resolved_fields': 'operations',
  'graphql.loader_batches': 'operations',
  'graphql.loader_items': 'items',
  'graphql.subscription_events': 'operations',
  'db.query': 'operations',
  'db.client.elapsed': 'milliseconds',
  'http.client.requests': 'operations',
  'http.client.elapsed': 'milliseconds',
  'http.client.response.bytes': 'bytes',
  'messaging.publish': 'operations',
  'messaging.client.elapsed': 'milliseconds',
  'messaging.payload.bytes': 'bytes',
} satisfies Record<string, UsageQuantity['unit']>);

/** EK-METER-001: independent immutable events, verified tenant provenance and bounded asynchronous export. */
export function createMeter(input: MeterOptions): ManagedUsageMeter {
  if (
    !input ||
    typeof input !== 'object' ||
    !input.service ||
    !input.auth ||
    typeof input.auth.isVerifiedTenant !== 'function'
  )
    throw invalid('Meter service and trusted tenant verifier are required');
  const options = { ...input, service: freezeData(copyData(input.service)) };
  const verifyTenant = options.auth.isVerifiedTenant.bind(options.auth);
  const service = options.service;
  const capacity = options.queueCapacity ?? DEFAULT_METER_QUEUE_CAPACITY;
  const byteCapacity = options.queueByteCapacity ?? 16_777_216;
  const maxActive = options.maxActiveSessions ?? 10_000;
  const batchSize = options.batchSize ?? 100;
  const timeout = options.exportTimeoutMs ?? 5000;
  const attempts = options.maxAttempts ?? 3;
  const retryDelay = options.retryDelayMs ?? 100;
  const intervalMs = options.flushIntervalMs ?? 1000;
  const enabled = options.enabled ?? true;
  if (
    typeof service.name !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}(?![\s\S])/.test(service.name) ||
    typeof service.version !== 'string' ||
    !new RegExp(SEMVER_PATTERN).test(service.version) ||
    !['test', 'development', 'production'].includes(service.environment) ||
    typeof enabled !== 'boolean' ||
    !bounded(capacity, 1, 1_000_000) ||
    !bounded(byteCapacity, 65_536, 1_073_741_824) ||
    !bounded(maxActive, 1, 100_000) ||
    !bounded(batchSize, 1, 1000) ||
    !bounded(timeout, 1, 60_000) ||
    !bounded(attempts, 1, 5) ||
    !bounded(retryDelay, 0, 10_000) ||
    !bounded(intervalMs, 1, 60_000) ||
    (enabled &&
      (!options.exporter ||
        !['jsonl', 'http'].includes(options.exporter.kind) ||
        typeof options.exporter.export !== 'function' ||
        typeof options.exporter.close !== 'function')) ||
    (options.currentTraceId !== undefined && typeof options.currentTraceId !== 'function')
  )
    throw invalid('Invalid metering policy');
  const instanceId = options.instanceId ?? randomUUID();
  if (!token(instanceId, 128)) throw invalid('Invalid metering instance identifier');
  const workload =
    options.workload === undefined ? undefined : freezeData(copyData(options.workload));
  if (
    options.workload !== undefined &&
    (!workload || typeof workload !== 'object' || Array.isArray(workload))
  )
    throw invalid('Trusted workload metadata must be a mapping');
  if (
    workload &&
    (Object.keys(workload).some(
      (key) => !['namespace', 'pod', 'container', 'node'].includes(key),
    ) ||
      Object.values(workload).some((value) => !token(value, 253)))
  )
    throw invalid('Invalid trusted workload metadata');
  if (
    options.usageDefinitions !== undefined &&
    (!options.usageDefinitions ||
      typeof options.usageDefinitions !== 'object' ||
      Array.isArray(options.usageDefinitions))
  )
    throw invalid('Usage definitions must be a mapping');
  const definitions = freezeData(
    copyData({
      ...defaultDimensions,
      ...options.usageDefinitions,
    } as Record<string, UsageQuantity['unit']>),
  );
  if (
    Object.entries(defaultDimensions).some(([name, unit]) => definitions[name] !== unit) ||
    Object.keys(definitions).length > 128 ||
    Object.entries(definitions).some(
      ([name, unit]) =>
        !dimensionName.test(name) ||
        !['operations', 'bytes', 'milliseconds', 'items'].includes(unit),
    )
  )
    throw invalid('Invalid registered usage dimensions');
  const storage = new AsyncLocalStorage<State | undefined>();
  const states = new WeakMap<MeterSession, State>();
  const active = new Set<State>();
  const queue: { event: MeteringEvent; bytes: number }[] = [];
  let queueBytes = 0;
  const counters = { enqueued: 0, exported: 0, dropped: 0, failedExports: 0 };
  let closed = false,
    draining = false;
  let pumping: Promise<void> | undefined, closing: Promise<void> | undefined;
  let lost: KitError | undefined;
  const controller = new AbortController();
  const metric = (name: string, value: number, reason?: string) => {
    try {
      const attrs = {
        service: service.name,
        ...(reason ? { reason } : { exporter: options.exporter?.kind ?? 'jsonl' }),
      };
      if (name.endsWith('queue.depth')) options.telemetry?.setGauge(name, value, attrs);
      else options.telemetry?.addCounter(name, value, attrs);
    } catch {
      /* Diagnostic loss never changes event acceptance or business results. */
    }
  };
  const depth = () => metric('arkenivajs.meter.queue.depth', queue.length);
  const drop = (count: number, reason: 'capacity' | 'disabled' | 'invalid' | 'error') => {
    counters.dropped += count;
    metric('arkenivajs.meter.events.dropped', count, reason);
  };
  const pump = (): Promise<void> => {
    if (pumping) return pumping;
    pumping = Promise.resolve()
      .then(async () => {
        while (queue.length && !controller.signal.aborted) {
          const batch = queue.slice(0, batchSize);
          let accepted = false;
          for (let attempt = 0; attempt < attempts; attempt++) {
            const attemptController = new AbortController();
            const signal = AbortSignal.any([controller.signal, attemptController.signal]);
            try {
              await within(
                () =>
                  options.exporter!.export(Object.freeze(batch.map((item) => item.event)), {
                    signal,
                    timeoutMs: timeout,
                  }),
                { signal: controller.signal, timeoutMs: timeout },
              );
              accepted = true;
              break;
            } catch (cause) {
              attemptController.abort();
              counters.failedExports++;
              metric('arkenivajs.meter.export.failures', 1);
              const retryable =
                !(cause instanceof KitError) ||
                cause.retryable ||
                ['EK_TIMEOUT', 'EK_BACKEND_UNAVAILABLE'].includes(cause.code);
              if (controller.signal.aborted || !retryable || attempt + 1 === attempts) {
                lost = new KitError({
                  code: 'EK_METER_EXPORT',
                  message: 'Accepted metering events could not be acknowledged',
                  cause,
                });
                break;
              }
              try {
                await delay(retryDelay, undefined, { signal: controller.signal });
              } catch {
                lost = new KitError({
                  code: 'EK_METER_EXPORT',
                  message: 'Meter export was interrupted',
                  cause,
                });
                break;
              }
            } finally {
              attemptController.abort();
            }
          }
          queue.splice(0, batch.length);
          queueBytes -= batch.reduce((total, item) => total + item.bytes, 0);
          if (accepted) {
            counters.exported += batch.length;
            metric('arkenivajs.meter.events.exported', batch.length);
          } else drop(batch.length, 'error');
          depth();
        }
      })
      .finally(() => {
        pumping = undefined;
      });
    return pumping;
  };
  const kick = () => {
    if (!closed && enabled)
      void pump().catch((cause) => {
        lost = new KitError({ code: 'EK_METER_EXPORT', message: 'Meter exporter failed', cause });
      });
  };
  const timer = enabled ? setInterval(kick, intervalMs) : undefined;
  timer?.unref();
  const owned = (session: MeterSession): State => {
    const state = states.get(session);
    if (!state || state.ended) throw sessionError('Meter session is foreign or already ended');
    return state;
  };
  const ensureOpen = () => {
    if (closed || draining)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Usage meter is closed' });
  };
  const api: ManagedUsageMeter = {
    start(input) {
      ensureOpen();
      if (!input || typeof input !== 'object')
        throw new KitError({
          code: 'EK_TENANT_UNVERIFIED',
          message: 'A trusted metering input is required',
        });
      const descriptors = Object.getOwnPropertyDescriptors(input);
      if (
        Object.entries(descriptors).some(
          ([key, descriptor]) =>
            !['tenant', 'operation', 'requestId'].includes(key) || !('value' in descriptor),
        )
      )
        throw sessionError('Meter inputs must use known data properties');
      let trusted = false;
      try {
        const decision: unknown = verifyTenant(input.tenant);
        if (decision instanceof Promise) void decision.catch(() => undefined);
        trusted = decision === true;
      } catch {
        /* Verifier failure cannot create a trusted event. */
      }
      if (!trusted)
        throw new KitError({
          code: 'EK_TENANT_UNVERIFIED',
          message: 'Metering requires a current provider-owned tenant context',
        });
      if (
        !token(input.operation, 256) ||
        (input.requestId !== undefined && !token(input.requestId, 128))
      )
        throw sessionError('Invalid operation or request identifier');
      const parent = storage.getStore();
      if (parent?.ended || (parent && parent.tenant.tenantId !== input.tenant.tenantId))
        throw sessionError('Nested metering requires a live scope for the same tenant');
      if (parent && input.requestId !== undefined && input.requestId !== parent.requestId)
        throw sessionError('Nested metering cannot replace request correlation');
      if (active.size >= maxActive) {
        drop(1, 'capacity');
        if (parent) {
          parent.droppedChildCount++;
          parent.missing.add('meter_queue_overflow');
        }
        throw new KitError({
          code: 'EK_METER_CAPACITY',
          message: 'Active metering session limit reached',
        });
      }
      let traceId = parent?.traceId;
      if (!parent) {
        try {
          traceId = options.currentTraceId?.();
        } catch {
          /* Correlation is optional and grants no identity. */
        }
        if (
          traceId !== undefined &&
          (typeof traceId !== 'string' ||
            !/^[0-9a-f]{32}(?![\s\S])/.test(traceId) ||
            /^0+$/.test(traceId))
        )
          traceId = undefined;
      }
      const session: MeterSession = Object.freeze({
        operationId: randomUUID(),
        recordUsage(name: string, usage: UsageQuantity) {
          owned(session);
          let fields: UsageQuantity;
          try {
            fields = copyData(usage);
          } catch {
            throw sessionError('Usage quantities must contain plain data');
          }
          if (
            typeof name !== 'string' ||
            !Object.hasOwn(definitions, name) ||
            !fields ||
            Object.keys(fields).some((key) => !['unit', 'source', 'value'].includes(key)) ||
            fields.unit !== definitions[name] ||
            !['observed', 'derived'].includes(fields.source) ||
            !Number.isFinite(fields.value) ||
            fields.value < 0
          )
            throw sessionError('Invalid or unregistered usage quantity');
          const previous = state.counters[name];
          const value = (previous?.value ?? 0) + fields.value;
          if ((previous && previous.source !== fields.source) || !Number.isFinite(value))
            throw sessionError('Usage dimensions cannot change source or overflow');
          state.counters[name] = Object.freeze({ unit: fields.unit, source: fields.source, value });
        },
        recordOperation(name: string, count = 1) {
          owned(session);
          if (!Number.isSafeInteger(count) || count < 0)
            throw sessionError('Operation count must be a nonnegative integer');
          session.recordUsage(name, { unit: 'operations', value: count, source: 'observed' });
        },
        recordError(error: unknown) {
          owned(session);
          state.error = 'error';
          try {
            if (
              (error instanceof KitError && error.code === 'EK_ABORTED') ||
              (error instanceof DOMException && error.name === 'AbortError')
            )
              state.error = 'aborted';
          } catch {
            /* Hostile thrown objects cannot replace the original business exception. */
          }
        },
        end(status?: MeterResultStatus): MeterEndReceipt {
          owned(session);
          if (status !== undefined && !['ok', 'error', 'aborted', 'unknown'].includes(status))
            throw sessionError('Invalid metering completion status');
          state.ended = true;
          active.delete(state);
          if (state.parent) state.parent.activeChildren--;
          if (state.activeChildren > 0) state.missing.add('downstream_unobserved');
          const outcome = status ?? state.error ?? 'unknown';
          if (outcome === 'aborted') state.missing.add('aborted_before_close');
          const eventId = randomUUID();
          const rejected = (reason: 'capacity' | 'disabled' | 'invalid'): MeterEndReceipt => {
            drop(1, reason);
            if (state.parent && !state.parent.ended) {
              state.parent.droppedChildCount++;
              state.parent.missing.add(
                reason === 'disabled' ? 'exporter_unavailable' : 'meter_queue_overflow',
              );
            }
            return Object.freeze({ eventId, accepted: false, reason });
          };
          if (!enabled) return rejected('disabled');
          if (lost) state.missing.add('exporter_unavailable');
          const event: MeteringEvent = freezeData({
            schemaVersion: METER_EVENT_SCHEMA_VERSION,
            eventId,
            tenantId: state.tenant.tenantId,
            operationId: state.operationId,
            ...(state.parent ? { parentOperationId: state.parent.operationId } : {}),
            ...(state.traceId ? { traceId: state.traceId } : {}),
            ...(state.requestId ? { requestId: state.requestId } : {}),
            service: service.name,
            serviceVersion: service.version,
            environment: service.environment,
            instanceId,
            ...(workload ? { k8s: workload } : {}),
            operation: state.operation,
            startedAt: new Date(state.startedAt).toISOString(),
            endedAt: new Date(Math.max(state.startedAt, Date.now())).toISOString(),
            durationMs: performance.now() - state.began,
            status: outcome,
            counters: { ...state.counters },
            quality: {
              complete: state.missing.size === 0,
              droppedChildCount: state.droppedChildCount,
              missing: [...state.missing].sort(),
            },
          });
          const bytes = Buffer.byteLength(JSON.stringify(event));
          if (bytes > 16_384) return rejected('invalid');
          if (queue.length >= capacity || queueBytes + bytes > byteCapacity)
            return rejected('capacity');
          queue.push({ event, bytes });
          queueBytes += bytes;
          counters.enqueued++;
          metric('arkenivajs.meter.events.enqueued', 1);
          depth();
          queueMicrotask(kick);
          return Object.freeze({ eventId, accepted: true });
        },
      });
      const state: State = {
        tenant: input.tenant,
        operation: input.operation,
        operationId: session.operationId,
        ...((parent ? parent.requestId : input.requestId)
          ? { requestId: (parent ? parent.requestId : input.requestId)! }
          : {}),
        ...(traceId ? { traceId } : {}),
        ...(parent ? { parent } : {}),
        began: performance.now(),
        startedAt: Date.now(),
        ended: false,
        activeChildren: 0,
        droppedChildCount: 0,
        missing: new Set(),
        counters: Object.create(null) as Record<string, UsageQuantity>,
        session,
      };
      states.set(session, state);
      active.add(state);
      if (parent) parent.activeChildren++;
      return session;
    },
    run(session, work) {
      const state = owned(session);
      if (typeof work !== 'function') throw sessionError('Meter work must be a function');
      return storage.run(state, work);
    },
    withoutScope(work) {
      if (typeof work !== 'function') throw sessionError('Meter work must be a function');
      return storage.run(undefined, work);
    },
    markMissing(session, reason) {
      const state = owned(session);
      if (!gaps.includes(reason)) throw sessionError('Unknown metering coverage gap');
      state.missing.add(reason);
    },
    async measure(input: Input, work) {
      if (typeof work !== 'function') throw sessionError('Meter work must be a function');
      let session: MeterSession;
      try {
        session = api.start(input);
      } catch (cause) {
        if (cause instanceof KitError && cause.code === 'EK_METER_CAPACITY')
          return storage.run(undefined, work);
        throw cause;
      }
      const state = states.get(session)!;
      return api.run(session, async () => {
        let status: MeterResultStatus = 'ok';
        try {
          return await work();
        } catch (error) {
          if (!state.ended) session.recordError(error);
          status = state.error ?? 'error';
          throw error;
        } finally {
          if (!state.ended) session.end(status);
        }
      });
    },
    current: () => {
      const state = storage.getStore();
      return state && !state.ended ? state.session : undefined;
    },
    stats: () => Object.freeze({ ...counters, queueDepth: queue.length }),
    snapshot: () =>
      Object.freeze({
        activeSessions: active.size,
        queueDepth: queue.length,
        dropped: counters.dropped,
      }),
    async flush(operation: OperationOptions = {}) {
      if (closed)
        throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Usage meter is closed' });
      await within(pump, {
        timeoutMs: operation.timeoutMs ?? timeout * attempts + retryDelay * (attempts - 1) + 1000,
        ...(operation.signal ? { signal: operation.signal } : {}),
      });
      if (lost) throw lost;
    },
    close(operation: OperationOptions = {}) {
      if (closing) return closing;
      draining = true;
      if (timer) clearInterval(timer);
      for (const state of active) {
        state.missing.add('aborted_before_close');
        state.session.end('aborted');
      }
      const deadline =
        performance.now() +
        (operation.timeoutMs ?? timeout * attempts + retryDelay * (attempts - 1) + 1000);
      closing = (async () => {
        let primary: unknown;
        let failed = false;
        try {
          await api.flush(operation);
        } catch (error) {
          primary = error;
          failed = true;
        } finally {
          closed = true;
          controller.abort();
          try {
            await within(
              () =>
                options.exporter?.close({
                  timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())),
                }),
              { timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())) },
            );
          } catch (error) {
            if (!failed) primary = error;
            failed = true;
          }
        }
        if (failed) {
          if (primary instanceof KitError) throw primary;
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Meter exporter cleanup failed',
            cause: primary,
          });
        }
      })();
      return closing;
    },
  };
  return Object.freeze(api);
}
