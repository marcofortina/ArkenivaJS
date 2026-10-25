import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  context as globalContext,
  trace,
  SpanStatusCode,
  SpanKind,
  defaultTextMapGetter,
  defaultTextMapSetter,
  ROOT_CONTEXT,
} from '@opentelemetry/api';
import type { Context, Span, Counter, Histogram, Gauge } from '@opentelemetry/api';
import { W3CTraceContextPropagator, ExportResultCode } from '@opentelemetry/core';
import {
  TracerProvider,
  BatchSpanProcessor,
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace';
import type { SpanExporter, SpanProcessor } from '@opentelemetry/sdk-trace';
import {
  MeterProvider,
  PeriodicExportingMetricReader,
  AggregationType,
  InstrumentType,
} from '@opentelemetry/sdk-metrics';
import type { PushMetricExporter } from '@opentelemetry/sdk-metrics';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type {
  Telemetry,
  MeasureOptions,
  OperationOptions,
  ApplicationOptions,
  Plugin,
} from '@arkenivajs/core';
import { copyData, freezeData, SEMVER_PATTERN, within } from '@arkenivajs/core/support';
export type { Telemetry, MeasureOptions } from '@arkenivajs/core';

/** Primitive attribute values accepted by the bounded telemetry policy. */
export type TelemetryAttributeValue = string | number | boolean;
/** Immutable primitive attributes; each key/value still requires policy approval. */
export type TelemetryAttributes = Readonly<Record<string, TelemetryAttributeValue>>;
/** Export policy owns an isolated SDK and never replaces a process-global provider. */
export interface TelemetryOptions {
  readonly service: ApplicationOptions['service'];
  readonly mode?: 'off' | 'minimal' | 'standard' | 'detailed';
  readonly samplingRatio?: number;
  readonly endpoint?: string;
  readonly allowInsecureLoopback?: boolean;
  readonly exportTimeoutMs?: number;
  readonly exportIntervalMs?: number;
  readonly spanQueueCapacity?: number;
  readonly maxActiveSpans?: number;
  readonly maxInstruments?: number;
  readonly maxSeriesPerInstrument?: number;
  readonly instanceId?: string;
  readonly workload?: Readonly<{
    namespace?: string;
    pod?: string;
    container?: string;
    node?: string;
  }>;
  readonly labelValues?: Readonly<Record<string, readonly TelemetryAttributeValue[]>>;
}
/** Extra controls expose safe correlation, lifecycle and an explicitly native escape hatch. */
export interface ManagedTelemetry extends Telemetry {
  withRemoteContext<T>(headers: Readonly<Record<string, string | undefined>>, work: () => T): T;
  traceHeaders(): Readonly<{ traceparent?: string; tracestate?: string }>;
  currentTraceId(): string | undefined;
  resource(): TelemetryAttributes;
  status(): Readonly<{ mode: string; metrics: boolean; tracing: boolean; globalProvider: false }>;
  stats(): Readonly<{
    spansStarted: number;
    spansEnded: number;
    droppedSpans: number;
    pendingSpans: number;
    activeSpans: number;
    exportFailures: number;
    droppedMetrics: number;
    instruments: number;
    metricSeries: number;
  }>;
  close(options?: OperationOptions): Promise<void>;
  native(): Readonly<{ traces: TracerProvider | undefined; metrics: MeterProvider | undefined }>;
}
const invalid = (message: string) => new KitError({ code: 'EK_CONFIG_INVALID', message });
const positive = (n: number) => Number.isSafeInteger(n) && n > 0;
const namePattern = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}(?![\s\S])/;
const labels = new Set([
  'route',
  'method',
  'status_code',
  'peer.service',
  'db.system.name',
  'db.operation.name',
  'pool',
  'driver',
  'service',
  'exporter',
  'reason',
  'state',
  'kind',
  'direction',
  'operation',
]);
const fixed: Record<string, readonly TelemetryAttributeValue[]> = {
  method: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  direction: ['server.response', 'client.response'],
  'db.system.name': ['postgresql', 'mysql', 'mariadb', 'oracle', 'redis', 'etcd', 'mongodb'],
  'db.operation.name': [
    'query',
    'execute',
    'ping',
    'get',
    'set',
    'del',
    'increment',
    'publish',
    'put',
    'delete',
    'watch',
    'grantLease',
    'keepAlive',
    'revoke',
    'compareAndSwap',
    'findOne',
    'findMany',
    'insertOne',
    'updateOne',
    'deleteOne',
    'aggregate',
    'withTransaction',
  ],
  driver: ['postgresql', 'mysql', 'mariadb', 'oracle', 'redis', 'etcd', 'mongodb'],
  state: ['user', 'system'],
  exporter: ['jsonl', 'http', 'otlp'],
  reason: ['capacity', 'disabled', 'invalid', 'error'],
};
const units: Record<string, string> = {
  'http.server.active_requests': '{request}',
  'arkenivajs.meter.events.enqueued': '{event}',
  'arkenivajs.meter.events.exported': '{event}',
  'arkenivajs.meter.events.dropped': '{event}',
  'arkenivajs.meter.export.failures': '{failure}',
  'arkenivajs.meter.queue.depth': '{event}',
  'http.server.request.duration': 's',
  'http.client.request.duration': 's',
  'db.client.operation.duration': 's',
  'cache.get.duration': 's',
  'cache.set.duration': 's',
  'cache.delete.duration': 's',
  'health.ready.duration': 's',
  'arkenivajs.db.pool.acquire.duration': 's',
  'arkenivajs.db.pool.active': '{connection}',
  'arkenivajs.db.pool.idle': '{connection}',
  'arkenivajs.process.cpu.time': 's',
  'arkenivajs.process.memory.rss': 'By',
  'arkenivajs.runtime.event_loop.delay': 's',
  'arkenivajs.runtime.event_loop.utilization': '1',
  'arkenivajs.runtime.gc.duration': 's',
  'arkenivajs.http.body.bytes': 'By',
  'arkenivajs.operation.duration': 's',
};
/** Explicit histogram boundaries, in seconds, cover sub-millisecond work through long operations. */
export const DURATION_BUCKETS_SECONDS: readonly number[] = Object.freeze([
  0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
]);

/** EK-OTEL-001: bounded SDK metrics and sampled spans with instance-local async context. */
export function createTelemetry(input: TelemetryOptions): ManagedTelemetry {
  const mode = input?.mode ?? 'standard';
  const ratio = input?.samplingRatio ?? (mode === 'detailed' ? 1 : mode === 'standard' ? 0.1 : 0);
  const timeout = input?.exportTimeoutMs ?? 5000,
    interval = input?.exportIntervalMs ?? 10_000;
  const queueCapacity = input?.spanQueueCapacity ?? 2048,
    maxActive = input?.maxActiveSpans ?? 2048;
  const maxInstruments = input?.maxInstruments ?? 64,
    maxSeries = input?.maxSeriesPerInstrument ?? 128;
  if (
    !input?.service ||
    typeof input.service.name !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}(?![\s\S])/.test(input.service.name) ||
    typeof input.service.version !== 'string' ||
    !new RegExp(SEMVER_PATTERN).test(input.service.version) ||
    !['development', 'test', 'production'].includes(input.service.environment) ||
    !['off', 'minimal', 'standard', 'detailed'].includes(mode) ||
    !Number.isFinite(ratio) ||
    ratio < 0 ||
    ratio > 1 ||
    !positive(timeout) ||
    timeout > 60_000 ||
    !positive(interval) ||
    interval < timeout ||
    interval > 3_600_000 ||
    !positive(queueCapacity) ||
    queueCapacity > 100_000 ||
    !positive(maxActive) ||
    maxActive > 100_000 ||
    !positive(maxInstruments) ||
    maxInstruments > 1024 ||
    !positive(maxSeries) ||
    maxSeries > 4096 ||
    (input.allowInsecureLoopback !== undefined && typeof input.allowInsecureLoopback !== 'boolean')
  )
    throw invalid('Invalid telemetry policy');
  const options = freezeData(copyData(input));
  const scalar = (value: unknown): value is TelemetryAttributeValue =>
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value)) ||
    (typeof value === 'string' && value.length > 0 && value.length <= 128 && !/[\r\n]/.test(value));
  const allowed = new Map<string, ReadonlySet<TelemetryAttributeValue>>();
  for (const [key, values] of Object.entries(options.labelValues ?? {})) {
    if (
      !labels.has(key) ||
      !Array.isArray(values) ||
      !values.length ||
      values.length > 128 ||
      values.some((v) => !scalar(v))
    )
      throw invalid('Invalid telemetry label policy');
    allowed.set(key, new Set(values));
  }
  const resource: Record<string, TelemetryAttributeValue> = {
    'service.name': options.service.name,
    'service.version': options.service.version,
    'deployment.environment.name': options.service.environment,
    'process.pid': process.pid,
    'service.instance.id': options.instanceId ?? randomUUID(),
  };
  for (const [key, value] of Object.entries(options.workload ?? {})) {
    if (
      !['namespace', 'pod', 'container', 'node'].includes(key) ||
      typeof value !== 'string' ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(?![\s\S])/.test(value)
    )
      throw invalid('Invalid trusted workload metadata');
    resource[`k8s.${key}.name`] = value;
  }
  if (
    typeof resource['service.instance.id'] !== 'string' ||
    !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}(?![\s\S])/.test(resource['service.instance.id'])
  )
    throw invalid('Invalid service instance identifier');
  const resourceView = Object.freeze(resource);
  let endpoint: URL | undefined;
  if (mode !== 'off') {
    try {
      endpoint = new URL(options.endpoint ?? '');
      if (
        endpoint.username ||
        endpoint.password ||
        endpoint.hash ||
        endpoint.search ||
        endpoint.pathname !== '/' ||
        (endpoint.protocol !== 'https:' &&
          !(
            options.allowInsecureLoopback &&
            options.service.environment !== 'production' &&
            endpoint.protocol === 'http:' &&
            ['127.0.0.1', '[::1]'].includes(endpoint.hostname)
          ))
      )
        throw invalid('Telemetry export requires a trusted HTTPS origin');
    } catch (cause) {
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Invalid telemetry endpoint',
        cause,
      });
    }
  }
  const storage = new AsyncLocalStorage<Context>(),
    propagator = new W3CTraceContextPropagator();
  const counters = {
    spansStarted: 0,
    spansEnded: 0,
    droppedSpans: 0,
    pendingSpans: 0,
    exportFailures: 0,
    droppedMetrics: 0,
  };
  const active = new Set<Span>();
  let closed = false,
    closing: Promise<void> | undefined;
  let traces: TracerProvider | undefined, metrics: MeterProvider | undefined;
  if (endpoint) {
    const common = { timeoutMillis: timeout, concurrencyLimit: 1 };
    const metricExporter = new OTLPMetricExporter({
      ...common,
      url: new URL('/v1/metrics', endpoint).href,
    });
    const observedMetricExporter: PushMetricExporter = {
      export(data, done) {
        metricExporter.export(data, (result) => {
          if (result.code !== ExportResultCode.SUCCESS) counters.exportFailures++;
          done(result);
        });
      },
      forceFlush: () => metricExporter.forceFlush(),
      shutdown: () => metricExporter.shutdown(),
      selectAggregationTemporality: (type) => metricExporter.selectAggregationTemporality(type),
    };
    metrics = new MeterProvider({
      resource: resourceFromAttributes(resource),
      readers: [
        new PeriodicExportingMetricReader({
          exporter: observedMetricExporter,
          exportIntervalMillis: interval,
          exportTimeoutMillis: timeout,
          cardinalityLimits: { default: maxSeries },
          maxExportBatchSize: 512,
        }),
      ],
      views: [
        {
          instrumentType: InstrumentType.HISTOGRAM,
          instrumentUnit: 's',
          aggregation: {
            type: AggregationType.EXPLICIT_BUCKET_HISTOGRAM,
            options: { boundaries: [...DURATION_BUCKETS_SECONDS] },
          },
          aggregationCardinalityLimit: maxSeries,
        },
      ],
    });
    if (mode === 'standard' || mode === 'detailed') {
      const exporter = new OTLPTraceExporter({
        ...common,
        url: new URL('/v1/traces', endpoint).href,
      });
      const observed: SpanExporter = {
        export(spans, done) {
          exporter.export(spans, (result) => {
            counters.pendingSpans = Math.max(0, counters.pendingSpans - spans.length);
            if (result.code !== ExportResultCode.SUCCESS) counters.exportFailures++;
            done(result);
          });
        },
        shutdown: () => exporter.shutdown(),
        forceFlush: () => exporter.forceFlush(),
      };
      const batch = new BatchSpanProcessor({
        exporter: observed,
        maxQueueSize: queueCapacity,
        maxExportBatchSize: Math.min(512, queueCapacity),
        scheduledDelayMillis: Math.max(100, Math.min(interval, 5000)),
        exportTimeoutMillis: timeout,
      });
      const processor: SpanProcessor = {
        onStart: (span, parent) => batch.onStart(span, parent),
        onEnd(span) {
          if (!(span.spanContext().traceFlags & 1)) return;
          if (counters.pendingSpans >= queueCapacity) {
            counters.droppedSpans++;
            return;
          }
          counters.pendingSpans++;
          batch.onEnd(span);
        },
        async forceFlush() {
          await batch.forceFlush();
          // A full SDK batch may already be exporting outside its finished-span buffer.
          await exporter.forceFlush();
        },
        async shutdown() {
          try {
            await batch.shutdown();
          } finally {
            await exporter.shutdown();
          }
        },
      };
      traces = new TracerProvider({
        resource: resourceFromAttributes(resource),
        spanProcessors: [processor],
        sampler: new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(ratio) }),
        spanLimits: {
          attributeCountLimit: 16,
          attributeValueLengthLimit: 128,
          eventCountLimit: 0,
          linkCountLimit: 0,
        },
      });
    }
  }
  const meter = metrics?.getMeter('@arkenivajs/telemetry', '0.1.0');
  const tracer = traces?.getTracer('@arkenivajs/telemetry', '0.1.0');
  const instruments = new Map<
    string,
    {
      kind: 'counter' | 'histogram' | 'gauge';
      value: Counter | Histogram | Gauge;
      series: Set<string>;
      lastValues: Map<string, number>;
    }
  >();
  const operations = new Set<string>();
  const open = () => {
    if (closed) throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Telemetry is closed' });
  };
  const attrs = (values: TelemetryAttributes = {}): Record<string, TelemetryAttributeValue> => {
    if (!values || typeof values !== 'object' || Array.isArray(values))
      throw invalid('Telemetry labels must be a record');
    const result = copyData(values),
      keys = Object.keys(result);
    if (keys.length > 8) throw invalid('Too many telemetry labels');
    for (const [key, value] of Object.entries(result)) {
      const valid =
        labels.has(key) &&
        scalar(value) &&
        (allowed.get(key)?.has(value) ??
          fixed[key]?.includes(value) ??
          (key === 'status_code'
            ? typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
            : key === 'operation'
              ? operations.has(String(value))
              : key === 'service'
                ? value === options.service.name
                : false));
      if (!valid) throw invalid('Telemetry label is not permitted');
    }
    return result;
  };
  const instrument = (
    kind: 'counter' | 'histogram' | 'gauge',
    name: string,
    attributes: Record<string, TelemetryAttributeValue>,
  ) => {
    if (typeof name !== 'string' || !namePattern.test(name))
      throw invalid('Invalid telemetry instrument name');
    let entry = instruments.get(name);
    if (entry && entry.kind !== kind) throw invalid('Telemetry instrument kind cannot change');
    const key = JSON.stringify(
      Object.entries(attributes).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    if (entry && !entry.series.has(key) && entry.series.size >= maxSeries)
      throw invalid('Telemetry cardinality limit reached');
    if (!entry) {
      if (instruments.size >= maxInstruments) throw invalid('Telemetry instrument limit reached');
      const config = {
        unit: Object.hasOwn(units, name) ? units[name]! : kind === 'counter' ? '{operation}' : '1',
      };
      const value =
        kind === 'counter'
          ? meter!.createCounter(name, config)
          : kind === 'histogram'
            ? meter!.createHistogram(name, config)
            : name === 'http.server.active_requests'
              ? meter!.createUpDownCounter(name, config)
              : meter!.createGauge(name, config);
      entry = { kind, value, series: new Set(), lastValues: new Map() };
      instruments.set(name, entry);
    }
    entry.series.add(key);
    return entry;
  };
  const sample = (
    kind: 'counter' | 'histogram' | 'gauge',
    name: string,
    value: number,
    attributes: TelemetryAttributes = {},
  ) => {
    open();
    if (!meter) return;
    if (name === 'http.server.active_requests' && kind !== 'gauge')
      throw invalid('Active request state requires setGauge');
    if (
      !Number.isFinite(value) ||
      ((kind === 'counter' || name === 'http.server.active_requests') && value < 0)
    )
      throw invalid('Invalid telemetry sample');
    const fields = attrs(attributes),
      entry = instrument(kind, name, fields);
    if (kind === 'gauge' && name === 'http.server.active_requests') {
      const key = JSON.stringify(
        Object.entries(fields).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
      );
      (entry.value as Counter).add(value - (entry.lastValues.get(key) ?? 0), fields);
      entry.lastValues.set(key, value);
    } else if (kind === 'counter') (entry.value as Counter).add(value, fields);
    else (entry.value as Histogram | Gauge).record(value, fields);
  };
  const span = async <T>(
    name: string,
    work: () => Promise<T> | T,
    parameters: MeasureOptions = {},
  ): Promise<T> => {
    open();
    if (typeof work !== 'function') throw invalid('Telemetry work must be a function');
    if (!tracer) return work();
    if (typeof name !== 'string' || !namePattern.test(name))
      throw invalid('Invalid telemetry operation name');
    const fields = attrs(parameters.attributes);
    if (active.size >= maxActive) {
      counters.droppedSpans++;
      return work();
    }
    const parent = storage.getStore() ?? globalContext.active();
    const kind =
      name === 'http.server.request'
        ? SpanKind.SERVER
        : ['http.client.request', 'db.client.operation'].includes(name)
          ? SpanKind.CLIENT
          : SpanKind.INTERNAL;
    const current = tracer.startSpan(name, { attributes: fields, kind }, parent);
    active.add(current);
    counters.spansStarted++;
    return storage.run(trace.setSpan(parent, current), async () => {
      try {
        return await work();
      } catch (error) {
        current.setStatus({ code: SpanStatusCode.ERROR });
        current.setAttribute('error.type', error instanceof KitError ? error.code : 'EK_INTERNAL');
        throw error;
      } finally {
        if (active.delete(current)) {
          current.end();
          counters.spansEnded++;
        }
      }
    });
  };
  const api: ManagedTelemetry = {
    withSpan: span,
    async measure(name, work, parameters = {}) {
      open();
      if (typeof work !== 'function') throw invalid('Telemetry work must be a function');
      if (mode === 'off') return work();
      if (typeof name !== 'string' || !namePattern.test(name))
        throw invalid('Invalid telemetry operation name');
      const fields = attrs(parameters.attributes);
      if (!operations.has(name) && operations.size < maxSeries) operations.add(name);
      const began = performance.now();
      try {
        return await span(name, work, parameters);
      } finally {
        if (!closed)
          try {
            sample(
              'histogram',
              'arkenivajs.operation.duration',
              (performance.now() - began) / 1000,
              { ...fields, operation: name },
            );
          } catch {
            counters.droppedMetrics++;
          }
      }
    },
    addCounter: (name, value, fields) => sample('counter', name, value, fields),
    recordHistogram: (name, value, fields) => sample('histogram', name, value, fields),
    setGauge: (name, value, fields) => sample('gauge', name, value, fields),
    async flush(request: OperationOptions = {}) {
      open();
      const failed = counters.exportFailures;
      // Keep the adapter deadline authoritative instead of racing SDK timeout errors.
      const sdkTimeout = Math.min(
        2_147_483_647,
        Math.max(timeout, request.timeoutMs ?? timeout) + 1000,
      );
      try {
        await within(
          async () => {
            await Promise.all([
              traces?.forceFlush({ timeoutMillis: sdkTimeout }),
              metrics?.forceFlush({ timeoutMillis: sdkTimeout }),
            ]);
          },
          { timeoutMs: request.timeoutMs ?? timeout, ...request },
        );
      } catch (cause) {
        if (cause instanceof KitError) throw cause;
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'Telemetry export failed',
          cause,
        });
      }
      if (counters.exportFailures !== failed)
        throw new KitError({ code: 'EK_BACKEND_UNAVAILABLE', message: 'Telemetry export failed' });
    },
    withRemoteContext(headers, work) {
      open();
      if (!headers || typeof headers !== 'object' || Array.isArray(headers))
        throw invalid('Trace headers must be a record');
      const carrier = { traceparent: headers.traceparent, tracestate: headers.tracestate };
      if (typeof work !== 'function') throw invalid('Trace context work must be a function');
      // Baggage and caller identity headers are deliberately absent from the carrier.
      return storage.run(propagator.extract(ROOT_CONTEXT, carrier, defaultTextMapGetter), work);
    },
    traceHeaders() {
      open();
      const output: Record<string, string> = {};
      propagator.inject(storage.getStore() ?? globalContext.active(), output, defaultTextMapSetter);
      return Object.freeze(output);
    },
    currentTraceId() {
      open();
      return trace.getSpanContext(storage.getStore() ?? globalContext.active())?.traceId;
    },
    resource: () => resourceView,
    status: () =>
      Object.freeze({ mode, metrics: !!metrics, tracing: !!traces, globalProvider: false }),
    stats: () =>
      Object.freeze({
        ...counters,
        activeSpans: active.size,
        instruments: instruments.size,
        metricSeries: [...instruments.values()].reduce(
          (total, entry) => total + entry.series.size,
          0,
        ),
      }),
    native() {
      open();
      return Object.freeze({ traces, metrics });
    },
    close(request: OperationOptions = {}) {
      if (closing) return closing;
      closed = true;
      for (const current of active) {
        current.setStatus({ code: SpanStatusCode.ERROR });
        current.end();
        counters.spansEnded++;
      }
      active.clear();
      storage.disable();
      const shutdown = Promise.allSettled([
        traces?.shutdown(),
        metrics?.shutdown({ timeoutMillis: request.timeoutMs ?? timeout }),
      ]);
      closing = within(
        async () => {
          const results = await shutdown;
          if (results.some((result) => result.status === 'rejected'))
            throw new KitError({
              code: 'EK_BACKEND_UNAVAILABLE',
              message: 'Telemetry shutdown failed',
            });
        },
        { timeoutMs: request.timeoutMs ?? timeout, ...request },
      );
      return closing;
    },
  };
  return Object.freeze(api);
}
/** Root service/mode policy cannot be overridden by adapter options. */
export type TelemetryPluginOptions = Omit<TelemetryOptions, 'service' | 'mode' | 'samplingRatio'>;
/** Install one explicitly configured SDK per application without global registration. */
export function telemetryPlugin(options: TelemetryPluginOptions = {}): Plugin {
  const services = new WeakMap<object, ManagedTelemetry>();
  return {
    id: 'telemetry',
    version: '0.1.0',
    capabilities: new Set(['telemetry']),
    dependencies: ['logging'],
    init(context) {
      const pools = Object.keys(context.options.databases ?? {});
      const telemetry = createTelemetry({
        ...options,
        ...(pools.length
          ? {
              labelValues: {
                ...options.labelValues,
                pool: [...new Set([...(options.labelValues?.pool ?? []), ...pools])],
              },
            }
          : {}),
        service: context.options.service,
        ...(context.options.telemetry ?? { mode: 'off' }),
      });
      try {
        context.provide(COMPONENTS.telemetry, telemetry);
        services.set(context, telemetry);
      } catch (error) {
        void telemetry.close().catch(() => undefined);
        throw error;
      }
    },
    async close(context) {
      await services
        .get(context)
        ?.close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      services.delete(context);
    },
  };
}
