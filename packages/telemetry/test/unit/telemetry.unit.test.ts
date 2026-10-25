import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { trace, metrics, context } from '@opentelemetry/api';
import { KitError, createApplication, COMPONENTS } from '@arkenivajs/core';
import type { Plugin, Logger } from '@arkenivajs/core';
import { createTelemetry, telemetryPlugin, DURATION_BUCKETS_SECONDS } from '@arkenivajs/telemetry';
import type { TelemetryOptions, ManagedTelemetry } from '@arkenivajs/telemetry';

const service = { name: 'telemetry-test', version: '1.0.0', environment: 'test' as const };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
interface Envelope {
  resourceSpans?: {
    resource: { attributes: unknown[] };
    scopeSpans: {
      spans: {
        name: string;
        traceId: string;
        spanId: string;
        parentSpanId?: string;
        status?: { code: number };
        attributes?: unknown[];
      }[];
    }[];
  }[];
  resourceMetrics?: unknown[];
}
async function receiver() {
  const data: { path: string; body: Envelope }[] = [];
  let behavior: 'ok' | 'error' | 'hang' = 'ok';
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    data.push({
      path: request.url!,
      body: JSON.parse(Buffer.concat(chunks).toString()) as Envelope,
    });
    if (behavior === 'hang') return;
    response.setHeader('content-type', 'application/json');
    response.statusCode = behavior === 'error' ? 400 : 200;
    response.end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    data,
    mode(value: typeof behavior) {
      behavior = value;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
const options = (endpoint: string): TelemetryOptions => ({
  service,
  endpoint,
  mode: 'standard',
  samplingRatio: 1,
  allowInsecureLoopback: true,
  exportTimeoutMs: 500,
  exportIntervalMs: 1000,
});

test('EK-OTEL-001 owned providers export actual SDK spans, metrics, resource metadata and explicit buckets', async () => {
  const target = await receiver();
  const globalTracer = trace.getTracerProvider(),
    globalMeter = metrics.getMeterProvider(),
    before = context.active();
  const telemetry = createTelemetry({
    ...options(target.endpoint),
    instanceId: 'instance-test',
    workload: { namespace: 'test', pod: 'example-pod', container: 'app', node: 'example-node' },
    labelValues: { route: ['/orders/:id'] },
  });
  try {
    assert.equal(telemetry.resource()['process.pid'], process.pid);
    assert.equal(Object.isFrozen(telemetry.resource()), true);
    assert.equal(telemetry.status().globalProvider, false);
    assert.equal(telemetry.native().traces !== undefined, true);
    assert.equal(
      await telemetry.measure('orders.fetch', async () => {
        assert.match(telemetry.currentTraceId()!, /^[0-9a-f]{32}$/);
        assert.match(telemetry.traceHeaders().traceparent!, /^00-/);
        return telemetry.withSpan('repository.read', () => 42, {
          attributes: { 'db.system.name': 'postgresql' },
        });
      }),
      42,
    );
    telemetry.addCounter('application.requests', 2, { method: 'GET', route: '/orders/:id' });
    telemetry.recordHistogram('http.server.request.duration', 0.02, {
      method: 'GET',
      route: '/orders/:id',
      status_code: 200,
    });
    assert.throws(
      () => telemetry.addCounter('http.server.active_requests', 1),
      code('EK_CONFIG_INVALID'),
    );
    telemetry.recordHistogram('constructor', 1);
    telemetry.setGauge('http.server.active_requests', 1, { route: '/orders/:id', method: 'GET' });
    telemetry.setGauge('http.server.active_requests', 0, { route: '/orders/:id', method: 'GET' });
    assert.throws(
      () => telemetry.setGauge('http.server.active_requests', -1),
      code('EK_CONFIG_INVALID'),
    );
    telemetry.setGauge('arkenivajs.process.memory.rss', process.memoryUsage().rss, {
      service: service.name,
    });
    await telemetry.flush();
    assert.ok(target.data.some((entry) => entry.path === '/v1/metrics'));
    const spans = target.data
      .flatMap((entry) => entry.body.resourceSpans ?? [])
      .flatMap((group) => group.scopeSpans.flatMap((scope) => scope.spans));
    const outer = spans.find((span) => span.name === 'orders.fetch')!,
      inner = spans.find((span) => span.name === 'repository.read')!;
    assert.ok(outer && inner);
    assert.equal(inner.parentSpanId, outer.spanId);
    assert.equal(inner.traceId, outer.traceId);
    const wire = JSON.stringify(target.data);
    assert.ok(wire.includes('http.server.active_requests') && wire.includes('"isMonotonic":false'));
    for (const value of [
      'example-pod',
      'example-node',
      'deployment.environment.name',
      'service.instance.id',
      'instance-test',
      'application.requests',
    ])
      assert.ok(wire.includes(value));
    assert.ok(wire.includes(JSON.stringify([...DURATION_BUCKETS_SECONDS])));
    assert.equal(telemetry.stats().spansStarted, 2);
    assert.equal(telemetry.stats().spansEnded, 2);
    assert.equal(telemetry.stats().pendingSpans, 0);
    assert.equal(trace.getTracerProvider(), globalTracer);
    assert.equal(metrics.getMeterProvider(), globalMeter);
    assert.equal(context.active(), before);
  } finally {
    await telemetry.close();
    await target.close();
  }
});

test('EK-OTEL-001 W3C propagation preserves independent async parents and ignores baggage as identity', async () => {
  const target = await receiver();
  const telemetry = createTelemetry(options(target.endpoint));
  const first = '1234567890abcdef1234567890abcdef',
    second = 'abcdef1234567890abcdef1234567890';
  try {
    await Promise.all(
      [first, second].map((id) =>
        telemetry.withRemoteContext(
          {
            traceparent: `00-${id}-1234567890abcdef-01`,
            tracestate: 'vendor=example',
            baggage: 'tenant_id=fake-tenant',
          },
          () =>
            telemetry.withSpan('request.execute', async () => {
              await delay(5);
              assert.equal(telemetry.currentTraceId(), id);
              assert.ok(!JSON.stringify(telemetry.traceHeaders()).includes('tenant'));
            }),
        ),
      ),
    );
    assert.equal(telemetry.currentTraceId(), undefined);
    assert.deepEqual(telemetry.traceHeaders(), {});
    telemetry.withRemoteContext(
      { traceparent: '00-' + '0'.repeat(32) + '-1234567890abcdef-01' },
      () => assert.equal(telemetry.currentTraceId(), undefined),
    );
    await telemetry.flush();
    const wire = JSON.stringify(target.data);
    assert.ok(wire.includes(first) && wire.includes(second));
    assert.ok(!wire.includes('fake-tenant'));
  } finally {
    await telemetry.close();
    await target.close();
  }
});

test('EK-OTEL-001 telemetry always preserves business values and original exceptions without secret-bearing span events', async () => {
  const target = await receiver();
  const telemetry = createTelemetry({ ...options(target.endpoint), maxSeriesPerInstrument: 1 });
  try {
    const failure = new KitError({
      code: 'EK_DATABASE_QUERY',
      message: 'fake-private-database-token',
    });
    await assert.rejects(
      telemetry.measure('first', () => {
        throw failure;
      }),
      (error) => error === failure,
    );
    assert.equal(await telemetry.measure('second', () => 'business-result'), 'business-result');
    assert.equal(telemetry.stats().droppedMetrics, 1);
    await telemetry.flush();
    const wire = JSON.stringify(target.data);
    assert.ok(!wire.includes('fake-private-database-token'));
    assert.ok(wire.includes('EK_DATABASE_QUERY'));
    await assert.rejects(telemetry.withSpan('bad', null as never), code('EK_CONFIG_INVALID'));
    await assert.rejects(telemetry.measure('bad', null as never), code('EK_CONFIG_INVALID'));
    assert.throws(() => telemetry.withRemoteContext({}, null as never), code('EK_CONFIG_INVALID'));
  } finally {
    await telemetry.close();
    await target.close();
  }
});

test('EK-OTEL-001 metric inputs reject unsafe labels, changing kinds and bounded cardinality/instrument exhaustion', async () => {
  const target = await receiver();
  const telemetry = createTelemetry({
    ...options(target.endpoint),
    maxInstruments: 2,
    maxSeriesPerInstrument: 1,
  });
  try {
    for (const value of [NaN, Infinity, -1])
      assert.throws(() => telemetry.addCounter('count', value), code('EK_CONFIG_INVALID'));
    for (const attrs of [
      { tenant_id: 'fake' },
      { requestId: 'fake' },
      { route: '/raw/123' },
      { method: 'CUSTOM' },
      { status_code: 600 },
      { service: 'other' },
      { state: 'fake' },
      { method: [] },
      3,
      null,
      { method: 'GET', a: 1, b: 1, c: 1, d: 1, e: 1, f: 1, g: 1, h: 1 },
    ])
      assert.throws(
        () => telemetry.addCounter('count', 1, attrs as never),
        code('EK_CONFIG_INVALID'),
      );
    for (const name of ['', 'bad name', 'x'.repeat(129)])
      assert.throws(() => telemetry.setGauge(name, 1), code('EK_CONFIG_INVALID'));
    telemetry.addCounter('count', 0, { method: 'GET' });
    assert.throws(
      () => telemetry.addCounter('count', 1, { method: 'POST' }),
      code('EK_CONFIG_INVALID'),
    );
    assert.throws(
      () => telemetry.setGauge('count', 1, { method: 'GET' }),
      code('EK_CONFIG_INVALID'),
    );
    telemetry.recordHistogram('size', -1);
    assert.throws(() => telemetry.recordHistogram('size', NaN), code('EK_CONFIG_INVALID'));
    assert.throws(() => telemetry.setGauge('third', 1), code('EK_CONFIG_INVALID'));
    assert.equal(telemetry.stats().instruments, 2);
    assert.equal(telemetry.stats().metricSeries, 2);
    await assert.rejects(
      telemetry.withSpan('bad operation', () => 1),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(
      telemetry.measure('bad operation', () => 1),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(
      telemetry.measure('valid', () => 1, { attributes: { tenant_id: 'fake' } }),
      code('EK_CONFIG_INVALID'),
    );
  } finally {
    await telemetry.close();
    await target.close();
  }
});

test('EK-OTEL-001 queue saturation and active-span bounds drop diagnostics while work continues', async () => {
  const target = await receiver();
  target.mode('hang');
  const telemetry = createTelemetry({
    ...options(target.endpoint),
    spanQueueCapacity: 1,
    maxActiveSpans: 1,
    exportTimeoutMs: 100,
  });
  try {
    await telemetry.withSpan('outer', () => telemetry.withSpan('inner', () => 'ok'));
    await telemetry.withSpan('next', () => 1);
    assert.ok(telemetry.stats().droppedSpans >= 2);
    assert.ok(telemetry.stats().pendingSpans <= 1);
    assert.equal(telemetry.stats().activeSpans, 0);
    await assert.rejects(telemetry.flush({ timeoutMs: 20 }), code('EK_TIMEOUT'));
    await assert.rejects(telemetry.flush({ signal: AbortSignal.abort() }), code('EK_ABORTED'));
  } finally {
    await telemetry.close().catch(() => undefined);
    await target.close();
  }
});

test('EK-OTEL-001 rejected exporters report typed failures without altering completed work', async () => {
  const target = await receiver();
  target.mode('error');
  const telemetry = createTelemetry(options(target.endpoint));
  try {
    assert.equal(await telemetry.measure('completed', () => 7), 7);
    await assert.rejects(
      telemetry.flush(),
      (error) =>
        error instanceof KitError && ['EK_BACKEND_UNAVAILABLE', 'EK_TIMEOUT'].includes(error.code),
    );
    assert.ok(telemetry.stats().exportFailures > 0);
  } finally {
    await telemetry.close().catch(() => undefined);
    await target.close();
  }
});

test('EK-OTEL-001 off, minimal and zero sampling modes expose actual configuration and close resources', async () => {
  const off = createTelemetry({ service, mode: 'off' });
  assert.deepEqual(off.status(), {
    mode: 'off',
    metrics: false,
    tracing: false,
    globalProvider: false,
  });
  off.addCounter('ignored', NaN, { tenant_id: 'not-exported' });
  assert.equal(await off.measure('ignored', () => 3), 3);
  assert.equal(await off.withSpan('ignored', () => 4), 4);
  await off.flush();
  const closing = off.close();
  assert.equal(off.close(), closing);
  await closing;
  for (const work of [
    () => off.addCounter('x', 1),
    () => off.native(),
    () => off.traceHeaders(),
    () => off.currentTraceId(),
    () => off.withRemoteContext({}, () => 1),
  ])
    assert.throws(work, code('EK_RESOURCE_CLOSED'));
  await assert.rejects(
    off.measure('x', () => 1),
    code('EK_RESOURCE_CLOSED'),
  );
  await assert.rejects(off.flush(), code('EK_RESOURCE_CLOSED'));
  const target = await receiver();
  for (const mode of ['minimal', 'standard'] as const) {
    const telemetry = createTelemetry({ ...options(target.endpoint), mode, samplingRatio: 0 });
    try {
      await telemetry.measure('sampled.out', () => 1);
      await telemetry.flush();
    } finally {
      await telemetry.close();
    }
  }
  assert.ok(!target.data.some((entry) => entry.path === '/v1/traces'));
  await target.close();
});

test('EK-OTEL-001 close ends active spans once and rejects new work while callback cleanup remains independent', async () => {
  const target = await receiver();
  const telemetry = createTelemetry(options(target.endpoint));
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const running = telemetry.withSpan('active', async () => {
    await gate;
    return 5;
  });
  await telemetry.close();
  release();
  assert.equal(await running, 5);
  assert.equal(telemetry.stats().spansEnded, 1);
  assert.equal(telemetry.stats().activeSpans, 0);
  await target.close();
});

test('EK-OTEL-001 invalid resource/export policies fail before opening resources', () => {
  for (const partial of [
    { mode: 'bad' },
    { samplingRatio: NaN },
    { samplingRatio: 2 },
    { exportTimeoutMs: 0 },
    { exportIntervalMs: 1 },
    { spanQueueCapacity: 0 },
    { maxActiveSpans: 0 },
    { maxInstruments: 0 },
    { maxSeriesPerInstrument: 0 },
    { instanceId: 'bad id' },
    { workload: { namespace: 'bad namespace' } },
    { workload: { unexpected: 'value' } },
    { labelValues: { tenant_id: ['bad'] } },
    { labelValues: { route: [] } },
    { labelValues: { route: [null] } },
    { endpoint: 'https://user:fake@collector.invalid' },
    { endpoint: 'http://169.254.169.254' },
    { endpoint: 'https://collector.invalid/path' },
    { endpoint: 'https://collector.invalid/?bad' },
    { endpoint: 'bad' },
    { allowInsecureLoopback: 'yes' },
    { service: { ...service, name: 'Bad service' } },
    { service: { ...service, version: 'no-version' } },
  ])
    assert.throws(
      () =>
        createTelemetry({ ...options('http://127.0.0.1:4318'), ...partial } as TelemetryOptions),
      code('EK_CONFIG_INVALID'),
    );
  assert.throws(
    () =>
      createTelemetry({
        service: { ...service, environment: 'production' },
        endpoint: 'http://127.0.0.1:4318',
        allowInsecureLoopback: true,
      }),
    code('EK_CONFIG_INVALID'),
  );
});

const quiet = (): Logger => {
  const log = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    setLevel() {},
    flush: async () => {},
    child: () => log,
  };
  return log;
};
const logging: Plugin = {
  id: 'logging',
  version: '1.0.0',
  capabilities: new Set(['logger']),
  init(ctx) {
    ctx.provide(COMPONENTS.logger, quiet());
  },
  close() {},
};
test('EK-OTEL-001 reused plugin factories provide independent application instances without global SDK replacement', async () => {
  const plugin = telemetryPlugin();
  const first = await createApplication({ service, plugins: [logging, plugin] });
  const second = await createApplication({ service, plugins: [logging, plugin] });
  try {
    await first.start();
    await second.start();
    assert.notEqual(first.telemetry, second.telemetry);
    await first.stop();
    assert.equal(await second.telemetry.measure('still.available', () => 9), 9);
  } finally {
    await first.stop();
    await second.stop();
  }
});

test('EK-DB-004 root database names permit bounded pool metrics and fixed SQL operation labels', async () => {
  const target = await receiver();
  const driver: Plugin = {
    id: 'database-test-port',
    version: '1.0.0',
    capabilities: new Set(['database.postgresql']),
    init() {},
    close() {},
  };
  const app = await createApplication({
    service,
    telemetry: { mode: 'standard', samplingRatio: 1 },
    databases: { main: { driver: 'postgresql' }, secondary: { driver: 'postgresql' } },
    plugins: [
      logging,
      driver,
      telemetryPlugin({
        endpoint: target.endpoint,
        allowInsecureLoopback: true,
        exportTimeoutMs: 500,
      }),
    ],
  });
  try {
    await app.start();
    assert.equal(
      await app.telemetry.withSpan('db.client.operation', () => 42, {
        attributes: { 'db.system.name': 'postgresql', 'db.operation.name': 'query' },
      }),
      42,
    );
    app.telemetry.recordHistogram('db.client.operation.duration', 0.002, {
      'db.system.name': 'postgresql',
      'db.operation.name': 'execute',
    });
    for (const operation of ['get', 'set', 'del', 'increment', 'publish']) {
      await app.telemetry.withSpan('db.client.operation', () => 1, {
        attributes: { 'db.system.name': 'redis', 'db.operation.name': operation },
      });
      app.telemetry.recordHistogram('db.client.operation.duration', 0.001, {
        'db.system.name': 'redis',
        'db.operation.name': operation,
      });
    }
    app.telemetry.recordHistogram('arkenivajs.db.pool.acquire.duration', 0.001, {
      pool: 'main',
      driver: 'postgresql',
    });
    app.telemetry.setGauge('arkenivajs.db.pool.active', 1, { pool: 'main', driver: 'postgresql' });
    app.telemetry.setGauge('arkenivajs.db.pool.idle', 0, {
      pool: 'secondary',
      driver: 'postgresql',
    });
    assert.throws(
      () =>
        app.telemetry.setGauge('arkenivajs.db.pool.active', 1, {
          pool: 'request-controlled',
          driver: 'postgresql',
        }),
      code('EK_CONFIG_INVALID'),
    );
    assert.throws(
      () =>
        app.telemetry.recordHistogram('db.client.operation.duration', 1, {
          'db.operation.name': 'arbitrary SQL',
        }),
      code('EK_CONFIG_INVALID'),
    );
    await app.telemetry.flush();
    const body = JSON.stringify(target.data);
    for (const expected of [
      'db.client.operation.duration',
      'arkenivajs.db.pool.acquire.duration',
      'arkenivajs.db.pool.active',
      'arkenivajs.db.pool.idle',
      '{connection}',
      'redis',
      'increment',
      'publish',
    ])
      assert.ok(body.includes(expected));
    assert.equal((app.telemetry as ManagedTelemetry).stats().exportFailures, 0);
  } finally {
    await app.stop();
    await target.close();
  }
});
