import test from 'node:test';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApplication, COMPONENTS, APPLICATION_SIGNAL, KitError } from '@arkenivajs/core';
import type {
  Plugin,
  Logger,
  VerifiedTenantContext,
  TenantId,
  ApplicationOptions,
  PluginContext,
  MeteringEvent,
} from '@arkenivajs/core';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import type { MeterExporter } from '@arkenivajs/metering';

const service = { name: 'meter-plugin', version: '1.0.0', environment: 'test' as const };
const logger: Logger = {
  trace() {},
  debug() {},
  info() {},
  warn() {},
  error() {},
  fatal() {},
  setLevel() {},
  async flush() {},
  child() {
    return logger;
  },
};
const logging: Plugin = {
  id: 'logging',
  version: '1.0.0',
  capabilities: new Set(['logger']),
  init(context) {
    context.provide(COMPONENTS.logger, logger);
  },
  close() {},
};
const tenant: VerifiedTenantContext = Object.freeze({
  tenantId: 'tenant-plugin' as TenantId,
  identity: {
    subject: 'test',
    issuer: 'https://issuer.invalid',
    audience: ['api'],
    scopes: [],
    claims: {},
  },
  verifiedAt: new Date().toISOString(),
  source: 'oidc',
});
const auth = {
  isVerifiedTenant: (value: unknown): value is VerifiedTenantContext => value === tenant,
};
const security: Plugin = {
  id: 'security',
  version: '1.0.0',
  capabilities: new Set(['auth']),
  init(context) {
    context.provide(COMPONENTS.auth, auth);
  },
  close() {},
};
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const startupCode = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === 'EK_PLUGIN_FAILED' && code(expected)(error.cause);

function context(
  options: ApplicationOptions,
  provide: PluginContext['provide'] = () => {},
  signal = new AbortController().signal,
): PluginContext {
  return {
    options,
    logger,
    provide,
    require<T>(key: symbol): T {
      if (key === APPLICATION_SIGNAL) return signal as T;
      if (key === COMPONENTS.auth) return auth as T;
      if (key === COMPONENTS.telemetry)
        return { currentTraceId: () => '0123456789abcdef0123456789abcdef' } as T;
      throw new Error('Unexpected test dependency');
    },
  };
}

test('EK-METER-001 root JSONL plugin owns per-application files, flushes on shutdown and preserves independent instances', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-plugin-'));
  const plugin = meteringPlugin({ workspace });
  const first = await createApplication({
    service,
    metering: { enabled: true, path: 'first.jsonl' },
    plugins: [logging, security, plugin],
  });
  const second = await createApplication({
    service: { ...service, name: 'meter-plugin-other' },
    metering: { enabled: true, exporter: 'jsonl', path: 'second.jsonl' },
    plugins: [logging, security, plugin],
  });
  try {
    await first.start();
    await second.start();
    assert.notEqual(first.meter, second.meter);
    await first.meter!.measure({ tenant, operation: 'first' }, () =>
      first.meter!.current()!.recordOperation('db.query'),
    );
    await second.meter!.measure({ tenant, operation: 'second' }, () => 'ok');
    await first.stop();
    await second.stop();
    const one = parseMeteringEvent(
      JSON.parse((await readFile(join(workspace, 'first.jsonl'), 'utf8')).trim()),
    );
    const two = parseMeteringEvent(
      JSON.parse((await readFile(join(workspace, 'second.jsonl'), 'utf8')).trim()),
    );
    assert.equal(one.operation, 'first');
    assert.equal(two.operation, 'second');
    assert.notEqual(one.instanceId, two.instanceId);
    assert.notEqual(one.eventId, two.eventId);
  } finally {
    await first.stop();
    await second.stop();
    await rm(workspace, { recursive: true, force: true });
  }
});

test('EK-METER-001 disabled root plugin performs no export and root policy rejects missing/conflicting transports', async () => {
  const disabled = await createApplication({
    service,
    metering: { enabled: false },
    plugins: [logging, security, meteringPlugin()],
  });
  try {
    await disabled.start();
    await disabled.meter!.measure({ tenant, operation: 'disabled' }, () => 1);
    assert.equal(disabled.meter!.stats().dropped, 1);
  } finally {
    await disabled.stop();
  }
  for (const [config, options, expected] of [
    [undefined, {}, 'EK_CONFIG_INVALID'],
    [{ enabled: true, exporter: 'jsonl' }, {}, 'EK_CONFIG_MISSING'],
    [{ enabled: true, exporter: 'http' }, {}, 'EK_CONFIG_MISSING'],
    [{ enabled: true, exporter: 'otlp' }, {}, 'EK_UNSUPPORTED_CAPABILITY'],
  ] as const) {
    const app = await createApplication({
      service,
      ...(config ? { metering: config } : {}),
      plugins: [logging, security, meteringPlugin(options)],
    });
    await assert.rejects(app.start(), startupCode(expected));
    assert.equal(app.state, 'CLOSED');
    await app.stop();
  }
  let closed = 0;
  const exporter: MeterExporter = {
    kind: 'jsonl',
    async export() {},
    async close() {
      closed++;
    },
  };
  const bad = meteringPlugin({ exporter });
  await assert.rejects(
    Promise.resolve(bad.init(context({ service, metering: { enabled: true, exporter: 'http' } }))),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(closed, 1);
});

test('EK-METER-001 failed registry publication and cancellation release partially acquired exporters without hiding cleanup failures', async () => {
  for (const cleanupFails of [false, true]) {
    let closed = 0;
    const primary = new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Registry rejected test publication',
    });
    const plugin = meteringPlugin({
      exporter: {
        kind: 'jsonl',
        async export() {},
        async close() {
          closed++;
          if (cleanupFails) throw new Error('fake-cleanup');
        },
      },
    });
    const ctx = context({ service, metering: { enabled: true, exporter: 'jsonl' } }, () => {
      throw primary;
    });
    await assert.rejects(Promise.resolve(plugin.init(ctx)), (error) =>
      cleanupFails ? code('EK_METER_EXPORT')(error) : error === primary,
    );
    assert.equal(closed, 1);
    await plugin.close(ctx);
    assert.equal(closed, 1);
  }
  let closed = 0;
  const cancelled = meteringPlugin({
    exporter: {
      kind: 'jsonl',
      async export() {},
      async close() {
        closed++;
      },
    },
  });
  await assert.rejects(
    Promise.resolve(
      cancelled.init(
        context({ service, metering: { enabled: true } }, () => {}, AbortSignal.abort()),
      ),
    ),
    code('EK_ABORTED'),
  );
  assert.equal(closed, 1);
});

test('EK-METER-001 explicit root telemetry dependency supplies correlation without substituting spans for events', async () => {
  const events: MeteringEvent[] = [];
  const plugin = meteringPlugin({
    dependencies: ['telemetry'],
    exporter: {
      kind: 'http',
      async export(batch) {
        events.push(...batch);
      },
      async close() {},
    },
  });
  let provided: unknown;
  const ctx = context(
    {
      service,
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'otlp', queueCapacity: 2 },
    },
    (_key, value) => {
      provided = value;
    },
  );
  await plugin.init(ctx);
  const meter = provided as ReturnType<(typeof import('@arkenivajs/metering'))['createMeter']>;
  await meter.measure({ tenant, operation: 'correlated' }, () => 1);
  await meter.flush();
  assert.equal(events.length, 1);
  assert.equal(events[0]!.traceId, '0123456789abcdef0123456789abcdef');
  await plugin.close(ctx);
  const unsupported = await createApplication({
    service,
    metering: { enabled: false },
    plugins: [
      logging,
      {
        ...security,
        init(ctx) {
          ctx.provide(COMPONENTS.auth, {});
        },
      },
      meteringPlugin(),
    ],
  });
  await assert.rejects(unsupported.start(), startupCode('EK_CONFIG_INVALID'));
  await unsupported.stop();
});

test('EK-METER-001 root HTTP policy owns an authenticated collector independently from the application client', async () => {
  const events: MeteringEvent[] = [];
  const server = createServer(async (request, reply) => {
    assert.equal(request.headers.authorization, 'Bearer fake-root-collector');
    const chunks: Buffer[] = [];
    for await (const part of request) chunks.push(part);
    const batch = JSON.parse(Buffer.concat(chunks).toString()) as { events: MeteringEvent[] };
    events.push(...batch.events);
    reply.statusCode = 202;
    reply.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const app = await createApplication({
    service,
    metering: { enabled: true, exporter: 'http', endpoint: `http://127.0.0.1:${address.port}` },
    plugins: [
      logging,
      security,
      meteringPlugin({
        http: { allowInsecureLoopback: true, authorization: () => 'Bearer fake-root-collector' },
      }),
    ],
  });
  try {
    await app.start();
    await app.meter!.measure({ tenant, operation: 'root.http' }, () => 1);
    await app.stop();
    assert.equal(events.length, 1);
    assert.equal(events[0]!.operation, 'root.http');
  } finally {
    await app.stop();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
