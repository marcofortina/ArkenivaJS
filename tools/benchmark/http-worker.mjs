import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createWriteStream } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { Session } from 'node:inspector';
import { performance, monitorEventLoopDelay, PerformanceObserver } from 'node:perf_hooks';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import Fastify from 'fastify';
import { Ajv } from 'ajv';
import { randomUUID } from 'node:crypto';
import pino from 'pino';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Pool } from 'pg';
import Cursor from 'pg-cursor';
import { parse, toClientConfig } from 'pg-connection-string';
import { checkServerIdentity } from 'node:tls';
import { setInterval, clearInterval } from 'node:timers';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin } from '@arkenivajs/metering';
import { postgresPlugin } from '@arkenivajs/database-postgres';

const require = createRequire(import.meta.url);
const response = { ok: true, value: 7, padding: 'x'.repeat(94) };
assert.equal(Buffer.byteLength(JSON.stringify(response)), 128);
const responseSchema = {
  type: 'object',
  properties: {
    ok: { const: true },
    value: { const: 7 },
    padding: { type: 'string', minLength: 94, maxLength: 94 },
  },
  required: ['ok', 'value', 'padding'],
  additionalProperties: false,
};
const modes = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'];
const routes = ['/json', '/authenticated', '/database'];
const hasControls = (value, includeSpace = false) => {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= (includeSpace ? 32 : 31) || code === 127) return true;
  }
  return false;
};
const gauges = new Set([
  'queueDepth',
  'pendingSpans',
  'activeSpans',
  'instruments',
  'metricSeries',
  'pendingBytes',
  'active',
]);
const difference = (after, before) =>
  after
    ? Object.fromEntries(
        Object.entries(after).map(([key, value]) => [
          key,
          gauges.has(key) ? value : value - (before?.[key] ?? 0),
        ]),
      )
    : null;
const rank = (values, quantile) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b),
    index = (sorted.length - 1) * quantile;
  return (
    sorted[Math.floor(index)] +
    (sorted[Math.ceil(index)] - sorted[Math.floor(index)]) * (index - Math.floor(index))
  );
};

/** An isolated server process owns its resources; the controller owns offered load and raw artifacts. */
export async function startWorker(settings) {
  assert.ok(settings && modes.includes(settings.mode));
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_POSTGRES_URL);
  assert.match(settings.issuer, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.match(settings.otlpEndpoint, /^http:\/\/127\.0\.0\.1:\d+$/);
  const service = { name: 'http-performance', version: '1.0.0', environment: 'test' },
    sink = createWriteStream(join(settings.directory, 'application.jsonl'), {
      flags: 'wx',
      mode: 0o600,
    }),
    samples = [],
    pauses = [],
    delay = monitorEventLoopDelay({ resolution: 10 });
  let app,
    native,
    pool,
    logger,
    meter,
    telemetry,
    timer,
    measurement,
    closePromise,
    sinkFailure,
    profiler,
    databaseVersion,
    gcOverflow = 0,
    finished = false;
  sink.on('error', (error) => {
    sinkFailure = error;
  });
  const close = () =>
    (closePromise ??= (async () => {
      clearInterval(timer);
      profiler?.disconnect();
      gc.disconnect();
      delay.disable();
      const failures = [];
      if (app) {
        try {
          await app.stop({ timeoutMs: 10000 });
        } catch (error) {
          failures.push(error);
        }
      } else {
        for (const resource of [() => native?.close(), () => pool?.end()]) {
          try {
            await resource();
          } catch (error) {
            failures.push(error);
          }
        }
      }
      if (!sink.destroyed) {
        try {
          await new Promise((resolve, reject) => {
            sink.once('error', reject);
            sink.end(resolve);
          });
        } catch (error) {
          failures.push(error);
        }
      }
      if (sinkFailure) failures.push(sinkFailure);
      if (failures.length) throw new AggregateError(failures, 'Benchmark resource cleanup failed');
    })());
  const counts = {
    completed: 0,
    failed: 0,
    active: 0,
    maxActive: 0,
    maxPoolWaiting: 0,
    maxMeterQueue: 0,
    maxLogBacklogBytes: 0,
  };
  const collect = () => {
    if (sinkFailure)
      throw new Error('The benchmark log destination failed', { cause: sinkFailure });
    const memory = process.memoryUsage();
    if (memory.rss > 1_073_741_824) throw new Error('The benchmark server exceeded its RSS bound');
    if (samples.length < 8000)
      samples.push({
        elapsedMs: performance.now() - measurement.at,
        rss: memory.rss,
        heap: memory.heapUsed,
      });
    counts.maxPoolWaiting = Math.max(counts.maxPoolWaiting, pool?.waitingCount ?? 0);
    counts.maxMeterQueue = Math.max(counts.maxMeterQueue, meter?.stats().queueDepth ?? 0);
    counts.maxLogBacklogBytes = Math.max(counts.maxLogBacklogBytes, sink.writableLength);
  };
  const gc = new PerformanceObserver((list) => {
    if (!measurement || finished) return;
    for (const entry of list.getEntries()) {
      if (pauses.length < 50000) pauses.push(entry.duration);
      else gcOverflow++;
    }
  });
  gc.observe({ entryTypes: ['gc'] });
  const startup = performance.now();
  async function query(tenant) {
    if (app) {
      const value = await app.sql.queryOne('main', {
        text: 'SELECT :value::integer AS value, :tenant::text AS tenant',
        bindings: { value: 7, tenant },
      });
      assert.deepEqual(value, { value: 7, tenant });
      return;
    }
    const client = await pool.connect();
    try {
      await client.query('DISCARD ALL');
      await client.query("SET client_encoding TO 'UTF8'; SET standard_conforming_strings TO on");
      const cursor = client.query(
        new Cursor('SELECT $1::integer AS value, $2::text AS tenant', [7, tenant]),
      );
      try {
        assert.deepEqual(await cursor.read(2), [{ value: 7, tenant }]);
      } finally {
        await cursor.close();
      }
    } finally {
      client.release();
    }
  }
  try {
    if (settings.mode === 'BASELINE') {
      logger = pino(
        {
          level: 'info',
          timestamp: pino.stdTimeFunctions.isoTime,
          base: {
            service: service.name,
            serviceVersion: service.version,
            environment: service.environment,
          },
          redact: { paths: ['authorization'], censor: '[REDACTED]' },
        },
        sink,
      );
      native = Fastify({
        logger: false,
        genReqId: randomUUID,
        bodyLimit: 1048576,
        requestTimeout: 30000,
        ajv: { customOptions: { coerceTypes: false, useDefaults: false, removeAdditional: false } },
      });
      const validate = new Ajv({ strict: true, allErrors: false }).compile(responseSchema);
      const configuration = toClientConfig(parse(process.env.ARKENIVA_POSTGRES_URL));
      assert.ok(configuration.ssl && typeof configuration.ssl === 'object' && configuration.host);
      pool = new Pool({
        ...configuration,
        ssl: {
          ...configuration.ssl,
          rejectUnauthorized: true,
          checkServerIdentity: (_name, certificate) =>
            checkServerIdentity(configuration.host, certificate),
        },
        max: 2,
        connectionTimeoutMillis: 5000,
        client_encoding: 'UTF8',
        pipeline: false,
        enableChannelBinding: true,
      });
      const discovery = await globalThis.fetch(
        settings.issuer + '/.well-known/openid-configuration',
        {
          signal: AbortSignal.timeout(5000),
          redirect: 'error',
        },
      );
      assert.ok(discovery.ok);
      const metadata = await discovery.json();
      assert.equal(metadata.issuer, settings.issuer);
      assert.equal(metadata.jwks_uri, settings.issuer + '/keys');
      const keys = createRemoteJWKSet(new URL(metadata.jwks_uri));
      await pool.query('SELECT 1');
      const began = new WeakMap();
      native.addHook('onRequest', async (request) => {
        began.set(request, performance.now());
        counts.active++;
        counts.maxActive = Math.max(counts.maxActive, counts.active);
      });
      native.addHook('onResponse', async (request, reply) => {
        counts.active--;
        counts.completed++;
        if (reply.statusCode >= 400) counts.failed++;
        logger.info(
          {
            requestId: request.id,
            method: request.method,
            route: request.routeOptions.url ?? 'unmatched',
            status: reply.statusCode,
            durationMs: performance.now() - began.get(request),
          },
          'HTTP request completed',
        );
      });
      for (const path of routes)
        native.get(
          path,
          { schema: { response: { 200: responseSchema } } },
          async (request, reply) => {
            let tenant;
            if (path !== '/json') {
              try {
                assert.ok(typeof request.headers.authorization === 'string');
                assert.ok(request.headers.authorization.length <= 16384);
                assert.match(
                  request.headers.authorization,
                  /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/i,
                );
                const { payload } = await jwtVerify(request.headers.authorization.slice(7), keys, {
                  issuer: settings.issuer,
                  audience: settings.audience,
                  algorithms: ['RS256'],
                  clockTolerance: 5,
                  typ: 'JWT',
                  requiredClaims: ['sub', 'iss', 'aud', 'exp'],
                });
                assert.ok(
                  typeof payload.sub === 'string' &&
                    payload.sub.length > 0 &&
                    payload.sub.length <= 512 &&
                    !hasControls(payload.sub, true),
                );
                const scopes = payload.scope ?? payload.scp ?? '';
                assert.ok(
                  typeof scopes === 'string' && scopes.length <= 4096 && !hasControls(scopes),
                );
                if (!scopes.split(' ').includes('orders:read'))
                  return reply.code(403).send({ error: { code: 'EK_AUTH_FORBIDDEN' } });
                if (
                  typeof payload.tenant_id !== 'string' ||
                  !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\s\S])/.test(payload.tenant_id)
                )
                  return reply.code(403).send({ error: { code: 'EK_TENANT_UNVERIFIED' } });
                tenant = payload.tenant_id;
              } catch {
                return reply.code(401).send({ error: { code: 'EK_AUTH_INVALID' } });
              }
            }
            if (path === '/database') await query(tenant);
            assert.ok(validate(response));
            return response;
          },
        );
      await native.listen({ host: '127.0.0.1', port: 0 });
    } else {
      const reservation = createServer();
      await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve));
      const port = reservation.address().port;
      await new Promise((resolve) => reservation.close(resolve));
      const mode =
        settings.mode === 'FRAMEWORK'
          ? 'off'
          : settings.mode === 'STANDARD'
            ? 'standard'
            : 'detailed';
      app = await createApplication({
        service,
        http: { host: '127.0.0.1', port },
        security: { issuer: settings.issuer, audience: settings.audience, algorithms: ['RS256'] },
        ...(mode === 'off'
          ? {}
          : {
              telemetry: { mode, samplingRatio: mode === 'detailed' ? 1 : 0.1 },
              metering: { enabled: true, exporter: 'jsonl', path: 'metering.jsonl' },
            }),
        databases: {
          main: { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_POSTGRES_URL', poolMax: 2 },
        },
        plugins: [
          loggingPlugin({ destination: sink }),
          securityPlugin({ allowInsecureLoopback: true }),
          ...(mode === 'off'
            ? []
            : [
                telemetryPlugin({
                  endpoint: settings.otlpEndpoint,
                  allowInsecureLoopback: true,
                  labelValues: { route: routes },
                }),
                meteringPlugin({ workspace: settings.directory, dependencies: ['telemetry'] }),
              ]),
          postgresPlugin(),
          apiPlugin({
            dependencies: ['security', ...(mode === 'off' ? [] : ['metering', 'telemetry'])],
          }),
        ],
      });
      for (const path of routes)
        app.api.get(path, {
          schema: { response: responseSchema },
          auth: {
            required: path !== '/json',
            ...(path === '/json' ? {} : { scopes: ['orders:read'] }),
          },
          handler: async (context) => {
            if (path === '/database') await query(context.auth.tenantId);
            return response;
          },
        });
      native = app.api.native();
      native.addHook('onRequest', async () => {
        counts.active++;
        counts.maxActive = Math.max(counts.maxActive, counts.active);
      });
      native.addHook('onResponse', async (_request, reply) => {
        counts.active--;
        counts.completed++;
        if (reply.statusCode >= 400) counts.failed++;
      });
      await app.start();
      pool = app.sql.native('main');
      logger = app.logger;
      if (mode !== 'off') {
        meter = app.meter;
        telemetry = app.telemetry;
      }
    }
    databaseVersion = (await pool.query('SHOW server_version')).rows[0].server_version;
  } catch (cause) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([cause, cleanup], 'Benchmark startup and cleanup failed', {
        cause: cleanup,
      });
    }
    throw cause;
  }
  const address = native.server.address();
  assert.ok(address && typeof address === 'object');
  return {
    address: 'http://127.0.0.1:' + address.port,
    startupMs: performance.now() - startup,
    versions: {
      node: process.version,
      openssl: process.versions.openssl,
      fastify: require('fastify/package.json').version,
      pg: require('pg/package.json').version,
      postgresServer: databaseVersion,
    },
    async begin() {
      assert.equal(measurement, undefined);
      assert.equal(counts.active, 0);
      await meter?.flush();
      await telemetry?.flush();
      for (const name of Object.keys(counts)) counts[name] = 0;
      if (settings.mode === 'DETAILED') {
        profiler = new Session();
        profiler.connect();
        const command = (method, parameters = {}) =>
          new Promise((resolve, reject) =>
            profiler.post(method, parameters, (error, result) =>
              error ? reject(error) : resolve(result),
            ),
          );
        await command('Profiler.enable');
        await command('Profiler.setSamplingInterval', { interval: 10000 });
        await command('Profiler.start');
      }
      measurement = {
        at: performance.now(),
        cpu: process.cpuUsage(),
        loop: performance.eventLoopUtilization(),
        meter: meter?.stats(),
        telemetry: telemetry?.stats?.(),
        logs: logger?.stats?.(),
        api: app?.api.stats(),
      };
      delay.enable();
      delay.reset();
      collect();
      timer = setInterval(collect, 1000);
      timer.unref();
    },
    async finish() {
      assert.ok(measurement && !finished);
      collect();
      finished = true;
      clearInterval(timer);
      const cpu = process.cpuUsage(measurement.cpu),
        loop = performance.eventLoopUtilization(measurement.loop),
        durationMs = performance.now() - measurement.at;
      const result = {
        durationMs,
        counts: { ...counts },
        cpuDeltaMicros: cpu,
        cpuSecondsPer1000Requests: counts.completed
          ? ((cpu.user + cpu.system) / 1e6 / counts.completed) * 1000
          : null,
        rssBytes: {
          mean: samples.reduce((sum, sample) => sum + sample.rss, 0) / samples.length,
          max: Math.max(...samples.map((sample) => sample.rss)),
          first: samples[0].rss,
          last: samples.at(-1).rss,
        },
        heapBytes: { first: samples[0].heap, last: samples.at(-1).heap },
        samples,
        eventLoop: {
          utilization: loop.utilization,
          delayP99Ms: delay.count ? delay.percentile(99) / 1e6 : null,
        },
        gc: {
          count: pauses.length,
          discardedObservations: gcOverflow,
          supported: PerformanceObserver.supportedEntryTypes.includes('gc'),
          durationMs: pauses.reduce((sum, value) => sum + value, 0),
          p50Ms: rank(pauses, 0.5),
          p95Ms: rank(pauses, 0.95),
          p99Ms: rank(pauses, 0.99),
        },
        meter: difference(meter?.stats(), measurement.meter),
        telemetry: difference(telemetry?.stats?.(), measurement.telemetry),
        logs: difference(logger?.stats?.(), measurement.logs),
        api: difference(app?.api.stats(), measurement.api),
        measurementCoverage: [
          'CPU, RSS, heap, event loop and GC describe the server process, never an exact tenant or request allocation',
          'RSS sampled once per second; short peaks may be missed',
          'Pool waiting is sampled, not a complete contention history',
          'No database-server CPU or TLS/network-billed egress measurement',
        ],
      };
      if (profiler) {
        const profile = await new Promise((resolve, reject) =>
          profiler.post('Profiler.stop', (error, result) =>
            error ? reject(error) : resolve(result.profile),
          ),
        );
        const encoded = JSON.stringify(profile);
        assert.ok(
          Buffer.byteLength(encoded) <= 33554432,
          'The CPU profile exceeded its artifact bound',
        );
        await writeFile(join(settings.directory, 'server.cpuprofile'), encoded, {
          flag: 'wx',
          mode: 0o600,
        });
        profiler.disconnect();
        profiler = undefined;
      }
      await meter?.flush();
      await telemetry?.flush();
      result.afterFlush = {
        meter: difference(meter?.stats(), measurement.meter),
        telemetry: difference(telemetry?.stats?.(), measurement.telemetry),
      };
      return result;
    },
    close,
  };
}

if (process.send) {
  let owner;
  process.once('message', async (settings) => {
    try {
      owner = await startWorker(settings);
      process.send({
        kind: 'ready',
        address: owner.address,
        startupMs: owner.startupMs,
        versions: owner.versions,
      });
      process.on('message', async (message) => {
        try {
          if (message.kind === 'begin') {
            await owner.begin();
            process.send({ kind: 'began' });
          } else if (message.kind === 'finish')
            process.send({ kind: 'result', observations: await owner.finish() });
          else if (message.kind === 'close') {
            await owner.close();
            process.disconnect();
          }
        } catch {
          process.exitCode = 1;
          await owner.close().catch(() => undefined);
          process.disconnect();
        }
      });
    } catch {
      process.exitCode = 1;
      process.send({ kind: 'failure', message: 'The benchmark worker could not initialize' });
      process.disconnect();
    }
  });
}
