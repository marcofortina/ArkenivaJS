// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { cpus, totalmem, release, platform, arch } from 'node:os';
import { checkServerIdentity } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Pool } from 'pg';
import Cursor from 'pg-cursor';
import { parse, toClientConfig } from 'pg-connection-string';
import { Bench } from 'tinybench';
import { createApplication, KitError } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';

const endpoint = process.env.ARKENIVA_POSTGRES_URL;
if (!endpoint || process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
  throw new Error('The PostgreSQL benchmark requires an explicitly disposable endpoint');
const startedAt = new Date().toISOString();
const configuration = toClientConfig(parse(endpoint));
assert.ok(configuration.host && configuration.user && configuration.database);
assert.ok(configuration.ssl && typeof configuration.ssl === 'object');
const host = configuration.host;
const native = new Pool({
  ...configuration,
  ssl: {
    ...configuration.ssl,
    rejectUnauthorized: true,
    checkServerIdentity: (_name, certificate) => checkServerIdentity(host, certificate),
  },
  max: 2,
  connectionTimeoutMillis: 5000,
  client_encoding: 'UTF8',
  query_timeout: 0,
  pipeline: false,
  enableChannelBinding: true,
});
const variable = 'ARKENIVA_POSTGRES_BENCHMARK_URL';
assert.equal(process.env[variable], undefined);
process.env[variable] = endpoint;
let app;
try {
  app = await createApplication({
    service: { name: 'postgres-benchmark', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: variable, poolMax: 2 } },
  });
  await app.start();
  delete process.env[variable];
  const serverVersion = (await native.query('SHOW server_version')).rows[0].server_version;
  const frameworkPool = app.sql.native('main');
  const records = [];
  for (const mode of ['BASELINE', 'FRAMEWORK']) {
    let invocations = 0,
      maxWaiting = 0;
    const work =
      mode === 'BASELINE'
        ? async () => {
            const client = await native.connect();
            try {
              // Match the framework's session isolation, native fetch bound and TLS policy.
              await client.query('DISCARD ALL');
              await client.query(
                "SET client_encoding TO 'UTF8'; SET standard_conforming_strings TO on",
              );
              const cursor = client.query(new Cursor('SELECT $1::int AS value', [7]));
              try {
                const rows = await cursor.read(2);
                assert.deepEqual(rows, [{ value: 7 }]);
              } finally {
                await cursor.close();
              }
            } finally {
              client.release();
            }
          }
        : async () => {
            assert.deepEqual(
              await app.sql.queryOne('main', {
                text: 'SELECT :value::int AS value',
                bindings: { value: 7 },
              }),
              { value: 7 },
            );
          };
    const bench = new Bench({
      time: 0,
      iterations: 1000,
      warmupTime: 0,
      warmupIterations: 100,
      retainSamples: true,
      throws: true,
    });
    bench.add(
      mode,
      async () => {
        await work();
        invocations++;
        maxWaiting = Math.max(
          maxWaiting,
          (mode === 'BASELINE' ? native : frameworkPool).waitingCount,
        );
      },
      { async: true },
    );
    await nextTurn();
    const cpuBefore = process.cpuUsage(),
      memoryBefore = process.memoryUsage(),
      loopBefore = performance.eventLoopUtilization(),
      began = performance.now();
    await bench.run();
    await nextTurn();
    const elapsedMs = performance.now() - began;
    const cpu = process.cpuUsage(cpuBefore),
      memoryAfter = process.memoryUsage();
    const loop = performance.eventLoopUtilization(loopBefore);
    const result = bench.tasks[0].result;
    assert.equal(result.state, 'completed');
    assert.equal(result.latency.samplesCount, 1000);
    assert.equal(result.latency.samples.length, result.latency.samplesCount);
    assert.ok(
      result.latency.samples.length <= 10000 &&
        result.latency.samples.every((value) => Number.isFinite(value) && value >= 0),
    );
    assert.equal(invocations, 1100);
    const samples = [...result.latency.samples].sort((left, right) => left - right);
    const percentile = (quantile) => {
      const rank = (samples.length - 1) * quantile;
      return (
        samples[Math.floor(rank)] +
        (samples[Math.ceil(rank)] - samples[Math.floor(rank)]) * (rank - Math.floor(rank))
      );
    };
    records.push({
      mode,
      measured: true,
      sampleCount: 1000,
      rawLatency: { unit: 'milliseconds', values: [...result.latency.samples] },
      totalInvocations: invocations,
      latencyMs: {
        p50: result.latency.p50,
        p95: percentile(0.95),
        p99: result.latency.p99,
        max: result.latency.max,
      },
      throughputOpsPerSecond: result.throughput.mean,
      errors: 0,
      timeouts: 0,
      cpuDeltaMicros: cpu,
      cpuSecondsPer1000Invocations: (((cpu.user + cpu.system) / 1e6) * 1000) / invocations,
      processMemoryBytes: { before: memoryBefore, after: memoryAfter },
      elapsedIncludingWarmupMs: elapsedMs,
      eventLoop: { utilization: loop.utilization, activeMs: loop.active, idleMs: loop.idle },
      queue: { maximumObservedWaitingAfterCompletion: maxWaiting, contentionScenario: false },
      eventLoopDelayMs: null,
      gcPauseMs: null,
      meterDropped: null,
      networkBytes: null,
    });
  }
  let governor = null;
  try {
    governor = readFileSync('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor', 'utf8').trim();
  } catch {
    /* The runner may not expose CPU frequency policy. */
  }
  console.log(
    JSON.stringify({
      scenarioId: 'postgres-select-one-local-exploration',
      measured: true,
      releaseGate: false,
      gitSha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
      workingTreeDirty:
        execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0,
      nodeVersion: process.version,
      startedAt,
      runIterationCount: 1,
      hardware: {
        cpuModel: cpus()[0]?.model ?? null,
        logicalCpus: cpus().length,
        memoryBytes: totalmem(),
        platform: platform(),
        kernel: release(),
        architecture: arch(),
        affinity: null,
        governor,
        runnerType: 'shared-development-host-with-external-database',
      },
      environment: {
        serverVersion,
        pg: '8.23.1',
        pgCursor: '2.22.1',
        image: process.env.ARKENIVA_POSTGRES_IMAGE ?? null,
        containerLimits: process.env.ARKENIVA_POSTGRES_CONTAINER_LIMITS ?? null,
      },
      loadProfile: {
        concurrency: 1,
        offeredRps: null,
        warmupIterations: 100,
        measuredIterations: 1000,
        schedule: 'sequential-closed-loop',
        seed: null,
      },
      telemetry: { tracing: false, metrics: false, metering: false },
      records,
      coverage: [
        'Both modes use the same SELECT, verified TLS, pool maximum, session reset and bounded two-row cursor read',
        'FRAMEWORK additionally compiles named binds, fingerprints SQL, manages cancellation and optional observation boundaries',
        'CPU, memory and event-loop observations belong to the whole client process, including warmup and benchmark overhead',
        'Sequential completion samples do not measure pool saturation, offered-rate behavior, server CPU or per-tenant resource attribution',
        'Network bytes, GC pauses, event-loop delay and exporter drops are unobserved',
        'One short run on a shared virtualized setup is exploratory; STANDARD/DETAILED modes, dedicated repetitions and soak gates remain separate',
      ],
    }),
  );
} catch (error) {
  console.error(
    JSON.stringify(
      error instanceof KitError
        ? error.toSafeJSON()
        : { code: 'EK_INTERNAL', message: 'PostgreSQL benchmark failed' },
    ),
  );
  process.exitCode = 1;
} finally {
  delete process.env[variable];
  try {
    await app?.stop();
  } finally {
    await native.end();
  }
}
