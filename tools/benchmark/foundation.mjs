// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { cpus, totalmem, platform, release, arch } from 'node:os';
import { Writable } from 'node:stream';
import { Bench } from 'tinybench';
import { pino } from 'pino';
import { createApplication, KitError } from '@arkenivajs/core';
import { createConfig } from '@arkenivajs/config';
import { createLogger } from '@arkenivajs/logging';
import { createDiagnostics } from '@arkenivajs/diagnostics';

const service = { name: 'foundation-benchmark', version: '1.0.0', environment: 'test' };
const schema = {
  type: 'object',
  properties: { count: { type: 'integer' } },
  required: ['count'],
  additionalProperties: false,
};
const startedAt = new Date().toISOString();
const optionalFile = (path) => {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch {
    return null;
  }
};
let bytes = 0;
const destination = new Writable({
  write(chunk, _encoding, callback) {
    bytes += Buffer.byteLength(chunk);
    callback();
  },
});
const fields = { operation: 'benchmark', credentials: { password: 'fake-benchmark-password' } };
const native = pino(
  {
    base: {
      service: service.name,
      serviceVersion: service.version,
      environment: service.environment,
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: { paths: ['credentials.password'], censor: '[REDACTED]' },
  },
  destination,
);
const logger = createLogger({ service, destination });
const diagnostics = createDiagnostics();
const config = await createConfig({
  workspace: process.cwd(),
  schema,
  defaults: { count: 1 },
  environment: {},
});
const records = [];
const capabilityKey = Symbol('foundation-benchmark.capability');
const capabilityValue = Object.freeze({ value: 1 });
const nativeCapabilities = new Map([[capabilityKey, capabilityValue]]);
const capabilityApp = await createApplication({
  service,
  plugins: [
    {
      id: 'benchmark-capability',
      version: '1.0.0',
      capabilities: new Set(['benchmark-capability']),
      init(context) {
        context.provide(capabilityKey, capabilityValue);
      },
      close() {},
    },
  ],
});
await capabilityApp.start();
assert.equal(capabilityApp.resolve(capabilityKey), nativeCapabilities.get(capabilityKey));
const scenarios = [
  ['native-capability-map-read', 'BASELINE', 10000, () => nativeCapabilities.get(capabilityKey)],
  [
    'application-capability-resolve',
    'FRAMEWORK',
    10000,
    () => capabilityApp.resolve(capabilityKey),
  ],
  [
    'application-capability-try-resolve',
    'FRAMEWORK',
    10000,
    () => capabilityApp.tryResolve(capabilityKey),
  ],
  ['native-error', 'BASELINE', 1000, () => new Error('Benchmark error')],
  [
    'typed-safe-error',
    'FRAMEWORK',
    1000,
    () => new KitError({ code: 'EK_INTERNAL', message: 'Benchmark error' }).toSafeJSON(),
  ],
  ['configuration-read', 'FRAMEWORK', 1000, () => config.require('count')],
  [
    'configuration-load',
    'FRAMEWORK',
    100,
    () => createConfig({ workspace: process.cwd(), schema, yamlText: 'count: 1', environment: {} }),
  ],
  [
    'application-lifecycle',
    'FRAMEWORK',
    100,
    async () => {
      const app = await createApplication({ service });
      try {
        await app.start();
      } finally {
        await app.stop();
      }
    },
  ],
  ['native-pino', 'BASELINE', 1000, () => native.info(fields, 'Benchmark operation')],
  ['framework-pino', 'FRAMEWORK', 1000, () => logger.info('Benchmark operation', fields)],
  [
    'native-process-counters',
    'BASELINE',
    1000,
    () => ({ cpu: process.cpuUsage(), memory: process.memoryUsage() }),
  ],
  ['framework-process-snapshot', 'FRAMEWORK', 1000, () => diagnostics.snapshot()],
];

try {
  for (const [scenarioId, mode, samples, work] of scenarios) {
    let observed;
    const bench = new Bench({
      time: 0,
      iterations: samples,
      warmupTime: 0,
      warmupIterations: 100,
      retainSamples: true,
      throws: true,
    });
    bench.add(scenarioId, () => (observed = work()));
    const cpuBefore = process.cpuUsage();
    const rssBefore = process.memoryUsage().rss;
    await bench.run();
    const cpuDelta = process.cpuUsage(cpuBefore);
    const result = bench.tasks[0].result;
    assert.equal(result.state, 'completed');
    const values = result.latency.samples;
    assert.ok(values && values.length >= samples);
    const rank = (values.length - 1) * 0.95;
    const lower = Math.floor(rank);
    const p95 = values[lower] + (values[Math.ceil(rank)] - values[lower]) * (rank - lower);
    records.push({
      scenarioId,
      mode,
      sampleCount: result.latency.samplesCount,
      runIterationCount: 1,
      warmupIterations: 100,
      latencyMs: {
        p50: result.latency.p50,
        p95,
        p99: result.latency.p99,
        max: result.latency.max,
        mean: result.latency.mean,
      },
      throughputOpsPerSecond: result.throughput.mean,
      errors: 0,
      errorRate: 0,
      cpuDeltaMicros: cpuDelta,
      rssBytes: { before: rssBefore, after: process.memoryUsage().rss },
      queueDropCount: scenarioId === 'framework-pino' ? logger.stats().dropped : null,
      lastResultType: typeof observed,
    });
  }
  await logger.flush();
  assert.equal(logger.stats().dropped, 0);
  assert.equal(logger.stats().failedWrites, 0);
  assert.ok(bytes > 0);
} finally {
  await capabilityApp.stop();
  diagnostics.close();
  await logger.close();
  destination.destroy();
}

console.log(
  JSON.stringify(
    {
      scenarioId: 'foundation-local-exploration',
      gitSha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
      workingTreeDirty:
        execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0,
      nodeVersion: process.version,
      startedAt,
      measured: true,
      releaseGate: false,
      hardware: {
        cpuModel: cpus()[0]?.model ?? null,
        logicalCpus: cpus().length,
        memoryBytes: totalmem(),
        platform: platform(),
        kernel: release(),
        architecture: arch(),
        cpuAffinity:
          optionalFile('/proc/self/status')?.match(/^Cpus_allowed_list:\s*(.+)$/m)?.[1] ?? null,
        governor: optionalFile('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'),
        containerCpuLimit: optionalFile('/sys/fs/cgroup/cpu.max'),
        containerMemoryLimit: optionalFile('/sys/fs/cgroup/memory.max'),
      },
      testEnvironmentVersions: { tinybench: '6.2.2', pino: '10.4.0', framework: '0.1.0' },
      loadProfile: {
        concurrency: 1,
        offeredRate: null,
        runnerType: 'local-shared',
        fixedIterations: true,
      },
      measurementCoverage: {
        latency: 'individual local operations including timer overhead',
        cpuAndRss: 'whole process across warmup and measurement; RSS at interval boundaries',
        transport: 'synchronously acknowledged in-memory writable; no disk or network',
        comparisons:
          'different contract work; exploratory component costs, not equivalent end-to-end workloads',
        unavailable: [
          'request-load',
          'standard-telemetry',
          'detailed-profiling',
          'meter-drops',
          'network-bytes',
          'dedicated-runner-confidence',
        ],
      },
      records,
    },
    null,
    2,
  ),
);
