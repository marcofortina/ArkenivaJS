// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir, cpus } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { Bench } from 'tinybench';
import { createMeter, createJsonlExporter, parseMeteringEvent } from '@arkenivajs/metering';

const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-meter-benchmark-'));
const tenant = Object.freeze({
  tenantId: 'benchmark-tenant',
  identity: {
    subject: 'benchmark',
    issuer: 'https://issuer.invalid',
    audience: ['benchmark'],
    scopes: [],
    claims: {},
  },
  source: 'oidc',
  verifiedAt: new Date().toISOString(),
});
const service = { name: 'meter-benchmark', version: '1.0.0', environment: 'test' };
const auth = { isVerifiedTenant: (value) => value === tenant };
const usageDefinitions = { 'benchmark.operation': 'operations' };
const enabled = createMeter({
  service,
  auth,
  usageDefinitions,
  exporter: await createJsonlExporter({ workspace, path: 'events.jsonl' }),
  queueCapacity: 10_000,
});
const disabled = createMeter({ service, auth, usageDefinitions, enabled: false });
const records = [];
const startedAt = new Date().toISOString();
try {
  for (const [mode, meter] of [
    ['disabled', disabled],
    ['jsonl', enabled],
  ]) {
    const bench = new Bench({
      time: 0,
      iterations: 1000,
      warmupTime: 0,
      warmupIterations: 100,
      retainSamples: true,
      throws: true,
    });
    bench.add(
      'trusted-scope',
      () =>
        meter.measure({ tenant, operation: 'benchmark.lookup' }, () =>
          meter.current().recordOperation('benchmark.operation'),
        ),
      { async: true },
    );
    const cpuBefore = process.cpuUsage(),
      rssBefore = process.memoryUsage().rss;
    await bench.run();
    await meter.flush();
    const cpu = process.cpuUsage(cpuBefore);
    const result = bench.tasks[0].result;
    assert.equal(result.state, 'completed');
    assert.ok(result.latency.samplesCount >= 1000);
    assert.equal(result.latency.samples.length, result.latency.samplesCount);
    assert.ok(
      result.latency.samples.length <= 10000 &&
        result.latency.samples.every((value) => Number.isFinite(value) && value >= 0),
    );
    const samples = [...result.latency.samples].sort((left, right) => left - right);
    const rank = (samples.length - 1) * 0.95;
    const p95 =
      samples[Math.floor(rank)] +
      (samples[Math.ceil(rank)] - samples[Math.floor(rank)]) * (rank - Math.floor(rank));
    records.push({
      mode,
      measured: true,
      sampleCount: result.latency.samplesCount,
      rawLatency: { unit: 'milliseconds', values: [...result.latency.samples] },
      latencyMs: {
        mean: result.latency.mean,
        p50: result.latency.p50,
        p95,
        p99: result.latency.p99,
      },
      throughputOpsPerSecond: result.throughput.mean,
      cpuDeltaMicros: cpu,
      rssBytes: { before: rssBefore, after: process.memoryUsage().rss },
      stats: meter.stats(),
      snapshot: meter.snapshot(),
    });
  }
  assert.equal(enabled.stats().dropped, 0);
  assert.equal(enabled.stats().failedExports, 0);
  const lines = (await readFile(join(workspace, 'events.jsonl'), 'utf8'))
    .trim()
    .split('\n')
    .map((line) => parseMeteringEvent(JSON.parse(line)));
  assert.equal(lines.length, enabled.stats().exported);
  assert.ok(lines.length >= 1100);
} finally {
  await enabled.close();
  await disabled.close();
  await rm(workspace, { recursive: true, force: true });
}
console.log(
  JSON.stringify({
    scenarioId: 'metering-local-exploration',
    measured: true,
    releaseGate: false,
    gitSha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    workingTreeDirty:
      execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0,
    nodeVersion: process.version,
    startedAt,
    cpuModel: cpus()[0]?.model ?? null,
    runIterationCount: 1,
    warmupIterations: 100,
    records,
    coverage: [
      'Observed scope/enqueue latency; asynchronous file dispatch can overlap measurement',
      'CPU deltas are whole-process and include warmup and concurrent exporter work',
      'RSS is sampled at interval endpoints, not exact per-operation memory',
      'Default sampled tracing is not involved; JSONL readback proves independent delivery',
      'Shared laptop, short run and one repetition do not establish release overhead or long-soak budgets',
    ],
  }),
);
