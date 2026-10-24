import assert from 'node:assert/strict';
import { cpus } from 'node:os';
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Bench } from 'tinybench';
import { compileSql } from '@arkenivajs/database';

const startedAt = new Date().toISOString();
const records = [];
const scenarios = [
  ['postgres', "SELECT :id::bigint, ':hidden', $$:body$$, :id /* :comment */"],
  ['mysql', "SELECT :id, ':hidden', `:column`, :id /* :comment */"],
  ['mariadb', "SELECT :id, ':hidden', `:column`, :id # :comment\n"],
  ['oracle', "SELECT :id, ':hidden', q'[:body]', :id /* :comment */ FROM dual"],
];
for (const [dialect, text] of scenarios) {
  const input = Object.freeze({ text, bindings: Object.freeze({ id: 9007199254740993n }) });
  const expected = compileSql(input, dialect);
  assert.deepEqual(expected.names, ['id', 'id']);
  let invocations = 0,
    consumed = 0;
  const bench = new Bench({
    time: 0,
    iterations: 10_000,
    warmupTime: 0,
    warmupIterations: 1000,
    retainSamples: true,
    throws: true,
  });
  bench.add(
    'named-bind-compile',
    () => {
      const result = compileSql(input, dialect);
      consumed += result.text.length;
      invocations++;
    },
    { async: false },
  );
  // Native event-loop counters become meaningful only after an actual loop iteration.
  await nextTurn();
  const cpuBefore = process.cpuUsage(),
    rssBefore = process.memoryUsage().rss,
    loopBefore = performance.eventLoopUtilization();
  await bench.run();
  await nextTurn();
  const loop = performance.eventLoopUtilization(loopBefore);
  const cpu = process.cpuUsage(cpuBefore);
  const result = bench.tasks[0].result;
  assert.equal(result.state, 'completed');
  assert.equal(result.latency.samplesCount, 10_000);
  assert.equal(invocations, 11_000);
  assert.equal(consumed, expected.text.length * invocations);
  const samples = [...result.latency.samples].sort((left, right) => left - right);
  const rank = (samples.length - 1) * 0.95;
  records.push({
    dialect,
    measured: true,
    statementBytes: Buffer.byteLength(text),
    bindOccurrences: expected.names.length,
    sampleCount: result.latency.samplesCount,
    totalCompilerInvocations: invocations,
    latencyMs: {
      mean: result.latency.mean,
      p50: result.latency.p50,
      p95:
        samples[Math.floor(rank)] +
        (samples[Math.ceil(rank)] - samples[Math.floor(rank)]) * (rank - Math.floor(rank)),
      p99: result.latency.p99,
    },
    throughputOpsPerSecond: result.throughput.mean,
    cpuDeltaMicros: cpu,
    rssBytes: { before: rssBefore, after: process.memoryUsage().rss },
    eventLoop:
      loop.active + loop.idle > 0
        ? { utilization: loop.utilization, activeMs: loop.active, idleMs: loop.idle }
        : null,
    eventLoopDelayMs: null,
    gcPauseMs: null,
  });
}
console.log(
  JSON.stringify({
    scenarioId: 'sql-compiler-local-exploration',
    measured: true,
    releaseGate: false,
    gitSha: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    workingTreeDirty:
      execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0,
    nodeVersion: process.version,
    startedAt,
    cpuModel: cpus()[0]?.model ?? null,
    runIterationCount: 1,
    warmupIterations: 1000,
    records,
    coverage: [
      'Observed synchronous compilation, captured bigint binding and SHA-256 statement fingerprint',
      'No server, pool wait, query execution or transaction latency is measured',
      'CPU and event-loop deltas include whole-process warmup, benchmark overhead and loop-boundary yields',
      'RSS records interval endpoints; event-loop delay and GC pauses are unobserved',
      'Shared laptop, short run and one repetition do not establish a release budget',
    ],
  }),
);
