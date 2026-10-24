import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { execFileSync } from 'node:child_process';
import { createDiagnostics, diagnosticsPlugin, DIAGNOSTIC_SOURCES } from '@arkenivajs/diagnostics';
import { createApplication, KitError } from '@arkenivajs/core';

const service = { name: 'diagnostic-test', version: '1.0.0', environment: 'test' } as const;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('Native CPU and memory snapshots retain units, provenance and actual process identity', () => {
  const collector = createDiagnostics({ eventLoopUtilization: false });
  const before = process.cpuUsage();
  const snapshot = collector.snapshot();
  const after = process.cpuUsage();
  assert.equal(snapshot.processId, process.pid);
  assert.ok(Number.isFinite(Date.parse(snapshot.timestamp)));
  assert.ok(snapshot.timestamp.endsWith('Z'));
  assert.ok(snapshot.cpuUserMicros >= before.user && snapshot.cpuUserMicros <= after.user);
  assert.ok(snapshot.cpuSystemMicros >= before.system && snapshot.cpuSystemMicros <= after.system);
  assert.ok(snapshot.memoryRssBytes > 0);
  assert.ok(snapshot.heapUsedBytes > 0);
  assert.ok(Object.isFrozen(snapshot));
  assert.equal(snapshot.eventLoopUtilization, undefined);
  assert.equal(snapshot.eventLoopDelayP99Ms, undefined);
  assert.equal(DIAGNOSTIC_SOURCES.cpuUserMicros.unit, 'microseconds');
  assert.equal(DIAGNOSTIC_SOURCES.memoryRssBytes.source, 'process.memoryUsage().rss');
  assert.equal(DIAGNOSTIC_SOURCES.eventLoopUtilization.scope, 'process');
  assert.ok(Object.isFrozen(DIAGNOSTIC_SOURCES));
  assert.ok(Object.isFrozen(DIAGNOSTIC_SOURCES.cpuUserMicros));
  collector.close();
  collector.close();
  assert.throws(() => collector.snapshot(), code('EK_RESOURCE_CLOSED'));
});

test('Enabled event-loop delay omits unsampled values and reports real sampled intervals', async () => {
  const collector = createDiagnostics({ eventLoopDelay: true, resolutionMs: 5 });
  assert.equal(collector.snapshot().eventLoopDelayP99Ms, undefined);
  await delay(30);
  const busyUntil = performance.now() + 12;
  while (performance.now() < busyUntil) {
    /* Deliberately create event-loop delay for a native measurement. */
  }
  await delay(10);
  const snapshot = collector.snapshot();
  assert.ok(snapshot.eventLoopDelayP99Ms !== undefined && snapshot.eventLoopDelayP99Ms >= 0);
  assert.ok(
    snapshot.eventLoopUtilization !== undefined &&
      snapshot.eventLoopUtilization >= 0 &&
      snapshot.eventLoopUtilization <= 1,
  );
  assert.equal(collector.snapshot().eventLoopDelayP99Ms, undefined);
  collector.close();
});

test('Invalid diagnostics options reject instead of enabling an unintended collector', () => {
  for (const options of [
    null,
    [],
    { eventLoopDelay: 'true' },
    { eventLoopUtilization: 1 },
    { resolutionMs: 0 },
    { resolutionMs: 0.5 },
    { unknown: true },
  ])
    assert.throws(() => createDiagnostics(options as never), code('EK_CONFIG_INVALID'));
});

test('Diagnostics plugin resources close and remain independent when a factory is reused', async () => {
  const plugin = diagnosticsPlugin({ eventLoopDelay: true, resolutionMs: 5 });
  const first = await createApplication({ service, plugins: [plugin] });
  const second = await createApplication({ service, plugins: [plugin] });
  await first.start();
  await second.start();
  const collector = first.diagnostics;
  await first.stop();
  assert.throws(() => collector.snapshot(), code('EK_RESOURCE_CLOSED'));
  assert.equal(second.diagnostics.snapshot().processId, process.pid);
  await second.stop();
});

test('Import and explicit collector shutdown do not keep an isolated Node process alive', () => {
  const entry = new URL('../../../dist/index.js', import.meta.url).href;
  const output = execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `const module = await import(${JSON.stringify(entry)}); const collector = module.createDiagnostics({eventLoopDelay:true}); collector.close(); console.log('closed');`,
    ],
    { encoding: 'utf8', timeout: 2000 },
  );
  assert.equal(output.trim(), 'closed');
});
