// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import { healthPlugin } from '@arkenivajs/health';
import { startHealthFixture } from '../health-fixture.mjs';
import { nativeHealth, healthSettings, verifyHealth } from '../health-workload.mjs';

test('Native and public readiness execute actual dependency failures without changing liveness', async () => {
  const authority = await startHealthFixture();
  const app = await createApplication({
    service: { name: 'health-comparison-test', version: '1.0.0', environment: 'test' },
    plugins: [healthPlugin(healthSettings(authority.fixture))],
  });
  const native = nativeHealth(authority.fixture);
  try {
    await app.start();
    for (const service of [native, app.resolve(COMPONENTS.health)])
      assert.equal((await verifyHealth(service, authority.fixture)).livenessIndependent, true);
    assert.equal(authority.state.ready, true);
    assert.equal(authority.state.failedProbes, 2);
    assert.equal(authority.state.changes, 4);
    assert.ok(authority.state.probes >= 18);
    for (const origin of [
      'http://example.invalid:1234',
      'https://127.0.0.1:1',
      'http://127.0.0.1:1/other',
      'http://user:password@127.0.0.1:1',
    ]) {
      assert.throws(() => nativeHealth({ ...authority.fixture, origin }));
      assert.throws(() => healthSettings({ ...authority.fixture, origin }));
    }
  } finally {
    native.close();
    await app.stop();
    await authority.close();
  }
});

test(
  'Four health profiles verify real HTTP probes, SDK privacy and bounded optional sampling',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-health-harness-'));
    const script = fileURLToPath(new URL('../health.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 25000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8');
        const report = JSON.parse(encoded);
        const protocol = JSON.parse(
          await readFile(join(output, 'protocol-observation.json'), 'utf8'),
        );
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.doesNotMatch(encoded, /owned-health-probe-value|http:\/\/127\.0\.0\.1/);
        assert.equal(protocol.failedProbeRequests, 4);
        assert.equal(protocol.readinessChanges, 8);
        assert.equal(protocol.dependencyRestored, true);
        assert.ok(protocol.completedProbeRequests >= (mode === '--smoke' ? 516 : 36));
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            readySnapshots: 8,
            failedSnapshots: 1,
            nativeProbeObserved: true,
            livenessIndependent: true,
          });
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'ready');
            assert.ok(operation.sampleCount >= 100);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
