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
import { createApplication } from '@arkenivajs/core';
import { nativeCore, frameworkCore, verifyCore } from '../core-workload.mjs';

test('Public core lookup preserves identity only in its actual active lifecycle', async () => {
  const fixture = { marker: 'owned-core-test-value' },
    definition = frameworkCore(fixture);
  const app = await createApplication({
    service: { name: 'core-comparison-test', version: '1.0.0', environment: 'test' },
    plugins: [definition.plugin],
  });
  definition.configure(app);
  const native = nativeCore(fixture);
  try {
    await app.start();
    for (const service of [native, app.resolve(definition.key)])
      assert.equal(verifyCore(service, fixture).identityPreserved, true);
  } finally {
    native.close();
    await app.stop();
    definition.dispose();
  }
});

test(
  'Four core profiles verify real lookup batches without fabricated SDK instruments',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-core-harness-')),
      script = fileURLToPath(new URL('../core.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 25000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(report.collector.receivedBodies, 0);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.equal(report.inputs.lookupsPerBatch, 256);
        assert.doesNotMatch(encoded, /owned-core-private-capability-value/);
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            lookupPairsVerified: 128,
            identityPreserved: true,
            immutableValue: true,
            optionalMissing: true,
            requiredMissingRejected: true,
          });
          assert.equal(row.records.length, mode === '--smoke' ? 2 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) {
            assert.equal(row.quality.instruments, 0);
            assert.equal(row.quality.metricSeries, 0);
            assert.equal(row.quality.spansStarted, 0);
          }
          for (const operation of row.records) {
            assert.ok(['resolve-256', 'try-resolve-256'].includes(operation.operation));
            assert.ok(operation.sampleCount >= 1000);
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
