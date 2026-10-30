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
import { createConfig } from '@arkenivajs/config';
import { assertRawLatencySamples } from './raw-latency.mjs';
import { nativeConfig, configOptions, configFixture, verifyConfig } from '../config-workload.mjs';

test('Native flat configuration and public configuration preserve precedence and failed-reload atomicity', async () => {
  const before = process.env.ARKENIVAJS_BENCH_COUNT;
  for (const service of [nativeConfig(), await createConfig(configOptions())])
    assert.equal((await verifyConfig(service)).failedReloadPreservedState, true);
  assert.equal(process.env.ARKENIVAJS_BENCH_COUNT, before);
});

test(
  'Configuration profiles isolate mutable reload state and keep data values out of reports',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-config-harness-')),
      script = fileURLToPath(new URL('../config.mjs', import.meta.url));
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
        assert.equal(encoded.includes(configFixture.marker), false);
        assert.equal(report.collector.inputOccurrences, 0);
        for (const row of report.records) {
          assert.equal(row.verification.checkedCases, 8);
          assert.equal(row.verification.precedenceVerified, true);
          assert.equal(row.verification.failedReloadPreservedState, true);
          assert.equal(row.verification.priorSnapshotImmutable, true);
          assert.equal(row.records.length, mode === '--smoke' ? 5 : 0);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (mode === '--verify') assert.equal(row.resource, null);
          for (const operation of row.records) {
            assert.ok(operation.sampleCount >= 1000);
            assertRawLatencySamples(operation);
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
