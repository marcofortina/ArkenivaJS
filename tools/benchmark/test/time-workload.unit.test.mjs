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
import { createTimeService } from '@arkenivajs/data-time';
import {
  nativeTime,
  timeFixture,
  timeSettings,
  verifyTime,
  timeWorkload,
} from '../time-workload.mjs';

test('Native Temporal and public time preserve nanoseconds and elapsed DST transitions without global zone changes', () => {
  const zone = process.env.TZ,
    native = nativeTime(),
    framework = createTimeService(timeSettings);
  for (const service of [native, framework]) assert.equal(verifyTime(service).checkedCases, 8);
  const a = timeWorkload(native),
    b = timeWorkload(framework);
  for (const operation of Object.keys(a)) assert.deepEqual(a[operation](), b[operation]());
  assert.equal(process.env.TZ, zone);
});

test(
  'Four time profiles verify the same valid corpus and keep inputs out of telemetry and reports',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-time-harness-')),
      script = fileURLToPath(new URL('../time.mjs', import.meta.url));
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
        assert.deepEqual(report.records.map((row) => row.mode).sort(), [
          'BASELINE',
          'DETAILED',
          'FRAMEWORK',
          'STANDARD',
        ]);
        for (const value of Object.values(timeFixture))
          assert.equal(encoded.includes(value), false);
        assert.equal(report.collector.inputOccurrences, 0);
        for (const row of report.records) {
          assert.equal(row.verification.checkedCases, 8);
          assert.equal(row.verification.elapsedDstTransitionsVerified, 2);
          assert.equal(row.verification.processZoneUnchanged, true);
          assert.equal(row.records.length, mode === '--smoke' ? 4 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          for (const operation of row.records) {
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
