// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { assertRawLatencySamples } from './raw-latency.mjs';

assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
assert.ok(process.env.ARKENIVA_POSTGRES_URL, 'An owned verified PostgreSQL fixture is required');

test(
  'The actual disposable PostgreSQL legacy CLI retains measured samples without exporting fixture credentials',
  { timeout: 120000 },
  async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [fileURLToPath(new URL('../postgres.mjs', import.meta.url))],
      {
        cwd: fileURLToPath(new URL('../../../', import.meta.url)),
        timeout: 90000,
        maxBuffer: 8 * 1024 ** 2,
      },
    );
    const report = JSON.parse(stdout);
    assert.equal(report.scenarioId, 'postgres-select-one-local-exploration');
    assert.equal(report.measured, true);
    assert.equal(report.releaseGate, false);
    assert.equal(report.nodeVersion, process.version);
    assert.deepEqual(
      report.records.map((record) => record.mode),
      ['BASELINE', 'FRAMEWORK'],
    );
    for (const record of report.records) {
      assert.equal(record.sampleCount, 1000);
      assert.equal(record.totalInvocations, 1100);
      assert.equal(record.errors, 0);
      assert.equal(record.timeouts, 0);
      assertRawLatencySamples({
        ...record,
        latencyNanoseconds: Object.fromEntries(
          Object.entries(record.latencyMs).map(([name, value]) => [name, value * 1e6]),
        ),
      });
    }
    const endpoint = new URL(process.env.ARKENIVA_POSTGRES_URL);
    assert.equal(stdout.includes(process.env.ARKENIVA_POSTGRES_URL), false);
    assert.equal(stdout.includes(decodeURIComponent(endpoint.password)), false);
  },
);
