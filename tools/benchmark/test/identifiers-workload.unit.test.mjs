// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createIdentifiersService } from '@arkenivajs/data-identifiers';
import {
  nativeIdentifiers,
  identifierWorkload,
  verifyIdentifiers,
} from '../identifiers-workload.mjs';

const fixture = {
  v4: 'a47ac10b-58cc-4372-a567-0e02b2c3d479',
  v7: '01900000-0000-7000-8000-000000000001',
};
test('Native and public identifier workloads preserve canonical parsing, version policy and real CSPRNG generation', () => {
  const native = nativeIdentifiers(),
    framework = createIdentifiersService({ allowVersions: [4, 7] });
  for (const service of [native, framework])
    assert.equal(verifyIdentifiers(service, fixture).checkedFreshIdentifiers, 200);
  const a = identifierWorkload(native, fixture),
    b = identifierWorkload(framework, fixture);
  for (const name of ['parseV4', 'parseV7', 'validateV4', 'validateV7', 'rejectNoncanonical'])
    assert.deepEqual(a[name](), b[name]());
});

test(
  'Four isolated identifier profiles distinguish functional verification from exploratory sampling without reporting fixture values',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-identifiers-harness-')),
      output = join(directory, 'verification'),
      script = fileURLToPath(new URL('../identifiers.mjs', import.meta.url));
    try {
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const report = JSON.parse(await readFile(join(output, 'report.json'), 'utf8'));
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.deepEqual(report.records.map((row) => row.mode).sort(), [
        'BASELINE',
        'DETAILED',
        'FRAMEWORK',
        'STANDARD',
      ]);
      for (const row of report.records) {
        assert.equal(row.verification.checkedFreshIdentifiers, 200);
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
      }
      assert.equal(report.collector.identifierOccurrences, 0);
      const measured = join(directory, 'exploratory');
      await promisify(execFile)(process.execPath, [script, '--smoke', measured], {
        timeout: 20000,
        maxBuffer: 1048576,
      });
      const sample = JSON.parse(await readFile(join(measured, 'report.json'), 'utf8'));
      assert.equal(sample.measured, true);
      assert.equal(sample.releaseGate, false);
      for (const row of sample.records) {
        assert.equal(row.records.length, 7);
        assert.ok(row.resource.memoryBytes.peakRss > 0);
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        for (const operation of row.records) {
          assert.ok(operation.sampleCount >= 10000);
          for (const value of Object.values(operation.latencyNanoseconds))
            assert.ok(Number.isFinite(value) && value >= 0);
        }
      }
      await assert.rejects(promisify(execFile)(process.execPath, [script, '--verify', output]));
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', 'relative-output']),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
