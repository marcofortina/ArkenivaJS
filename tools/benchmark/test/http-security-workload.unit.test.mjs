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
import {
  nativeHeaders,
  verifyHeaders,
  headerExchange,
  headerSettings,
} from '../http-security-workload.mjs';

test('Native Helmet hardens actual success and error replies; header-only providers cannot authorize CSRF', async () => {
  const fixture = { marker: 'owned-header-test-value' },
    native = await nativeHeaders(fixture),
    authority = headerSettings();
  try {
    assert.equal((await verifyHeaders(native, fixture)).successAndErrorHeaders, true);
    await assert.rejects(authority.settings.authority.require());
    for (const method of Object.values(authority.settings.csrfStore.store))
      await assert.rejects(method());
    const hmac = authority.settings.csrfHmac,
      digest = await hmac.digest('owned-comparison', ['value']);
    assert.equal(await hmac.verify('owned-comparison', ['value'], digest), true);
    assert.equal(await hmac.verify('different-domain', ['value'], digest), false);
    assert.throws(() => headerExchange({ address: () => 'http://example.invalid:1' }, '/headers'));
    assert.throws(() => headerExchange(native, '/other'));
  } finally {
    await native.close();
    authority.close();
  }
});

test(
  'Four isolated header profiles preserve hardening and SDK privacy with optional bounded sampling',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-header-harness-')),
      script = fileURLToPath(new URL('../http-security.mjs', import.meta.url));
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
        assert.equal(report.collector.inputOccurrences, 0);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.doesNotMatch(encoded, /owned-header-response-value/);
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualResponses: 3,
            successAndErrorHeaders: true,
            csrfMeasured: false,
          });
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'headers');
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
