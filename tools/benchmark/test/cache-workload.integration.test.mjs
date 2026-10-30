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

test(
  'Four real Redis cache profiles inspect native persisted state, actual expiry and private SDK exports',
  { timeout: 30000 },
  async () => {
    assert.equal(process.env.ARKENIVA_REDIS_DISPOSABLE, '1');
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-cache-harness-')),
      script = fileURLToPath(new URL('../cache.mjs', import.meta.url));
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
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-cache-private-value|cache-comparison:|127\.0\.0\.1/);
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualEnvelopeVerified: true,
            actualTtlVerified: true,
            expiredEntryAbsent: true,
            corruptEntryRejectedAndPreserved: true,
            deletionOutcomes: [true, false],
          });
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'roundtrip');
            assert.ok(operation.sampleCount >= 100);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
      assert.ok(process.env.ARKENIVA_REDIS_WRONG_SAN_URL);
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', join(directory, 'untrusted')], {
          env: { ...process.env, ARKENIVA_REDIS_URL: process.env.ARKENIVA_REDIS_WRONG_SAN_URL },
          timeout: 10000,
          maxBuffer: 1048576,
        }),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
