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
import { nativeSqlQuery, verifySqlQuery } from '../sql-query-workload.mjs';

test(
  'Native SQL comparison verifies the healthy fixture before rejecting its wrong-SAN peer',
  { timeout: 15000 },
  async () => {
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_POSTGRES_WRONG_SAN_URL);
    const fixture = {
      url: process.env.ARKENIVA_POSTGRES_URL,
      marker: 'owned-native-sql-test-value',
      exact: '9007199254740993',
    };
    const healthy = await nativeSqlQuery(fixture);
    try {
      await verifySqlQuery(healthy, fixture);
    } finally {
      await healthy.close();
    }
    await assert.rejects(
      nativeSqlQuery({ ...fixture, url: process.env.ARKENIVA_POSTGRES_WRONG_SAN_URL }),
    );
  },
);

test(
  'Four SQL profiles verify actual bound rows, precision, sampled queries and released pool checkouts',
  { timeout: 45000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sql-query-harness-'));
    const script = fileURLToPath(new URL('../sql-query.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 30000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8');
        const report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-sql-private-value|9007199254740993|127\.0\.0\.1/);
        for (const row of report.records) {
          assert.ok([17, 18].includes(row.verification.serverMajor));
          assert.equal(row.verification.actualBoundRowVerified, true);
          assert.equal(row.verification.repeatedBindVerified, true);
          assert.equal(row.verification.exactBigintTextVerified, true);
          assert.equal(row.completion.nativePoolDrained, true);
          assert.ok(row.completion.poolConnections >= 1 && row.completion.poolConnections <= 2);
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'queryOne');
            assert.ok(operation.sampleCount >= 100);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', join(directory, 'untrusted')], {
          env: {
            ...process.env,
            ARKENIVA_POSTGRES_URL: process.env.ARKENIVA_POSTGRES_WRONG_SAN_URL,
          },
          timeout: 15000,
          maxBuffer: 1048576,
        }),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
