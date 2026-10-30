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
import { nativeMysqlQuery, verifyMysqlQuery } from '../mysql-query-workload.mjs';

test(
  'Native MySQL comparison verifies the healthy fixture before rejecting its wrong-SAN peer',
  { timeout: 15000 },
  async () => {
    assert.equal(process.env.ARKENIVA_MYSQL_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_MYSQL_WRONG_SAN_URL);
    const fixture = {
      url: process.env.ARKENIVA_MYSQL_URL,
      marker: 'owned-native-mysql-test',
      exact: '9007199254740993',
    };
    const healthy = await nativeMysqlQuery(fixture);
    try {
      await verifyMysqlQuery(healthy, fixture);
    } finally {
      await healthy.close();
    }
    await assert.rejects(
      nativeMysqlQuery({ ...fixture, url: process.env.ARKENIVA_MYSQL_WRONG_SAN_URL }),
    );
  },
);

test(
  'Four MySQL profiles verify actual prepared queries, exact text bigint, bounded samples and drained ownership',
  { timeout: 45000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mysql-query-harness-'));
    const script = fileURLToPath(new URL('../mysql-query.mjs', import.meta.url));
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
        assert.doesNotMatch(encoded, /owned-mysql-private-value|9007199254740993|127\.0\.0\.1/);
        for (const row of report.records) {
          assert.match(row.verification.serverVersion, /^9\.7\.4/);
          assert.equal(row.verification.actualPreparedRowVerified, true);
          assert.equal(row.verification.repeatedBindVerified, true);
          assert.equal(row.verification.exactBigintTextVerified, true);
          assert.deepEqual(row.completion, {
            trackedCheckoutsDrained: true,
            pendingAcquisitionsDrained: true,
            nativePoolCountersAvailable: false,
          });
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
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
          env: { ...process.env, ARKENIVA_MYSQL_URL: process.env.ARKENIVA_MYSQL_WRONG_SAN_URL },
          timeout: 15000,
          maxBuffer: 1048576,
        }),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
