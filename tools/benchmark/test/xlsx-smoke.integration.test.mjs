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
import { xlsxFixtureSha256 } from '../xlsx-fixture.mjs';

test(
  'Measured XLSX profiles preserve fixed input and exact ordered cells with complete child accounting',
  { timeout: 380000, skip: process.env.ARKENIVA_XLSX_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xlsx-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../xlsx.mjs', import.meta.url)), '--smoke', output],
        { timeout: 370000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.profileTimeoutMs, 90000);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-xlsx-private-content|Owned comparison data|Owned comparison other/,
      );
      for (const row of report.records) {
        assert.equal(row.verification.nativeToPublicRead, true);
        assert.equal(row.verification.publicToNativeRead, true);
        assert.equal(row.verification.formulasUnexecuted, true);
        assert.equal(row.verification.styleAndDateVerified, true);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'readFiveRows');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.values.length, 100);
        assert.equal(value.sampledReads, 100);
        assert.equal(value.warmupReads, 20);
        assert.equal(value.checkedReads, 120);
        assert.equal(value.fixedInputSha256, xlsxFixtureSha256);
        assert.equal(value.inputUnchanged, true);
        assert.equal(value.opaqueNativeBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.checkedSheets, 2);
          assert.equal(measurement.checkedRows, 5);
          assert.equal(measurement.inputBytes, 7283);
          assert.equal(measurement.sourceTraversals, 1);
          assert.equal(measurement.sourceRetired, true);
          assert.equal(measurement.readerClosed, true);
          assert.ok(measurement.firstRowMs >= 0 && measurement.elapsedMs >= measurement.firstRowMs);
          assert.ok(measurement.rowsPerSecond > 0);
        }
        const resource = row.processTreeResource;
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
