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
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Four supervised JSON profiles measure actual operations and verify every bounded result',
  {
    timeout: 150000,
  },
  async () => {
    assert.equal(process.env.ARKENIVA_BENCHMARK_DISPOSABLE, '1');
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-json-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../json.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /owned-json-private-value/);
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.deepEqual(row.completion, {
          sampledOperations: 400,
          warmupOperations: 80,
          checkedResults: 480,
          inputUnchanged: true,
          exactProjectionVerified: true,
          boundedRetainedResults: true,
        });
        assert.deepEqual(
          row.records.map((record) => record.operation),
          ['parse', 'stringify', 'validate', 'transform'],
        );
        for (const record of row.records) {
          assert.equal(record.sampleCount, 100);
          assert.equal(record.warmupIterations, 20);
          assertRawLatencySamples(record);
          assert.ok(record.throughputOpsPerSecond > 0);
        }
        assert.ok(row.resource.elapsedMs > 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.ok(resource.samplingRounds > 0);
        for (const key of ['userCpuSeconds', 'systemCpuSeconds', 'sampledSummedRssPeakBytes'])
          assert.ok(Number.isFinite(resource[key]) && resource[key] >= 0);
        if (row.quality)
          for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
            assert.equal(row.quality[key], 0);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
