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
import { csvFixture } from '../csv-workload.mjs';

test(
  'Explicit CSV smoke retains stream-boundary samples and separate large real-pressure observations',
  { timeout: 145000, skip: process.env.ARKENIVA_CSV_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-csv-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../csv.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(encoded.includes(csvFixture.marker), false);
      for (const row of report.records) {
        assert.equal(row.records.length, 2);
        for (const operation of ['parse', 'stringify']) {
          const record = row.records.find(
              (value) => value.operation === operation + '-stream-256-rows',
            ),
            streams = row.completion.streams[operation];
          assert.equal(record.sampleCount, 100);
          assert.equal(record.warmupIterations, 20);
          assert.equal(record.rawLatency.values.length, 100);
          assert.equal(streams.actualCallbacks, 120);
          assert.equal(streams.measurements.length, 120);
          assert.equal(
            streams.measurements.filter((value) => value.phase === 'measured').length,
            100,
          );
          for (const value of streams.measurements) {
            assert.equal(value.rows, 256);
            assert.equal(value.sourceRetired, true);
            assert.ok(value.firstInputMs >= 0 && value.elapsedMs > 0);
            assert.ok(
              (operation === 'parse' ? value.firstOutputRowMs : value.firstOutputByteMs) >= 0,
            );
            assert.ok(value.rowsPerSecond > 0 && value.encodedBytesPerSecond > 0);
          }
        }
        assert.equal(row.completion.pressure.length, 2);
        for (const probe of row.completion.pressure) {
          assert.equal(probe.encodedCorpusBytes, 8388608);
          assert.equal(probe.corpusRows, 8192);
          assert.equal(probe.completedEncodedBytes, 8388608);
          assert.equal(probe.completedRows, 8192);
          assert.equal(probe.producerPullsAtPlateau, probe.producerPullsAfterHold);
          assert.ok(probe.producerPullsAtPlateau < probe.producerPulls);
          assert.equal(probe.producerFinishedDuringHold, false);
          assert.equal(probe.producerRetired, true);
          assert.equal(probe.ownStreamsPhysicallyClosed, true);
          assert.equal(probe.opaqueInternalBufferBytes, null);
          assert.ok(probe.firstInputMs >= 0 && probe.firstOutputMs >= 0);
        }
        assert.equal(row.completion.postProbeHealthy, true);
        assert.equal(row.processTreeResource.allChildrenWaited, true);
        assert.equal(row.processTreeResource.remainingOwnedProcesses, 0);
        assert.equal(row.processTreeResource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
