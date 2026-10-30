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
import { compressionFixture, payload } from '../compression-workload.mjs';

test(
  'Explicit compression smoke retains actual byte streams and separate bounded real pressure observations',
  { timeout: 145000, skip: process.env.ARKENIVA_COMPRESSION_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-compression-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../compression.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      for (const token of Object.values(compressionFixture))
        assert.equal(encoded.includes(token), false);
      for (const row of report.records) {
        assert.equal(row.verification.checkedZipEntries, 2);
        assert.equal(row.records.length, 2);
        assert.equal(row.completion.zipTimingSupported, false);
        for (const operation of ['gzip', 'gunzip']) {
          const item = row.records.find(
              (value) => value.operation === operation + '-validated-byte-stream',
            ),
            values = row.completion.streams[operation];
          assert.equal(item.sampleCount, 100);
          assert.equal(item.warmupIterations, 20);
          assert.equal(item.rawLatency.values.length, 100);
          assert.equal(values.actualCallbacks, 120);
          assert.equal(
            values.measurements.filter((value) => value.phase === 'measured').length,
            100,
          );
          for (const value of values.measurements) {
            assert.equal(value.uncompressedBytes, payload.length);
            assert.ok(value.compressedBytes > 0 && value.compressionRatio <= 100);
            assert.equal(value.sourceRetired, true);
            assert.ok(
              value.firstInputMs >= 0 && value.firstOutputByteMs >= 0 && value.streamElapsedMs > 0,
            );
            assert.ok(value.inputBytesPerSecond > 0 && value.outputBytesPerSecond > 0);
          }
        }
        assert.equal(row.completion.pressure.length, 2);
        for (const probe of row.completion.pressure) {
          assert.equal(probe.uncompressedBytes, 8388608);
          assert.ok(probe.compressedBytes > 0 && probe.compressedBytes <= 16777216);
          assert.ok(probe.compressionRatio <= 100);
          assert.equal(probe.producerPullsAtPlateau, probe.producerPullsAfterHold);
          assert.ok(probe.producerPullsAtPlateau < probe.producerPulls);
          assert.equal(probe.producerRetired, true);
          assert.equal(probe.producerFinishedDuringHold, false);
          assert.equal(probe.ownStreamsPhysicallyClosed, true);
          assert.equal(probe.opaqueInternalBufferBytes, null);
          if (probe.operation === 'gzip') assert.equal(probe.nativeValidationDecoderClosed, true);
          else assert.equal(probe.nativeFixtureRetired, true);
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
