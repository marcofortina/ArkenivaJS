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
  'Sampled multipart profiles reconcile independently consumed streams with physical HTTP completion',
  { timeout: 145000, skip: process.env.ARKENIVA_UPLOAD_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-upload-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../upload.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-upload-content|owned-upload-field|owned\.bin|empty\.bin|127\.0\.0\.1/,
      );
      for (const row of report.records) {
        assert.equal(row.verification.completedRequests, 2);
        assert.equal(row.verification.emptyFileVerified, true);
        assert.equal(row.verification.fragmentedUtf8, true);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'streamedMultipart');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assertRawLatencySamples(record);
        assert.equal(value.sampledRequests, 100);
        assert.equal(value.warmupRequests, 20);
        assert.equal(value.checkedRequests, 120);
        assert.equal(value.independentlyConsumedFiles, 240);
        assert.equal(value.independentlyConsumedParts, 360);
        assert.equal(
          value.consumedFileBytes,
          Buffer.byteLength('owned-upload-content-π') * 4096 * 120,
        );
        assert.equal(value.consumedFieldBytes, Buffer.byteLength('owned-upload-field-€') * 120);
        assert.ok(value.emittedHttpBodyBytes > value.consumedFileBytes + value.consumedFieldBytes);
        assert.equal(
          value.frameworkObservedHttpBodyBytes,
          row.mode === 'BASELINE' ? null : value.emittedHttpBodyBytes,
        );
        assert.equal(value.opaqueParserAndKernelBufferBytes, null);
        assert.ok(value.observedDrainWaits > 0);
        assert.equal(value.measurements.length, 120);
        assert.equal(
          value.emittedHttpBodyBytes,
          value.measurements.reduce((sum, item) => sum + item.emittedBodyBytes, 0),
        );
        assert.equal(
          value.observedDrainWaits,
          value.measurements.reduce((sum, item) => sum + item.drainWaits, 0),
        );
        for (const item of value.measurements) {
          assert.equal(item.fileBytes, Buffer.byteLength('owned-upload-content-π') * 4096);
          assert.equal(item.digestsVerified, true);
          assert.equal(item.sourceRetired, true);
          assert.equal(item.connectionClosed, true);
          assert.equal(item.closedSinks, 2);
          assert.ok(item.firstFileByteMs >= 0);
          assert.ok(item.firstResponseByteMs >= item.firstFileByteMs);
          assert.ok(item.elapsedMs >= item.firstResponseByteMs);
          assert.ok(
            item.fileBytesPerSecond > 0 && item.httpBodyBytesPerSecond > item.fileBytesPerSecond,
          );
          assert.ok(item.drainWaits > 0 && item.drainWaitMs >= 0);
          assert.ok(item.sourcePeakQueuedBytes <= 24576);
          assert.ok(item.largestSourceChunkBytes <= 24576);
          assert.ok(item.sinkChunks > 0 && item.sinkPeakQueuedBytes > 0);
        }
        const resource = row.processTreeResource;
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality)
          for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
            assert.equal(row.quality[key], 0);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
