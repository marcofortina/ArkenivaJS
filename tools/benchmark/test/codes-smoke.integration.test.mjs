// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { codesFixture, codesOperations } from '../codes-workload.mjs';
import { codesPngBase64, codesPngDescriptor } from '../codes-fixture.mjs';
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Disposable supervised barcode smoke measures real codecs with independent exact output and descendant cleanup',
  { timeout: 135000, skip: process.env.ARKENIVA_CODES_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-codes-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../codes.mjs', import.meta.url)), '--smoke', output],
        { timeout: 130000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.match(report.processTreeResourceCoverage, /whole-supervised-lifecycle/);
      for (const value of [...Object.values(codesFixture), codesPngBase64])
        assert.equal(encoded.includes(value), false);
      let measured = 0,
        callbacks = 0;
      const baseline = report.records.find((row) => row.mode === 'BASELINE');
      for (const row of report.records) {
        assert.equal(row.verification.checkedPngRoundtrips, 3);
        assert.equal(row.verification.checkedSvgOutputs, 1);
        assert.equal(row.verification.actualNativeDecoding, true);
        assert.equal(row.completion.independentlyVerified, true);
        assert.equal(row.completion.fixedDecodeInputUnchanged, true);
        assert.equal(row.completion.retainedOutputsAfterCompletion, 0);
        assert.ok(
          row.completion.retainedOutputBytes > 0 && row.completion.retainedOutputBytes <= 8388608,
        );
        assert.deepEqual(
          row.records.map((record) => record.operation),
          codesOperations,
        );
        assert.equal(row.completion.summaries.length, 4);
        for (const [index, record] of row.records.entries()) {
          assert.equal(record.sampleCount, 100);
          assert.equal(record.warmupIterations, 20);
          assertRawLatencySamples(record);
          const summary = row.completion.summaries[index];
          assert.equal(summary.operation, record.operation);
          assert.equal(summary.actualCallbacks, record.sampleCount + record.warmupIterations);
          assert.ok(Number.isSafeInteger(summary.pixels) && summary.pixels > 0);
          if (index < 3) {
            assert.ok(summary.bytes > 0 && summary.bytes <= 120 * 65536);
            assert.match(summary.sha256, /^[a-f0-9]{64}$/);
            assert.equal(summary.pixels, summary.actualCallbacks * summary.width * summary.height);
            assert.equal(summary.width, baseline.completion.summaries[index].width);
            assert.equal(summary.height, baseline.completion.summaries[index].height);
          } else {
            assert.equal(summary.inputBytes, summary.actualCallbacks * codesPngDescriptor.bytes);
            assert.equal(summary.inputSha256, codesPngDescriptor.sha256);
            assert.equal(summary.pixels, summary.actualCallbacks * 256 * 256);
          }
          measured += record.sampleCount;
          callbacks += summary.actualCallbacks;
        }
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
        assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.ok(resource.userCpuSeconds + resource.systemCpuSeconds > 0);
        assert.ok(resource.sampledSummedRssPeakBytes > 0);
        assert.ok(resource.largestSingleProcessRssBytes > 0);
        assert.ok(resource.observedProcessCount >= (row.mode === 'BASELINE' ? 2 : 3));
        assert.ok(row.resource.elapsedMs > 0);
        for (const pid of resource.observedPids) await assert.rejects(access('/proc/' + pid));
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.equal(measured, 1600);
      assert.equal(callbacks, 1920);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
