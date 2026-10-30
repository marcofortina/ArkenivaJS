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
import { pdfFixture } from '../pdf-workload.mjs';
import { pdfInspectDescriptor, pdfInspectExpected, pdfInspectBase64 } from '../pdf-fixture.mjs';
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Disposable supervised PDF inspection retains real metadata outcomes with independent document verification and child cleanup',
  { timeout: 420000, skip: process.env.ARKENIVA_PDF_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-pdf-inspect-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../pdf.mjs', import.meta.url)), '--smoke', output],
        { timeout: 410000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.deepEqual(report.inputs.fixedInspectInput, pdfInspectDescriptor);
      assert.equal(report.inputs.supervisedProfileTimeoutMs, 90000);
      for (const value of [
        ...Object.values(pdfFixture),
        pdfInspectExpected.author,
        'owned-pdf-fixture',
        pdfInspectBase64,
      ])
        assert.equal(encoded.includes(value), false);
      let samples = 0,
        inspections = 0;
      for (const row of report.records) {
        assert.equal(row.verification.operationsVerified, 5);
        assert.equal(row.verification.mergedPages, 3);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          completion = row.completion;
        assert.equal(record.operation, 'inspect-fixed-one-page-pdf');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assertRawLatencySamples(record);
        assert.equal(
          completion.actualInspectOperations,
          record.sampleCount + record.warmupIterations,
        );
        assert.equal(completion.checkedInspectionReports, completion.actualInspectOperations);
        assert.equal(completion.inspectedPages, completion.actualInspectOperations);
        assert.equal(
          completion.consumedInputBytes,
          completion.actualInspectOperations * pdfInspectDescriptor.bytes,
        );
        assert.equal(completion.inputSha256, pdfInspectDescriptor.sha256);
        assert.equal(completion.inputUnchanged, true);
        assert.equal(completion.independentPdfLibPages, 1);
        assert.equal(completion.independentPdfJsPages, 1);
        assert.equal(completion.independentTextVerified, true);
        assert.equal(completion.retainedReportsAfterCompletion, 0);
        assert.ok(completion.reportBytes > 0 && completion.reportBytes <= 262144);
        assert.match(completion.reportSha256, /^[a-f0-9]{64}$/);
        const tree = row.processTreeResource;
        assert.equal(tree.scope, 'whole-supervised-lifecycle');
        assert.equal(tree.allChildrenWaited, true);
        assert.equal(tree.remainingOwnedProcesses, 0);
        assert.equal(tree.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(tree.rssReadQuality.inaccessibleReads, 0);
        assert.equal(tree.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(tree.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.ok(tree.observedProcessCount >= (row.mode === 'BASELINE' ? 2 : 3));
        assert.ok(tree.userCpuSeconds + tree.systemCpuSeconds > 0);
        assert.ok(tree.sampledSummedRssPeakBytes > 0);
        assert.equal(tree.pythonObserverIncluded, false);
        assert.equal(tree.externalServerResourcesIncluded, false);
        for (const pid of tree.observedPids) await assert.rejects(access('/proc/' + pid));
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        samples += record.sampleCount;
        inspections += completion.actualInspectOperations;
      }
      assert.equal(samples, 400);
      assert.equal(inspections, 480);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
