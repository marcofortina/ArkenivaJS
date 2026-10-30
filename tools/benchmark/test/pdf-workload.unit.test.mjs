// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { documentsPdfPlugin, PDF_CAPABILITY } from '@arkenivajs/documents-pdf';
import { nativePdf, verifyPdf, pdfSettings, pdfInspectWorkload } from '../pdf-workload.mjs';
import { pdfInspectFixture, pdfInspectDescriptor, pdfInspectExpected } from '../pdf-fixture.mjs';

test(
  'Native and public PDF engines exchange searchable documents, metadata, rotation and page order',
  { timeout: 30000 },
  async () => {
    const app = await createApplication({
      service: { name: 'pdf-comparison-test', version: '1.0.0', environment: 'test' },
      plugins: [documentsPdfPlugin(pdfSettings)],
    });
    const fixture = {
      first: 'owned-pdf-test-first',
      second: 'owned-pdf-test-second',
      added: 'owned-pdf-test-added',
      title: 'owned-pdf-test-title',
    };
    try {
      await app.start();
      for (const service of [nativePdf(), app.resolve(PDF_CAPABILITY)]) {
        const result = await verifyPdf(service, fixture);
        assert.equal(result.operationsVerified, 5);
        assert.equal(result.mergedPages, 3);
      }
    } finally {
      await app.stop();
    }
  },
);

test(
  'Four PDF verification profiles preserve document interoperability and refuse unapproved measurement modes',
  { timeout: 60000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-pdf-harness-')),
      script = fileURLToPath(new URL('../pdf.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 55000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.equal(report.inputs.supervisedProfileTimeoutMs, undefined);
      assert.doesNotMatch(encoded, /owned-pdf-private-/);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          operationsVerified: 5,
          mergedPages: 3,
          nativeToPublicRead: true,
          publicToNativeRead: true,
          metadataVerified: true,
          textGeometryVerified: true,
          rotatedTextRetained: true,
          mergedPageOrderVerified: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      for (const mode of ['--smoke', '--full']) {
        const rejected = join(directory, mode.slice(2));
        await assert.rejects(
          promisify(execFile)(process.execPath, [script, mode, rejected], {
            timeout: 5000,
            maxBuffer: 1048576,
            env: {
              ...process.env,
              ARKENIVA_PDF_BENCHMARK_DISPOSABLE: mode === '--smoke' ? '0' : '1',
            },
          }),
        );
        await assert.rejects(access(rejected), { code: 'ENOENT' });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'The fixed PDF is independently readable and one actual native/public inspection preserves identical metadata and input bytes',
  { timeout: 15000 },
  async () => {
    const app = await createApplication({
      service: { name: 'pdf-fixed-inspect-control', version: '1.0.0', environment: 'test' },
      plugins: [documentsPdfPlugin(pdfSettings)],
    });
    try {
      await app.start();
      const bytes = pdfInspectFixture(),
        before = Buffer.from(bytes);
      for (const service of [nativePdf(), app.resolve(PDF_CAPABILITY)]) {
        assert.deepEqual(await service.inspect(bytes), pdfInspectExpected);
        const state = pdfInspectWorkload(service);
        assert.equal(await state.workload['inspect-fixed-one-page-pdf'](), 1);
        const result = await state.complete([
          { operation: 'inspect-fixed-one-page-pdf', sampleCount: 1, warmupIterations: 0 },
        ]);
        assert.equal(result.actualInspectOperations, 1);
        assert.equal(result.checkedInspectionReports, 1);
        assert.equal(result.inspectedPages, 1);
        assert.equal(result.independentPdfLibPages, 1);
        assert.equal(result.independentPdfJsPages, 1);
        assert.equal(result.independentTextVerified, true);
        assert.equal(result.consumedInputBytes, pdfInspectDescriptor.bytes);
        assert.equal(result.inputSha256, pdfInspectDescriptor.sha256);
        assert.equal(result.inputUnchanged, true);
        assert.equal(result.retainedReportsAfterCompletion, 0);
        assert.deepEqual(bytes, before);
      }
    } finally {
      await app.stop();
    }
  },
);
