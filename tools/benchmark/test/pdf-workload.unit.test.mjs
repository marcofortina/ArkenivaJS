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
import { nativePdf, verifyPdf, pdfSettings } from '../pdf-workload.mjs';

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
  'Four PDF profiles retain actual document interoperability and SDK privacy without incomplete child sampling',
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
      const rejected = join(directory, 'sample');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          timeout: 5000,
          maxBuffer: 1048576,
        }),
      );
      await assert.rejects(access(rejected), { code: 'ENOENT' });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
