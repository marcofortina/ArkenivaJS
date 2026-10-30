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
import { nativeUpload, verifyUpload, sendUpload } from '../upload-workload.mjs';

test('Native multipart consumes fresh chunked sources, exact UTF8 fields, empty files and actual hashes', async () => {
  const fixture = { marker: 'owned-upload-content-π', note: 'owned-upload-field-€' },
    native = await nativeUpload();
  try {
    const result = await verifyUpload(native, fixture);
    assert.equal(result.consumedFileBytes, Buffer.byteLength(fixture.marker) * 4096 * 2);
    assert.equal(result.completedFiles, 4);
    await assert.rejects(sendUpload({ address: () => 'http://example.invalid:1' }, fixture, true));
  } finally {
    await native.close();
  }
});

test(
  'Four upload profiles verify streamed protocol and actual private SDK exports without performance claims',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-upload-harness-')),
      script = fileURLToPath(new URL('../upload.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /owned-upload-content|owned-upload-field|owned\.bin|empty\.bin|127\.0\.0\.1/,
      );
      for (const row of report.records) {
        assert.equal(row.records.length, 0);
        assert.equal(row.resource, null);
        assert.deepEqual(row.verification, {
          completedRequests: 2,
          completedFiles: 4,
          consumedFileBytes: Buffer.byteLength('owned-upload-content-π') * 4096 * 2,
          orderedParts: true,
          emptyFileVerified: true,
          fragmentedUtf8: true,
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
