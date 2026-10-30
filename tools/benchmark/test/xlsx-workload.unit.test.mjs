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
import { dataXlsxPlugin, XLSX_CAPABILITY } from '@arkenivajs/data-xlsx';
import { nativeXlsx, verifyXlsx, xlsxSettings } from '../xlsx-workload.mjs';

test(
  'Native and public XLSX workbooks exchange typed cells, styles and deliberately uncalculated formula caches',
  { timeout: 15000 },
  async () => {
    const app = await createApplication({
      service: { name: 'xlsx-comparison-test', version: '1.0.0', environment: 'test' },
      plugins: [dataXlsxPlugin(xlsxSettings)],
    });
    const fixture = {
      firstSheet: 'Owned first',
      secondSheet: 'Owned second',
      marker: 'owned-xlsx-test-value',
    };
    try {
      await app.start();
      for (const service of [nativeXlsx(), app.resolve(XLSX_CAPABILITY)]) {
        const verified = await verifyXlsx(service, fixture);
        assert.equal(verified.formulasUnexecuted, true);
        assert.equal(verified.styleAndDateVerified, true);
      }
    } finally {
      await app.stop();
    }
  },
);

test(
  'Four XLSX profiles retain actual interoperability and private SDK evidence while rejecting incomplete sampling',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xlsx-harness-')),
      script = fileURLToPath(new URL('../xlsx.mjs', import.meta.url));
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
        /owned-xlsx-private-content|Owned comparison data|Owned comparison other/,
      );
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          sheetsPerWorkbook: 2,
          rowsPerWorkbook: 5,
          nativeToPublicRead: true,
          publicToNativeRead: true,
          oneShotSourceVerified: true,
          awaitedTargetsVerified: true,
          formulasUnexecuted: true,
          styleAndDateVerified: true,
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
