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
import { dataCsvPlugin, CSV_CAPABILITY } from '@arkenivajs/data-csv';
import {
  nativeCsv,
  csvSettings,
  csvFixture,
  csvRows,
  csvFields,
  collectCsvBytes,
  collectCsvFields,
  verifyCsv,
} from '../csv-workload.mjs';

test('Native and public CSV consume one-shot sources and exchange exact text fields', async () => {
  const app = await createApplication({
    service: { name: 'csv-comparison-unit', version: '1.0.0', environment: 'test' },
    plugins: [dataCsvPlugin(csvSettings)],
  });
  try {
    await app.start();
    const framework = app.resolve(CSV_CAPABILITY),
      native = nativeCsv();
    for (const service of [native, framework])
      assert.equal((await verifyCsv(service)).completedStreams, true);
    for (const [encoder, decoder] of [
      [native, framework],
      [framework, native],
    ]) {
      let starts = 0,
        pulls = 0;
      const rows = {
        async *[Symbol.asyncIterator]() {
          assert.equal(++starts, 1);
          for (const row of csvRows()) {
            pulls++;
            yield row;
          }
        },
      };
      const encoded = await collectCsvBytes(encoder.stringify(rows)),
        before = Buffer.from(encoded);
      assert.equal(pulls, csvFields.length);
      assert.deepEqual(await collectCsvFields(decoder.parse(encoded)), csvFields);
      assert.deepEqual(encoded, before);
    }
  } finally {
    await app.stop();
  }
});

test(
  'Four CSV profiles verify completed streams and refuse incomplete streaming measurements',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-csv-harness-')),
      script = fileURLToPath(new URL('../csv.mjs', import.meta.url));
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
      assert.equal(encoded.includes(csvFixture.marker), false);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          checkedDelimiters: 3,
          checkedRows: 6,
          completedStreams: true,
          textOnly: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
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
