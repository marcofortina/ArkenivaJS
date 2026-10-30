// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { dataXlsxPlugin, XLSX_CAPABILITY } from '@arkenivajs/data-xlsx';
import { xlsxFixtureBytes, xlsxFixtureSha256 } from '../xlsx-fixture.mjs';
import {
  nativeXlsx,
  xlsxSettings,
  prepareXlsxRead,
  xlsxReadWorkload,
  completeXlsxRead,
} from '../xlsx-workload.mjs';

const fixture = {
  firstSheet: 'Owned comparison data',
  secondSheet: 'Owned comparison other',
  marker: 'owned-xlsx-private-content',
};

test('XLSX sampling refuses unmarked execution before creating reports or workers', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xlsx-entry-')),
    output = join(directory, 'report'),
    env = { ...process.env };
  delete env.ARKENIVA_XLSX_BENCHMARK_DISPOSABLE;
  try {
    await assert.rejects(
      promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../xlsx.mjs', import.meta.url)), '--smoke', output],
        { env, timeout: 5000 },
      ),
      (cause) => {
        assert.match(cause.stderr, /XLSX smoke requires an explicitly disposable/);
        return true;
      },
    );
    await assert.rejects(access(output));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Native and public sampled reads preserve the identical fixed workbook and physically close each reader', async () => {
  const app = await createApplication({
    service: { name: 'xlsx-fixed-sample-test', version: '1.0.0', environment: 'test' },
    plugins: [dataXlsxPlugin(xlsxSettings)],
  });
  try {
    await app.start();
    for (const service of [nativeXlsx(), app.resolve(XLSX_CAPABILITY)]) {
      prepareXlsxRead(service, fixture);
      const callback = xlsxReadWorkload(service).readFiveRows;
      const active = callback();
      await assert.rejects(callback());
      const result = await active;
      assert.equal(result.checkedRows, 5);
      assert.equal(result.checkedSheets, 2);
      assert.equal(result.inputBytes, 7283);
      assert.equal(result.sourceTraversals, 1);
      assert.equal(result.sourceRetired, true);
      assert.equal(result.readerClosed, true);
      assert.ok(result.firstRowMs >= 0 && result.elapsedMs >= result.firstRowMs);
      assert.ok(result.rowsPerSecond > 0);
      assert.throws(() => completeXlsxRead(service, { measure: true, records: [] }));
      await assert.rejects(callback());
      assert.throws(() => xlsxReadWorkload(service));
    }
    assert.equal(createHash('sha256').update(xlsxFixtureBytes).digest('hex'), xlsxFixtureSha256);
  } finally {
    await app.stop();
  }
});

test('Actual XLSX contents cannot pass a different expected private row corpus', async () => {
  const service = nativeXlsx();
  prepareXlsxRead(service, { ...fixture, marker: 'different-expected-content' });
  await assert.rejects(xlsxReadWorkload(service).readFiveRows());
  assert.throws(() => completeXlsxRead(service, { measure: true, records: [] }));
  assert.equal(createHash('sha256').update(xlsxFixtureBytes).digest('hex'), xlsxFixtureSha256);
});
