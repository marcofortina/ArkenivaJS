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
import { createApplication } from '@arkenivajs/core';
import { dataCsvPlugin, CSV_CAPABILITY } from '@arkenivajs/data-csv';
import {
  nativeCsv,
  csvSettings,
  csvFixture,
  csvSmallCorpus,
  csvSmallOperation,
} from '../csv-workload.mjs';

test('CSV entry rejects unsupported campaigns and unmarked smoke before workers or evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-csv-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_CSV_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../csv.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full CSV campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('One bounded functional CSV helper call per direction observes exact bytes, rows and first boundaries', async () => {
  const app = await createApplication({
    service: { name: 'csv-boundary-unit', version: '1.0.0', environment: 'test' },
    plugins: [dataCsvPlugin(csvSettings)],
  });
  try {
    await app.start();
    const corpus = csvSmallCorpus();
    for (const service of [nativeCsv(), app.resolve(CSV_CAPABILITY)]) {
      for (const operation of ['parse', 'stringify']) {
        const value = await csvSmallOperation(service, operation, corpus);
        assert.equal(value.rows, 256);
        assert.equal(value.encodedInputBytes + value.encodedOutputBytes, corpus.bytes.length);
        assert.equal(value.fieldUtf8Bytes, corpus.fieldBytes);
        assert.equal(value.sourceRetired, true);
        assert.ok(value.firstInputMs >= 0);
        assert.ok((operation === 'parse' ? value.firstOutputRowMs : value.firstOutputByteMs) >= 0);
        assert.ok(value.elapsedMs > 0);
        assert.equal(value.rowsPerSecond, (value.rows * 1000) / value.elapsedMs);
        assert.equal(value.encodedBytesPerSecond, (corpus.bytes.length * 1000) / value.elapsedMs);
        assert.equal(JSON.stringify(value).includes(csvFixture.marker), false);
      }
    }
  } finally {
    await app.stop();
  }
});
