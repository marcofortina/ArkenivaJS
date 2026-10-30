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
import { createLogger } from '@arkenivajs/logging';
import { createLoggingAdapter, loggingFixture } from '../logging-workload.mjs';

test('Native Pino and public logging redact actual written rows and retain child and level semantics', async () => {
  for (const mode of ['native', 'framework']) {
    const adapter = createLoggingAdapter();
    const logger =
      mode === 'native'
        ? adapter.native(loggingFixture)
        : createLogger({
            service: { name: 'logging-comparison', version: '1.0.0', environment: 'test' },
            ...(await adapter.framework(loggingFixture)).loggingOptions,
          });
    try {
      assert.equal((await adapter.verify(logger, loggingFixture)).actualRedactionVerified, true);
      const work = adapter.workload(logger, loggingFixture);
      work.info();
      work.childInfo();
      const completion = await adapter.complete(logger, { records: [] });
      assert.equal(completion.rowsWritten, 4);
      assert.equal(completion.privateOccurrences, 0);
      assert.ok(completion.bytesWritten > 0);
    } finally {
      await logger.close();
    }
  }
});

test(
  'Four logging modes prove completed acknowledged rows instead of filtered timing loops',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-logging-harness-')),
      script = fileURLToPath(new URL('../logging.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 25000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(encoded.includes(loggingFixture.privateValue), false);
        assert.equal(report.collector.privateOccurrences, 0);
        for (const row of report.records) {
          assert.equal(row.verification.checkedWrittenRecords, 2);
          assert.equal(row.verification.levelFilterVerified, true);
          assert.equal(row.verification.actualRedactionVerified, true);
          assert.equal(row.records.length, mode === '--smoke' ? 2 : 0);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          assert.ok(row.completion.rowsWritten >= (mode === '--smoke' ? 2202 : 2));
          assert.ok(row.completion.bytesWritten > 0);
          assert.equal(row.completion.privateOccurrences, 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          for (const operation of row.records) assert.ok(operation.sampleCount >= 1000);
          if (row.mode !== 'BASELINE')
            for (const key of ['dropped', 'failedWrites', 'flushFailures', 'pendingBytes'])
              assert.equal(row.completion.frameworkStats[key], 0);
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
