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
import { dataCompressionPlugin, COMPRESSION_CAPABILITY } from '@arkenivajs/data-compression';
import {
  nativeCompression,
  compressionSettings,
  compressionFixture,
  payload,
  compressionSmallCorpus,
  compressionSmallOperation,
} from '../compression-workload.mjs';

test('Compression entry rejects unsupported campaigns and unmarked smoke before workers or evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-compression-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_COMPRESSION_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../compression.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full compression campaigns remain separate|explicitly disposable runner/.test(
            error.stderr,
          ),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('One tiny functional GZIP/GUNZIP call observes exact bytes, CRC validation and actual first boundaries', async () => {
  const app = await createApplication({
    service: { name: 'compression-boundary-unit', version: '1.0.0', environment: 'test' },
    plugins: [dataCompressionPlugin(compressionSettings)],
  });
  try {
    await app.start();
    const corpus = compressionSmallCorpus();
    for (const service of [nativeCompression(), app.resolve(COMPRESSION_CAPABILITY)]) {
      for (const operation of ['gzip', 'gunzip']) {
        const value = await compressionSmallOperation(service, operation, corpus);
        assert.equal(value.uncompressedBytes, payload.length);
        assert.ok(value.compressedBytes > 0);
        assert.equal(value.compressionRatio, value.uncompressedBytes / value.compressedBytes);
        assert.equal(value.sourceRetired, true);
        assert.ok(value.firstInputMs >= 0 && value.firstOutputByteMs >= 0);
        assert.ok(value.streamElapsedMs > 0 && value.validationMs >= 0);
        assert.equal(value.inputBytesPerSecond, (value.inputBytes * 1000) / value.streamElapsedMs);
        assert.equal(
          value.outputBytesPerSecond,
          (value.outputBytes * 1000) / value.streamElapsedMs,
        );
        for (const token of Object.values(compressionFixture))
          assert.equal(JSON.stringify(value).includes(token), false);
      }
    }
  } finally {
    await app.stop();
  }
});
