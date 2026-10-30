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
import { dataCompressionPlugin, COMPRESSION_CAPABILITY } from '@arkenivajs/data-compression';
import {
  nativeCompression,
  compressionSettings,
  compressionFixture,
  payload,
  entries,
  collect,
  archiveContents,
  verifyCompression,
} from '../compression-workload.mjs';

test(
  'Native and public compression consume complete byte streams and exchange real ZIP entries',
  { timeout: 30000 },
  async () => {
    const app = await createApplication({
      service: { name: 'compression-comparison-unit', version: '1.0.0', environment: 'test' },
      plugins: [dataCompressionPlugin(compressionSettings)],
    });
    try {
      await app.start();
      const framework = app.resolve(COMPRESSION_CAPABILITY),
        native = nativeCompression();
      for (const service of [native, framework]) {
        assert.equal((await verifyCompression(service)).completedStreams, true);
        let pulled = 0;
        const input = (async function* () {
          pulled++;
          yield payload.subarray(0, 100);
          pulled++;
          yield payload.subarray(100);
        })();
        const encoded = await collect(service.gzip(input));
        assert.equal(pulled, 2);
        assert.deepEqual(await collect(service.gunzip(encoded)), payload);
      }
      const expected = Object.fromEntries(
        entries().map((entry) => [entry.path, Buffer.from(entry.data)]),
      );
      for (const [encoder, decoder] of [
        [native, framework],
        [framework, native],
      ]) {
        const archive = await collect(encoder.createZip(entries())),
          before = Buffer.from(archive);
        assert.deepEqual(await archiveContents(decoder, archive), expected);
        assert.deepEqual(archive, before);
      }
    } finally {
      await app.stop();
    }
  },
);

test(
  'Four compression profiles verify completed work and refuse incomplete streaming measurements',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-compression-harness-')),
      script = fileURLToPath(new URL('../compression.mjs', import.meta.url));
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
      for (const value of Object.values(compressionFixture))
        assert.equal(encoded.includes(value), false);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.equal(row.verification.checkedGzipRoundtrips, 3);
        assert.equal(row.verification.checkedZipEntries, 2);
        assert.equal(row.verification.completedStreams, true);
        assert.equal(row.verification.inputBytes, payload.byteLength);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      const rejected = join(directory, 'sample'),
        env = { ...process.env };
      delete env.ARKENIVA_COMPRESSION_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          env,
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
