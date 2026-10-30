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
import SftpClient from 'ssh2-sftp-client';
import {
  sftpCorpus,
  sftpSamplePath,
  sftpSampleBytes,
  sftpPressureBytes,
  summarizeSftpMeasurements,
  configureSftpSmokeClient,
} from '../sftp-workload.mjs';

test('SFTP entry refuses unsupported or unmarked measurements before fixture reads or evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sftp-entry-')),
    env = { ...process.env, ARKENIVA_SFTP_FIXTURE: '/nonexistent-owned-sftp-metadata.json' };
  delete env.ARKENIVA_SFTP_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../sftp.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full SFTP campaigns remain separate|explicitly disposable runner/.test(error.stderr) &&
          !error.stderr.includes('ENOENT'),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Smoke TCP tuning calls the real documented upstream client API and exports no client state', () => {
  const client = new SftpClient();
  const result = configureSftpSmokeClient({
    files: {
      native(name) {
        assert.equal(name, 'owned');
        return client;
      },
    },
  });
  assert.deepEqual(result, { clientTcpNoDelay: true, documentedNativeClientReturned: true });
  assert.throws(() => configureSftpSmokeClient({ files: { native: () => ({}) } }));
  assert.equal(JSON.stringify(result).includes('transfer'), false);
  assert.equal(JSON.stringify(result).includes('hostVerifier'), false);
  // This disconnected CPU check does not claim that a socket or protocol call was measured.
  assert.equal(client.sftp, undefined);
});

test('SFTP finite corpus, exact owned paths and aggregation preserve actual callback accounting', () => {
  const fixture = {
      root: '/home/transfer/data',
      fileStem: 'owned-comparison-' + 'a'.repeat(32),
      marker: 'owned-sftp-cpu-fixture',
      username: 'transfer',
    },
    small = sftpCorpus(fixture, sftpSampleBytes),
    pressure = sftpCorpus(fixture, sftpPressureBytes);
  assert.equal(small.length, 65536);
  assert.equal(pressure.length, 262144);
  assert.deepEqual(pressure.subarray(0, small.length), small);
  assert.deepEqual(sftpCorpus(fixture, sftpSampleBytes), small);
  assert.notEqual(
    createHash('sha256').update(small).digest('hex'),
    createHash('sha256').update(pressure).digest('hex'),
  );
  assert.equal(sftpSamplePath(fixture), fixture.root + '/' + fixture.fileStem + '.sample');
  assert.equal(sftpSamplePath(fixture, true), fixture.root + '/' + fixture.fileStem + '.pressure');
  assert.throws(() => sftpSamplePath({ ...fixture, fileStem: '../foreign' }));
  assert.throws(() => sftpSamplePath({ ...fixture, root: '/foreign' }));
  assert.throws(() => sftpCorpus(fixture, 1048576));
  const values = Array.from({ length: 120 }, (_, index) => ({
      bytes: sftpSampleBytes,
      callbacks: index % 2 ? 2 : 1,
    })),
    record = {
      operation: 'download-validated-byte-stream',
      sampleCount: 100,
      warmupIterations: 20,
      rawLatency: { values: Array.from({ length: 100 }, () => 1) },
    },
    result = summarizeSftpMeasurements(values, record);
  assert.equal(result.actualCallbacks, values.length);
  assert.equal(result.downloadBytes, values.length * sftpSampleBytes);
  assert.equal(result.destinationCallbacks, 180);
  assert.equal(result.measurements.filter((value) => value.phase === 'warmup').length, 20);
  assert.equal(result.measurements.filter((value) => value.phase === 'measured').length, 100);
  assert.throws(() => summarizeSftpMeasurements(values.slice(1), record));
  assert.equal(JSON.stringify(result).includes(fixture.marker), false);
  assert.equal(JSON.stringify(result).includes(fixture.fileStem), false);
  assert.equal(JSON.stringify(result).includes(fixture.username), false);
});
