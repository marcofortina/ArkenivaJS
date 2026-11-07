// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeApiKeyObservation } from '../apikey-observations.mjs';
import { fingerprint } from '../mfa-privacy.mjs';

const observation = (mode, overrides = {}) => ({
  mode,
  sourceCommit: 'test-source-revision',
  workingTreeDirty: true,
  sourceFilesSha256: { 'tools/benchmark/apikey.mjs': 'test-source-digest' },
  report: {
    mode,
    record: {
      completedOperations: 50,
      schedulingDrops: 0,
      latencyMs: { samples: [1, 2, 3], p50: 2, p95: 3, p99: 3, max: 3 },
    },
  },
  providerCalls: { 'store.read': 165 },
  ...overrides,
});
async function withDirectory(run) {
  const directory = await mkdtemp(join(tmpdir(), 'arkeniva-apikey-observations-'));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('Credential observations retain earlier and rejected raw profiles without a final acceptance report', async () => {
  await withDirectory(async (directory) => {
    await writeApiKeyObservation(directory, observation('BASELINE'), []);
    const rejected = observation('STANDARD', {
      report: {
        mode: 'STANDARD',
        record: {
          completedOperations: 49,
          schedulingDrops: 1,
          latencyMs: { samples: [4, 5], p50: 4, p95: 5, p99: 5, max: 5 },
        },
      },
    });
    let validationError;
    await assert.rejects(
      async () => {
        try {
          assert.equal(rejected.report.record.schedulingDrops, 0);
        } catch (error) {
          validationError = error;
          throw error;
        } finally {
          await writeApiKeyObservation(directory, rejected, []);
        }
      },
      (error) => error === validationError && error.code === 'ERR_ASSERTION',
    );
    const first = JSON.parse(await readFile(join(directory, 'baseline-observations.json'), 'utf8'));
    const last = JSON.parse(await readFile(join(directory, 'standard-observations.json'), 'utf8'));
    assert.equal(first.validation, 'UNVERIFIED');
    assert.equal(last.validation, 'UNVERIFIED');
    assert.equal(first.releaseGate, false);
    assert.equal(last.releaseGate, false);
    assert.deepEqual(first.report.record.latencyMs.samples, [1, 2, 3]);
    assert.equal(last.report.record.schedulingDrops, 1);
    assert.deepEqual(await readdir(directory), [
      'baseline-observations.json',
      'standard-observations.json',
    ]);
  });
});

test('Credential observation files are private, exclusive and isolated by the closed profile name', async () => {
  await withDirectory(async (directory) => {
    await writeApiKeyObservation(directory, observation('FRAMEWORK'), []);
    const path = join(directory, 'framework-observations.json'),
      original = await readFile(path);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(writeApiKeyObservation(directory, observation('FRAMEWORK'), []), {
      code: 'EEXIST',
    });
    assert.deepEqual(await readFile(path), original);
    await assert.rejects(writeApiKeyObservation(directory, observation('../outside'), []));
    assert.deepEqual(await readdir(directory), ['framework-observations.json']);
  });
});

test('Credential observations refuse raw secrets in report values or property names before creating a file', async () => {
  await withDirectory(async (directory) => {
    const secret = randomBytes(32).toString('base64url'),
      privateValues = [fingerprint(secret)];
    for (const report of [{ note: 'leaked ' + secret }, { [secret]: 1 }]) {
      await assert.rejects(
        writeApiKeyObservation(directory, observation('DETAILED', { report }), privateValues),
        /private material/,
      );
      assert.deepEqual(await readdir(directory), []);
    }
  });
});

test('Credential observations exclude comparison corpora and refuse fingerprints nested in report data', async () => {
  await withDirectory(async (directory) => {
    const secret = randomBytes(32).toString('base64url'),
      comparison = fingerprint(secret);
    await assert.rejects(
      writeApiKeyObservation(directory, observation('DETAILED', { report: { note: comparison } }), [
        comparison,
      ]),
      /comparison fingerprints/,
    );
    assert.deepEqual(await readdir(directory), []);
    await writeApiKeyObservation(
      directory,
      observation('DETAILED', { fingerprints: [comparison], corpus: [secret] }),
      [comparison],
    );
    const value = await readFile(join(directory, 'detailed-observations.json'), 'utf8');
    assert.equal(value.includes(comparison), false);
    assert.equal(value.includes(secret), false);
    assert.equal(value.includes('fingerprints'), false);
    assert.equal(value.includes('corpus'), false);
  });
});
