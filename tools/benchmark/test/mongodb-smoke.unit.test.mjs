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
import { BSON } from 'mongodb';
import {
  mongoReadDocument,
  checkMongoReadDocument,
  summarizeMongoRead,
  mongoCollectionConfiguration,
} from '../mongodb-workload.mjs';

test('MongoDB entry refuses unsupported or unmarked smoke before fixture access or evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mongodb-entry-')),
    env = { ...process.env, ARKENIVA_MONGODB_DISPOSABLE: '1', ARKENIVA_MONGODB_URL: 'invalid' };
  delete env.ARKENIVA_MONGODB_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../mongodb.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full MongoDB campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Native comparison maps only its two owned namespaces to distinct physical collections', () => {
  const fixture = {
    url: 'mongodb://user:pass@localhost:27018/owned?tls=true&tlsCAFile=/owned/ca&directConnection=true&prefix=owned_',
    collection: 'comparison_' + 'a'.repeat(32),
    readCollection: 'comparison_' + 'b'.repeat(32),
  };
  assert.equal(
    mongoCollectionConfiguration(fixture, fixture.collection).physical,
    'owned_' + fixture.collection,
  );
  assert.equal(
    mongoCollectionConfiguration(fixture, fixture.readCollection).physical,
    'owned_' + fixture.readCollection,
  );
  assert.throws(() => mongoCollectionConfiguration(fixture, 'comparison_' + 'c'.repeat(32)));
  assert.throws(() =>
    mongoCollectionConfiguration({ ...fixture, readCollection: undefined }, fixture.readCollection),
  );
});

test('Real BSON fidelity and callback accounting reject promoted values, extra commands and missing results', () => {
  const fixture = { marker: 'owned-mongodb-cpu-document', readId: 'read_' + 'a'.repeat(32) },
    document = mongoReadDocument(fixture),
    decoded = BSON.deserialize(BSON.serialize(document), {
      promoteValues: false,
      promoteLongs: false,
      bsonRegExp: true,
    }),
    bytes = checkMongoReadDocument(decoded, fixture);
  assert.equal(bytes, BSON.serialize(document).length);
  assert.throws(() => checkMongoReadDocument({ ...decoded, count: 7 }, fixture));
  assert.throws(() => checkMongoReadDocument({ ...decoded, exact: 9007199254740992 }, fixture));
  assert.throws(() => checkMongoReadDocument({ ...decoded, extra: 'unowned' }, fixture));
  const state = {
      returnedBsonBytes: Array.from({ length: 120 }, () => bytes),
      started: 120,
      succeeded: 120,
      failed: 0,
      getMore: 0,
      pending: new Set(),
    },
    record = {
      operation: 'find-one-owned-bson-document',
      sampleCount: 100,
      warmupIterations: 20,
      rawLatency: { values: Array.from({ length: 100 }, () => 1) },
    },
    actual = summarizeMongoRead(state, record);
  assert.equal(actual.actualCallbacks, state.returnedBsonBytes.length);
  assert.equal(actual.findCommandsSucceeded, state.succeeded);
  assert.equal(actual.observedBsonResultBytes, bytes * state.returnedBsonBytes.length);
  assert.equal(actual.wireBytes, null);
  assert.throws(() => summarizeMongoRead({ ...state, started: 121 }, record));
  assert.throws(() => summarizeMongoRead({ ...state, getMore: 1 }, record));
  assert.throws(() => summarizeMongoRead({ ...state, pending: new Set([1]) }, record));
  assert.throws(() => summarizeMongoRead({ ...state, returnedBsonBytes: [] }, record));
  for (const value of Object.values(fixture))
    assert.equal(JSON.stringify(actual).includes(value), false);
});
