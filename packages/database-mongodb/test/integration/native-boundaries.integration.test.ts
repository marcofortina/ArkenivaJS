// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MongoClient, BSON } from 'mongodb';
import { ConnectionString } from 'mongodb-connection-string-url';
import { mongoConfiguration } from '../../dist/config.js';
import {
  mongoCollection,
  mongoDocument,
  mongoPipeline,
  mongoInsertedId,
} from '../../dist/common.js';

async function fixture(context: TestContext) {
  assert.equal(
    process.env.ARKENIVA_MONGODB_DISPOSABLE,
    '1',
    'Only a dedicated disposable MongoDB replica set is permitted',
  );
  assert.ok(process.env.ARKENIVA_MONGODB_URL, 'A verified TLS MongoDB fixture URL is required');
  const directory = mkdtempSync(join(tmpdir(), 'arkeniva-mongodb-trust-'));
  const parsed = new ConnectionString(process.env.ARKENIVA_MONGODB_URL),
    source = parsed.searchParams.get('tlsCAFile');
  assert.ok(source, 'The disposable fixture requires an explicit CA');
  const ca = join(directory, 'ca.crt');
  writeFileSync(ca, readFileSync(source), { mode: 0o600 });
  parsed.searchParams.set('tlsCAFile', ca);
  const variable = 'ARKENIVA_MONGODB_CAPTURED_TEST',
    previous = process.env[variable];
  let configuration;
  try {
    process.env[variable] = parsed.toString();
    configuration = mongoConfiguration(
      { driver: 'mongodb', connectionStringEnv: variable },
      'production',
    );
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
  }
  writeFileSync(ca, 'Changed after trust capture');
  const oldAll = process.env.MONGODB_LOG_ALL,
    oldCommand = process.env.MONGODB_LOG_COMMAND;
  let logs = 0,
    client: MongoClient;
  try {
    process.env.MONGODB_LOG_ALL = 'trace';
    process.env.MONGODB_LOG_COMMAND = 'trace';
    client = new MongoClient(configuration.url, {
      ...configuration.native,
      mongodbLogPath: {
        write() {
          logs++;
        },
      },
    });
  } finally {
    if (oldAll === undefined) delete process.env.MONGODB_LOG_ALL;
    else process.env.MONGODB_LOG_ALL = oldAll;
    if (oldCommand === undefined) delete process.env.MONGODB_LOG_COMMAND;
    else process.env.MONGODB_LOG_COMMAND = oldCommand;
  }
  const names: string[] = [];
  context.after(async () => {
    try {
      for (const name of names) await client.db().collection(name).drop();
    } finally {
      try {
        await client.close();
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  });
  await client.connect();
  return {
    client,
    configuration,
    get logs() {
      return logs;
    },
    collection() {
      const name = mongoCollection(
        'boundary_' + randomBytes(10).toString('hex'),
        configuration.prefix,
        configuration.database,
      );
      names.push(name);
      return client.db().collection(name);
    },
  };
}

test('Real MongoDB uses captured verified trust and keeps inherited command logging disabled', async (context) => {
  const f = await fixture(context),
    collection = f.collection();
  await collection.insertOne(mongoDocument({ _id: 'captured-trust', value: 'private-document' }));
  assert.ok(await collection.findOne(mongoDocument({ _id: 'captured-trust' })));
  assert.equal(f.logs, 0);
  assert.equal(f.configuration.native.retryReads, false);
  assert.equal(f.configuration.native.retryWrites, false);
  assert.equal(f.configuration.native.maxAdaptiveRetries, 0);
});

test('Real MongoDB accepts captured BSON identities and unchanged proved aggregation pipelines', async (context) => {
  const f = await fixture(context),
    collection = f.collection();
  const ids = [
    new BSON.ObjectId(),
    'caller-string',
    BSON.Long.fromString('9007199254740993'),
    { account: 'object-id' },
  ];
  const encoded: string[] = [];
  for (let index = 0; index < ids.length; index++) {
    const document = mongoDocument({
      _id: ids[index],
      ordinal: index,
      exact: BSON.Long.fromString('9007199254740993'),
      amount: BSON.Decimal128.fromString('1234567890.123456789'),
      bytes: new BSON.Binary(Buffer.from([0, 255])),
    });
    const result = await collection.insertOne(document);
    encoded.push(mongoInsertedId(result.insertedId));
    const row = await collection.findOne(mongoDocument({ _id: ids[index]! }), {
      promoteValues: false,
      promoteLongs: false,
    });
    assert.ok(row?.exact instanceof BSON.Long);
    assert.equal(row.exact.toString(), '9007199254740993');
    assert.ok(row.amount instanceof BSON.Decimal128);
    assert.equal(row.amount.toString(), '1234567890.123456789');
    assert.ok(row.bytes instanceof BSON.Binary);
    assert.deepEqual(Buffer.from(row.bytes.buffer), Buffer.from([0, 255]));
  }
  assert.equal(new Set(encoded).size, ids.length);
  for (const stages of [
    [{ $limit: BSON.Long.fromNumber(2) }, { $project: { _id: 1, exact: 1 } }],
    [{ $sample: { size: 2 } }],
    [{ $bucketAuto: { groupBy: '$ordinal', buckets: 2 } }],
    [{ $bucket: { groupBy: '$ordinal', boundaries: [0, 2, 4] } }],
    [{ $count: 'total' }],
  ]) {
    const proof = mongoPipeline(stages),
      cursor = collection.aggregate(proof.pipeline, { batchSize: 1, promoteLongs: false });
    try {
      const rows = await cursor.toArray();
      assert.ok(rows.length <= proof.maximum);
    } finally {
      await cursor.close();
    }
  }
});
