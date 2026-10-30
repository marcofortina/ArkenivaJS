// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { connectMongo, mongodbConnection, dropOwnedMongo } from './mongodb-workload.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete MongoDB server resource sampling remains separate',
);
assert.equal(
  process.env.ARKENIVA_MONGODB_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable MongoDB fixture',
);
const fixture = {
  url: process.env.ARKENIVA_MONGODB_URL,
  collection: 'comparison_' + randomBytes(16).toString('hex'),
  marker: 'owned-mongodb-private-document',
};
const config = mongodbConnection(fixture),
  observer = await connectMongo(fixture);
let owned = false;
try {
  assert.equal(
    (
      await observer
        .db(config.database)
        .listCollections({ name: config.physical }, { nameOnly: true })
        .toArray()
    ).length,
    0,
  );
  owned = true;
  await runPureComparison(
    {
      scenarioId: 'mongodb-native-bson-crud-and-transaction-verification',
      fixture,
      privacyValues: [
        ...Object.values(fixture),
        config.database,
        config.prefix,
        config.caFile,
        decodeURIComponent(config.url.username),
        decodeURIComponent(config.url.password),
        '127.0.0.1',
        'localhost',
      ].filter((value) => value.length > 0),
      privacyField: 'inputOccurrences',
      worker: new URL('./mongodb-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'mongodb@7.7.0',
        operations: [
          'findOne',
          'findMany',
          'insertOne',
          'updateOne',
          'deleteOne',
          'aggregate',
          'withTransaction',
        ],
        maxPoolSize: 8,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four real verified-TLS/SCRAM MongoDB replica-set profiles preserve exact native BSON, opaque IDs, actual CRUD counts and unchanged aggregation. Native sessions commit/abort once with independent readback and confirmed session end. Separate native observers verify writes and exact collection retirement. Actual SDK exports exclude documents, credentials and namespaces.',
      limitations:
        'Small valid fixed corpus and one-member owned replica sets. Native baseline omits full hostile-input capture, command/frame admission, result limits, unknown-outcome classification, cancellation and lifecycle policy. Native transaction callbacks are deliberately not replayed; neither path claims exactly-once business effects. A collection prefix is not tenant authorization. No multi-member failover, complete server/client resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  assert.equal(
    (
      await observer
        .db(config.database)
        .listCollections({ name: config.physical }, { nameOnly: true })
        .toArray()
    ).length,
    0,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ ownedCollectionsRemaining: 0, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  try {
    if (owned) await dropOwnedMongo(observer, fixture);
  } finally {
    await observer.close();
  }
}
