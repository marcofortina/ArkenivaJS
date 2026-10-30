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
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full MongoDB campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_MONGODB_BENCHMARK_DISPOSABLE,
    '1',
    'MongoDB smoke measurements require an explicitly disposable runner',
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
  ...(measured
    ? {
        readCollection: 'comparison_' + randomBytes(16).toString('hex'),
        readId: 'read_' + randomBytes(16).toString('hex'),
      }
    : {}),
};
const config = mongodbConnection(fixture),
  observer = await connectMongo(fixture);
const ownedFixtures = [
  fixture,
  ...(measured ? [{ ...fixture, collection: fixture.readCollection }] : []),
];
let owned = false;
try {
  for (const selected of ownedFixtures) {
    const selectedConfig = mongodbConnection(selected);
    assert.equal(
      (
        await observer
          .db(selectedConfig.database)
          .listCollections({ name: selectedConfig.physical }, { nameOnly: true })
          .toArray()
      ).length,
      0,
    );
  }
  owned = true;
  await runPureComparison(
    {
      scenarioId: 'mongodb-native-bson-crud-and-transaction-verification',
      superviseProcessTree: true,
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
        samplingSupported: true,
        measuredScenarios: ['find-one-owned-bson-document'],
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        matchedDocumentCount: measured ? 1 : null,
        readRetries: false,
        writeRetries: false,
        byteObservationScope: 'decoded-native-bson-only',
        externalServerResourcesIncluded: false,
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
      },
      observationCoverage:
        'Four real verified-TLS/SCRAM MongoDB replica-set profiles preserve exact native BSON, opaque IDs, actual CRUD counts and unchanged aggregation. Native sessions commit/abort once with independent readback and confirmed session end. Explicit short smoke retains actual Tinybench findOne latency on one separately seeded owned BSON document; passive actual-driver events verify every observed find success against real callback counts. Independent native count/readback before/after and exact collection retirement remain outside callbacks. Actual SDK exports exclude documents, credentials and namespaces.',
      limitations:
        'Small valid fixed corpus and one-member owned replica sets. Native baseline omits full hostile-input capture, command/frame admission, result limits, unknown-outcome classification, cancellation and lifecycle policy. Timed reads include consumer BSON type/EJSON validation and byte-size observation; decoded BSON bytes are not wire bytes. Client process supervision includes its own independent observer work across the whole lifecycle; parent observer/collector and external mongod CPU/RSS are excluded. STANDARD and DETAILED both force diagnostic sampling1. Native transaction callbacks are deliberately not replayed; neither path claims exactly-once business effects. A collection prefix is not tenant authorization. No timed writes/transactions, multi-member failover, whole-pipeline/server resource budget, calibrated overhead, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  for (const selected of ownedFixtures) {
    const selectedConfig = mongodbConnection(selected);
    assert.equal(
      (
        await observer
          .db(selectedConfig.database)
          .listCollections({ name: selectedConfig.physical }, { nameOnly: true })
          .toArray()
      ).length,
      0,
    );
  }
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ ownedCollectionsRemaining: 0, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  try {
    if (owned) for (const selected of ownedFixtures) await dropOwnedMongo(observer, selected);
  } finally {
    await observer.close();
  }
}
