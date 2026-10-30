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

test(
  'Explicit MongoDB smoke retains actual TLS/SCRAM finds, native BSON and independent collection retirement',
  { timeout: 145000, skip: process.env.ARKENIVA_MONGODB_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mongodb-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../mongodb.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        protocol = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-mongodb-private-document|comparison_[a-f0-9]{32}|read_[a-f0-9]{32}|127\.0\.0\.1/,
      );
      assert.deepEqual(protocol, { ownedCollectionsRemaining: 0, releaseGate: false });
      for (const row of report.records) {
        assert.equal(row.verification.exactNativeBsonPreserved, true);
        assert.equal(row.verification.unchangedAggregationVerified, true);
        assert.equal(row.verification.commitAndRollbackVerified, true);
        assert.deepEqual(row.verification.callbackInvocations, [1, 1]);
        assert.equal(row.records.length, 1);
        const [record] = row.records,
          actual = row.completion;
        assert.equal(record.operation, 'find-one-owned-bson-document');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
        assert.equal(actual.actualCallbacks, record.sampleCount + record.warmupIterations);
        assert.equal(actual.measuredCallbacks, record.sampleCount);
        assert.equal(actual.warmupCallbacks, record.warmupIterations);
        assert.equal(actual.findCommandsStarted, actual.actualCallbacks);
        assert.equal(actual.findCommandsSucceeded, actual.actualCallbacks);
        assert.equal(actual.findCommandsFailed, 0);
        assert.equal(actual.getMoreCommandsStarted, 0);
        assert.equal(actual.outstandingCommands, 0);
        assert.equal(actual.wireBytes, null);
        assert.equal(actual.independentReadbacks.length, 2);
        assert.deepEqual(
          actual.independentReadbacks.map((value) => value.phase),
          ['before', 'after'],
        );
        for (const value of actual.independentReadbacks) {
          assert.equal(value.documents, 1);
          assert.ok(value.bsonDocumentBytes > 0);
          assert.equal(
            actual.observedBsonResultBytes,
            value.bsonDocumentBytes * actual.actualCallbacks,
          );
        }
        assert.equal(actual.ownedCollectionsRemaining, 0);
        assert.equal(actual.externalServerResourcesIncluded, false);
        assert.equal(row.processTreeResource.scope, 'whole-supervised-lifecycle');
        assert.equal(row.processTreeResource.allChildrenWaited, true);
        assert.equal(row.processTreeResource.remainingOwnedProcesses, 0);
        assert.equal(row.processTreeResource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(row.processTreeResource.externalServerResourcesIncluded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
