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
import { randomBytes } from 'node:crypto';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { connectMongo } from '../mongodb-workload.mjs';

test(
  'Native and public MongoDB verify healthy SCRAM/TLS controls before rejecting a healthy wrong-SAN peer',
  { timeout: 20000 },
  async () => {
    assert.equal(process.env.ARKENIVA_MONGODB_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_MONGODB_WRONG_SAN_URL);
    const fixture = {
      url: process.env.ARKENIVA_MONGODB_URL,
      collection: 'comparison_' + randomBytes(16).toString('hex'),
    };
    const healthy = await connectMongo(fixture);
    await healthy.close();
    const variable = 'ARKENIVA_MONGODB_COMPARISON_TEST_URL';
    assert.equal(process.env[variable], undefined);
    const apps = [];
    const application = async (url) => {
      process.env[variable] = url;
      const app = await createApplication({
        service: { name: 'mongodb-comparison-test', version: '1.0.0', environment: 'test' },
        plugins: [mongodbPlugin()],
        databases: { documents: { driver: 'mongodb', connectionStringEnv: variable } },
      });
      apps.push(app);
      await app.start();
      return app;
    };
    try {
      const app = await application(fixture.url);
      assert.equal(await app.resolve(COMPONENTS.mongo).findOne(fixture.collection, {}), null);
      await app.stop();
      await assert.rejects(
        connectMongo({ ...fixture, url: process.env.ARKENIVA_MONGODB_WRONG_SAN_URL }),
      );
      await assert.rejects(application(process.env.ARKENIVA_MONGODB_WRONG_SAN_URL));
    } finally {
      delete process.env[variable];
      const closed = await Promise.allSettled(apps.map((app) => app.stop()));
      assert.ok(closed.every((result) => result.status === 'fulfilled'));
    }
  },
);

test(
  'Four MongoDB profiles verify exact BSON, actual CRUD/aggregation, commit/rollback and owned collection retirement',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mongodb-harness-'));
    const script = fileURLToPath(new URL('../mongodb.mjs', import.meta.url));
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
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /owned-mongodb-private-document|comparison_[a-f0-9]{32}|127\.0\.0\.1/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { ownedCollectionsRemaining: 0, releaseGate: false },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          actualCrudAndCountsVerified: true,
          exactNativeBsonPreserved: true,
          opaqueCustomIdVerified: true,
          unchangedAggregationVerified: true,
          commitAndRollbackVerified: true,
          callbackInvocations: [1, 1],
          nativeSessionsEnded: true,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const unsupported = join(directory, 'unsupported');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
