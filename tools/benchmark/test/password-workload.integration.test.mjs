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
import { startPasswordFixture } from '../password-fixture.mjs';

test(
  'Owned KDF bridge rejects unauthenticated, foreign-namespace and unsupported store calls',
  { timeout: 15000 },
  async () => {
    const authority = await startPasswordFixture();
    try {
      for (const [bearer, body] of [
        ['', { method: 'read', args: ['password.budgets.v1', 'owned'] }],
        [authority.fixture.bearer, { method: 'read', args: ['foreign.namespace', 'owned'] }],
        [authority.fixture.bearer, { method: 'atomicBatch', args: [] }],
      ]) {
        const result = await globalThis.fetch(authority.fixture.endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-owned-provider': bearer },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(5000),
        });
        assert.equal(result.status, 500);
        assert.deepEqual(await result.json(), {});
      }
      assert.equal(authority.state.completedCalls, 0);
      assert.equal(await authority.durableCount(), 0);
    } finally {
      await authority.close();
    }
  },
);

test(
  'Four password profiles verify native KDF work and optionally sample positive verification with exact PostgreSQL admission',
  { timeout: 180000 },
  async () => {
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-password-harness-')),
      script = fileURLToPath(new URL('../password.mjs', import.meta.url));
    try {
      for (const campaign of ['verify', 'smoke']) {
        const measured = campaign === 'smoke',
          output = join(directory, campaign);
        await promisify(execFile)(process.execPath, [script, '--' + campaign, output], {
          timeout: 150000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded),
          durable = JSON.parse(await readFile(join(output, 'durable-observation.json'), 'utf8'));
        if (measured) {
          assert.equal(durable.persistedBudget, 375);
          assert.equal(durable.completedStoreCalls, 750);
          for (const field of [
            'successfulReadCalls',
            'successfulCompareAndSetCalls',
            'committedBudgetWrites',
          ])
            assert.equal(durable[field], 375);
          assert.equal(durable.independentlyVerifiedCurrentPhc, true);
          assert.equal(durable.technicalLimitPerMinute, 1000);
          assert.equal(durable.parentProviderResources, null);
          assert.equal(durable.postgresServerResources, null);
        } else
          assert.deepEqual(durable, {
            persistedBudget: 15,
            completedStoreCalls: 30,
            releaseGate: false,
          });
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(encoded.includes('$argon2id$'), false);
        for (const row of report.records) {
          assert.equal(row.completion.checkedVerifications, measured ? 120 : 0);
          if (measured) {
            assert.equal(row.completion.sampledVerifications, 100);
            assert.equal(row.completion.warmupVerifications, 20);
            assert.equal(row.completion.allPositiveAndCurrent, true);
            assert.equal(row.completion.peakRetainedResults, 120);
            assert.equal(row.completion.maximumRetainedResults, 128);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'verifyCurrentPassword');
            assert.equal(record.sampleCount, 100);
            assert.equal(record.warmupIterations, 20);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, 100);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(row.resource.elapsedMs > 0);
          } else {
            assert.equal(row.resource, null);
            assert.equal(row.records.length, 0);
          }
          assert.deepEqual(row.verification, {
            checkedHashes: 2,
            checkedVerifications: 3,
            independentSaltVerified: true,
            legacyRehashVerified: true,
          });
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
