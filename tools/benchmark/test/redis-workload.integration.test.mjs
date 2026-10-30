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
import { randomBytes } from 'node:crypto';
import { nativeRedis } from '../redis-workload.mjs';

test(
  'Native Redis comparison rejects the healthy wrong-SAN fixture without changing TLS policy',
  { timeout: 10000 },
  async () => {
    assert.equal(process.env.ARKENIVA_REDIS_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_REDIS_WRONG_SAN_URL);
    const fixture = {
      url: process.env.ARKENIVA_REDIS_URL,
      namespace: 'redis-comparison:' + randomBytes(16).toString('hex') + ':',
      marker: 'owned-native-redis-test-value',
    };
    const healthy = await nativeRedis(fixture);
    try {
      assert.equal(await healthy.inspect().ping(), 'PONG');
    } finally {
      await healthy.close();
    }
    await assert.rejects(
      nativeRedis({ ...fixture, url: process.env.ARKENIVA_REDIS_WRONG_SAN_URL }),
    );
  },
);

test(
  'Four Redis profiles verify actual portable operations, observed pubsub, sampled roundtrips and exact cleanup',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-redis-harness-')),
      script = fileURLToPath(new URL('../redis.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 25000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        const protocol = JSON.parse(
          await readFile(join(output, 'protocol-observation.json'), 'utf8'),
        );
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.deepEqual(protocol, { ownedKeysRemaining: 0, releaseGate: false });
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-redis-private-value|redis-comparison:|127\.0\.0\.1/);
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            utf8AndBomPreserved: true,
            nxOutcomes: [true, false],
            nativeTtlAndExpiryVerified: true,
            counterStateVerified: true,
            deleteCounts: [2, 0],
            actualSubscriberObserved: true,
          });
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          assert.equal(row.completion.nativeCounterVerified, true);
          if (mode === '--verify') {
            assert.equal(row.resource, null);
            assert.equal(row.completion.acknowledgedRoundtrips, 0);
          } else assert.ok(row.completion.acknowledgedRoundtrips >= 120);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
          for (const operation of row.records) {
            assert.equal(operation.operation, 'roundtrip');
            assert.ok(operation.sampleCount >= 100);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', join(directory, 'untrusted')], {
          env: { ...process.env, ARKENIVA_REDIS_URL: process.env.ARKENIVA_REDIS_WRONG_SAN_URL },
          timeout: 10000,
          maxBuffer: 1048576,
        }),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
