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
import { createApplication } from '@arkenivajs/core';
import { etcdPlugin } from '@arkenivajs/database-etcd';
import { connectEtcd } from '../etcd-workload.mjs';
import { etcdIterations, etcdWarmupIterations } from '../etcd-workload.mjs';

test(
  'Native and public etcd verify healthy mTLS controls before rejecting wrong identity and unauthorized clients',
  { timeout: 30000 },
  async () => {
    assert.equal(process.env.ARKENIVA_ETCD_DISPOSABLE, '1');
    const fixture = {
      url: process.env.ARKENIVA_ETCD_URL,
      namespace: 'comparison_' + randomBytes(16).toString('hex') + '/',
    };
    const healthy = await connectEtcd(fixture);
    healthy.close();
    const variable = 'ARKENIVA_ETCD_COMPARISON_TEST_URL',
      apps = [];
    assert.equal(process.env[variable], undefined);
    async function application(url) {
      process.env[variable] = url;
      const app = await createApplication({
        service: { name: 'etcd-comparison-test', version: '1.0.0', environment: 'test' },
        plugins: [etcdPlugin()],
        databases: { configuration: { driver: 'etcd', connectionStringEnv: variable } },
      });
      apps.push(app);
      await app.start();
      return app;
    }
    try {
      const app = await application(fixture.url);
      assert.equal(await app.etcd.get(fixture.namespace + 'health'), null);
      await app.stop();
      for (const name of ['ARKENIVA_ETCD_WRONG_SAN_URL', 'ARKENIVA_ETCD_UNKNOWN_IDENTITY_URL']) {
        assert.ok(process.env[name]);
        await assert.rejects(connectEtcd({ ...fixture, url: process.env[name] }));
        await assert.rejects(application(process.env[name]));
      }
    } finally {
      delete process.env[variable];
      const results = await Promise.allSettled(apps.map((app) => app.stop()));
      assert.ok(results.every((result) => result.status === 'fulfilled'));
    }
  },
);

test(
  'Verified and sampled etcd profiles reconcile fresh-key CAS with independent bounded native readback and cleanup',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-etcd-harness-'));
    const script = fileURLToPath(new URL('../etcd.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const measured = mode === '--smoke',
          output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 150000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(
          encoded,
          /comparison_[a-f0-9]{32}|arkeniva_test_[a-f0-9]{24}|127\.0\.0\.1/,
        );
        const protocolText = await readFile(join(output, 'protocol-observation.json'), 'utf8'),
          protocol = JSON.parse(protocolText);
        assert.equal(protocol.ownedKeysRemaining, 0);
        assert.equal(protocol.releaseGate, false);
        assert.doesNotMatch(
          protocolText,
          /comparison_[a-f0-9]{32}|arkeniva_test_[a-f0-9]{24}|127\.0\.0\.1/,
        );
        if (measured) {
          const callbacks = report.records.reduce(
            (sum, row) => sum + row.completion.acknowledgedCreates,
            0,
          );
          assert.equal(callbacks, 4 * (etcdIterations + etcdWarmupIterations));
          assert.equal(protocol.acknowledgedCasCreates, callbacks);
          assert.equal(protocol.independentReadbackMatches, callbacks);
          assert.equal(protocol.staleCasRejections, 4);
          assert.equal(protocol.profileReadbacks.length, 4);
          for (const profile of protocol.profileReadbacks) {
            assert.equal(profile.independentlyVerifiedKeys, etcdIterations + etcdWarmupIterations);
            assert.equal(profile.valueBytes, profile.independentlyVerifiedKeys * 4);
            assert.ok(profile.observedKeyAndValueBytes <= 32768);
            assert.equal(profile.exactRevisionAndVersionVerified, true);
          }
          assert.equal(protocol.parentObserverResources, null);
          assert.equal(protocol.serverResources, null);
        } else assert.deepEqual(protocol, { ownedKeysRemaining: 0, releaseGate: false });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            rawBytesVerified: true,
            exactRevisionAndVersionVerified: true,
            concurrentCasWinners: 1,
            orderedWatchEvents: 3,
            nativeLeaseGrantAndRevokeVerified: true,
            serverObservedLeaseRenewal: true,
          });
          assert.equal(row.completion.sampledCreates, measured ? etcdIterations : 0);
          assert.equal(row.completion.warmupCreates, measured ? etcdWarmupIterations : 0);
          assert.equal(
            row.completion.acknowledgedCreates,
            row.completion.sampledCreates + row.completion.warmupCreates,
          );
          assert.equal(row.completion.staleCasRejections, measured ? 1 : 0);
          if (measured) {
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'casCreate');
            assert.equal(record.sampleCount, etcdIterations);
            assert.equal(record.warmupIterations, etcdWarmupIterations);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, record.sampleCount);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(record.throughputOpsPerSecond > 0);
            assert.ok(row.resource.elapsedMs > 0);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.completion.retainedOwnedKeys, etcdIterations + etcdWarmupIterations);
          } else {
            assert.deepEqual(row.records, []);
            assert.equal(row.resource, null);
          }
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
        }
      }
      const unsupported = join(directory, 'unsupported');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--full', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
