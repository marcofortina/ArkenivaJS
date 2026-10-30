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
  'Four etcd profiles verify binary state, exact revisions, concurrent CAS, ordered watch and lease retirement',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-etcd-harness-'));
    const script = fileURLToPath(new URL('../etcd.mjs', import.meta.url));
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
        /comparison_[a-f0-9]{32}|arkeniva_test_[a-f0-9]{24}|127\.0\.0\.1/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { ownedKeysRemaining: 0, releaseGate: false },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          rawBytesVerified: true,
          exactRevisionAndVersionVerified: true,
          concurrentCasWinners: 1,
          orderedWatchEvents: 3,
          nativeLeaseGrantAndRevokeVerified: true,
          serverObservedLeaseRenewal: true,
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
