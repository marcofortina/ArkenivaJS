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
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { proxyPlugin } from '@arkenivajs/proxy';
import { startProxyFixture } from '../proxy-fixture.mjs';
import { proxyRoute, nativeProxyService, verifyProxy, proxyExchange } from '../proxy-workload.mjs';

test('Proxy comparison rejects foreign origins, plaintext and noncanonical destinations before I/O', () => {
  for (const upstream of [
    'http://127.0.0.1:443',
    'https://foreign.invalid:443',
    'https://127.0.0.1:443/path',
    'https://u:p@127.0.0.1:443',
  ])
    assert.throws(() => proxyRoute({ upstream, caFile: '/owned/ca' }));
});

test(
  'Native and public proxies verify healthy HTTPS controls before rejecting an actual wrong-hostname peer',
  { timeout: 20000 },
  async () => {
    const healthy = await startProxyFixture(),
      wrong = await startProxyFixture('DNS:wrong.invalid');
    const apps = [],
      baselines = [];
    const sink = new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    });
    try {
      for (const authority of [healthy, wrong]) {
        const fixture = authority.fixture,
          baseline = await nativeProxyService(fixture);
        baselines.push(baseline);
        const app = await createApplication({
          service: { name: 'proxy-comparison-test', version: '1.0.0', environment: 'test' },
          http: { host: '127.0.0.1', port: 0 },
          plugins: [
            loggingPlugin({ destination: sink }),
            apiPlugin(),
            proxyPlugin({ routes: [proxyRoute(fixture)] }),
          ],
        });
        apps.push(app);
        await app.start();
        for (const service of [baseline, app.api]) {
          if (authority === healthy) await verifyProxy(service, fixture);
          else {
            const result = await proxyExchange(service, fixture, 'GET');
            assert.equal(result.status, service === baseline ? 500 : 502);
            assert.equal(result.body.includes(Buffer.from(fixture.upstream)), false);
          }
        }
      }
      healthy.verify(2);
      assert.equal(wrong.received.length, 0);
    } finally {
      const results = await Promise.allSettled([
        ...apps.map((app) => app.stop()),
        ...baselines.map((baseline) => baseline.close()),
      ]);
      await Promise.all([healthy.close(), wrong.close()]);
      sink.destroy();
      assert.ok(results.every((result) => result.status === 'fulfilled'));
    }
  },
);

test(
  'Four actual HTTPS proxy profiles preserve streamed bytes and raw query without leaking identity headers or SDK inputs',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-proxy-harness-'));
    const script = fileURLToPath(new URL('../proxy.mjs', import.meta.url));
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
      assert.doesNotMatch(encoded, /owned-proxy-private-credential|foreign\.invalid|127\.0\.0\.1/);
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        {
          actualUpstreamRequests: 8,
          exactStreamedBytesAndQueryVerified: true,
          spoofedIdentityHeadersAbsent: true,
          releaseGate: false,
        },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          actualProxyRequests: 2,
          exactStreamedResponseBytes: 262144,
          verifiedUpstreamTls: true,
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
