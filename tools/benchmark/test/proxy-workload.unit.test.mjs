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
  'Four actual HTTPS proxy profiles verify streamed bytes and optionally sample bounded GET receipts without leaking inputs',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-proxy-harness-'));
    const script = fileURLToPath(new URL('../proxy.mjs', import.meta.url));
    try {
      const campaigns =
        process.env.ARKENIVA_PROXY_BENCHMARK_DISPOSABLE === '1' ? ['verify', 'smoke'] : ['verify'];
      for (const campaign of campaigns) {
        const measured = campaign === 'smoke',
          output = join(directory, campaign);
        await promisify(execFile)(process.execPath, [script, '--' + campaign, output], {
          timeout: 150000,
          maxBuffer: 1048576,
          env: { ...process.env, ARKENIVA_PROXY_BENCHMARK_DISPOSABLE: '1' },
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
          /owned-proxy-private-credential|foreign\.invalid|127\.0\.0\.1/,
        );
        const observation = JSON.parse(
          await readFile(join(output, 'protocol-observation.json'), 'utf8'),
        );
        if (measured) {
          assert.equal(observation.actualUpstreamRequests, 488);
          assert.equal(observation.sampledForwardedGets, 480);
          assert.equal(observation.actualResponsePayloadBytes, 63963136);
          assert.equal(observation.actualRequestPayloadBytes, 524288);
          assert.equal(observation.maximumRetainedUpstreamReceipts, 512);
          assert.equal(observation.pendingUpstreamHandlers, 0);
          assert.equal(observation.parentHttpsOriginResources, null);
          assert.equal(observation.exactStreamedBytesAndQueryVerified, true);
          assert.equal(observation.spoofedIdentityHeadersAbsent, true);
        } else
          assert.deepEqual(observation, {
            actualUpstreamRequests: 8,
            exactStreamedBytesAndQueryVerified: true,
            spoofedIdentityHeadersAbsent: true,
            releaseGate: false,
          });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualProxyRequests: 2,
            exactStreamedResponseBytes: 262144,
            verifiedUpstreamTls: true,
          });
          assert.equal(row.completion.checkedResponses, measured ? 120 : 0);
          if (measured) {
            assert.equal(row.completion.sampledGets, 100);
            assert.equal(row.completion.warmupGets, 20);
            assert.equal(row.completion.actualResponsePayloadBytes, 15728640);
            assert.equal(row.completion.responseIntegrityVerified, true);
            assert.equal(row.completion.peakRetainedReceipts, 120);
            assert.equal(row.completion.maximumRetainedReceipts, 128);
            assert.equal(row.completion.retainedResponseBuffers, 0);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'forwardedGet');
            assert.equal(record.sampleCount, 100);
            assert.equal(record.warmupIterations, 20);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, 100);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(row.resource.elapsedMs > 0);
          } else {
            assert.deepEqual(row.records, []);
            assert.equal(row.resource, null);
          }
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
        }
      }
      const unsupported = join(directory, 'unsupported');
      const unmarked = { ...process.env };
      delete unmarked.ARKENIVA_PROXY_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], {
          timeout: 5000,
          env: unmarked,
        }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
