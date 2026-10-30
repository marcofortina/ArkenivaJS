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
import { createApplication } from '@arkenivajs/core';
import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import { startMtlsFixture } from '../mtls-fixture.mjs';
import { mtlsConnection, mtlsSettings, nativeMtls, verifyMtls } from '../mtls-workload.mjs';

test('mTLS comparison rejects foreign origins and unowned trust bridges before accessing material', () => {
  const fixture = { endpoint: 'https://localhost:1', bridgeUrl: 'http://127.0.0.1:1/verify' };
  for (const endpoint of [
    'http://localhost:1',
    'https://foreign.invalid:443',
    'https://localhost:1/path',
    'https://u:p@localhost:1',
  ])
    assert.throws(() => mtlsConnection({ ...fixture, endpoint }));
  for (const bridgeUrl of [
    'http://foreign.invalid:1/verify',
    'http://u:p@127.0.0.1:1/verify',
    'http://127.0.0.1:1/verify?bypass=true',
  ])
    assert.throws(() => mtlsConnection({ ...fixture, bridgeUrl }));
});

test(
  'Actual native and public mutual TLS fail closed on trust-bridge denial, revocation outage and a revoked server',
  { timeout: 30000 },
  async () => {
    const authority = await startMtlsFixture(),
      apps = [];
    const application = async (fixture, environment = 'test') => {
      const app = await createApplication({
        service: { name: 'mtls-comparison-test', version: '1.0.0', environment },
        plugins: [mtlsPlugin(mtlsSettings(fixture))],
      });
      apps.push(app);
      await app.start();
      return app.resolve(MTLS_CAPABILITY);
    };
    try {
      const fixture = authority.fixture,
        actual = await application(fixture);
      for (const service of [nativeMtls(fixture), actual])
        assert.equal((await verifyMtls(service, fixture)).actualMutualTlsHandshake, true);
      assert.equal(authority.verify(2).actualAuthorizedHttp2Requests, 2);
      const deniedFixture = { ...fixture, bearer: 'invalid' },
        denied = await application(deniedFixture);
      for (const service of [nativeMtls(deniedFixture), denied])
        await assert.rejects(verifyMtls(service, deniedFixture));
      assert.equal(authority.observations().applicationRequests, 2);
      authority.unavailable(true);
      for (const service of [nativeMtls(fixture), actual])
        await assert.rejects(verifyMtls(service, fixture));
      assert.equal(authority.observations().applicationRequests, 2);
      authority.unavailable(false);
      await authority.revokeServer();
      for (const service of [nativeMtls(fixture), actual])
        await assert.rejects(verifyMtls(service, fixture));
      assert.equal(authority.observations().applicationRequests, 2);
      await assert.rejects(application(fixture, 'production'));
    } finally {
      const results = await Promise.allSettled(apps.map((app) => app.stop()));
      await authority.close();
      assert.ok(results.every((result) => result.status === 'fulfilled'));
    }
  },
);

test(
  'Four actual mTLS profiles verify peer policy and optionally sample fresh non-resumed exchanges before physical closure',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mtls-harness-'));
    const script = fileURLToPath(new URL('../mtls.mjs', import.meta.url));
    try {
      const campaigns =
        process.env.ARKENIVA_MTLS_BENCHMARK_DISPOSABLE === '1' ? ['verify', 'smoke'] : ['verify'];
      for (const campaign of campaigns) {
        const measured = campaign === 'smoke';
        const output = join(directory, campaign);
        await promisify(execFile)(process.execPath, [script, '--' + campaign, output], {
          timeout: 150000,
          maxBuffer: 1048576,
          env: { ...process.env, ARKENIVA_MTLS_BENCHMARK_DISPOSABLE: '1' },
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
          /owned-mtls-private-response|spiffe:\/\/fixture|127\.0\.0\.1|BEGIN PRIVATE KEY/,
        );
        const observation = JSON.parse(
          await readFile(join(output, 'protocol-observation.json'), 'utf8'),
        );
        if (measured) {
          for (const field of [
            'actualAuthorizedHttp2Requests',
            'actualClientPeerCrlChecks',
            'actualServerPeerCrlChecks',
            'independentlyObservedFreshTls13Sessions',
          ])
            assert.equal(observation[field], 484);
          for (const field of ['resumedTlsSessions', 'activeSessions', 'pendingProviderWork'])
            assert.equal(observation[field], 0);
          for (const field of [
            'parentServerResources',
            'parentPkiProviderResources',
            'parentOpenSslDescendantResources',
          ])
            assert.equal(observation[field], null);
        } else
          assert.deepEqual(observation, {
            actualAuthorizedHttp2Requests: 4,
            actualClientPeerCrlChecks: 4,
            actualServerPeerCrlChecks: 4,
            releaseGate: false,
          });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualMutualTlsHandshake: true,
            negotiatedHttp2: true,
            asynchronousPeerCrlVerifiedBeforeRequest: true,
            actualAuthorizedResponse: true,
          });
          assert.equal(row.completion.checkedExchanges, measured ? 120 : 0);
          if (measured) {
            assert.equal(row.completion.sampledHandshakes, 100);
            assert.equal(row.completion.warmupHandshakes, 20);
            assert.equal(row.completion.freshNonResumedTls13, true);
            assert.equal(row.completion.physicalSessionsClosed, true);
            assert.equal(row.completion.peakRetainedResults, 120);
            assert.equal(row.completion.maximumRetainedResults, 128);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'freshHandshake');
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
      delete unmarked.ARKENIVA_MTLS_BENCHMARK_DISPOSABLE;
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
