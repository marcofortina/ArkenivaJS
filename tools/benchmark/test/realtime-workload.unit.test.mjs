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
import { realtimeSettings } from '../realtime-workload.mjs';
import { startRealtimeFixture } from '../realtime-fixture.mjs';

test('Realtime comparison rejects foreign issuer and ambiguous origins before listener creation', () => {
  for (const issuer of [
    'http://foreign.invalid:1',
    'https://127.0.0.1:1',
    'http://u:p@127.0.0.1:1',
    'http://127.0.0.1:1/another',
  ])
    assert.throws(() => realtimeSettings({ issuer }));
});

test('The independent realtime observer rejects unauthenticated, foreign-origin and unregistered reads before outbound effects', async () => {
  const authority = await startRealtimeFixture(true);
  try {
    for (const [key, method, args] of [
      ['invalid', 'register', ['http://127.0.0.1:1']],
      [authority.fixture.observerKey, 'register', ['http://foreign.invalid:1']],
      [authority.fixture.observerKey, 'register', ['http://user:pass@127.0.0.1:1']],
      [authority.fixture.observerKey, 'read', ['unknown']],
      [authority.fixture.observerKey, 'unapproved', []],
    ]) {
      const response = await globalThis.fetch(authority.fixture.observerUrl, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
        body: JSON.stringify({ method, args }),
        signal: AbortSignal.timeout(4000),
      });
      assert.equal(response.status, 400);
      await response.arrayBuffer();
      assert.deepEqual(authority.observations(), {
        registeredOwnedListeners: 0,
        observedStreams: 0,
        activeObserverSockets: 0,
        completedAuthorizations: 0,
      });
    }
  } finally {
    await authority.close();
  }
});

test(
  'Four actual realtime profiles preserve WebSocket and SSE controls and optionally sample independently consumed finite streams',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-realtime-harness-'));
    const script = fileURLToPath(new URL('../realtime.mjs', import.meta.url));
    try {
      const campaigns =
        process.env.ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE === '1'
          ? ['verify', 'smoke']
          : ['verify'];
      for (const campaign of campaigns) {
        const measured = campaign === 'smoke',
          output = join(directory, campaign);
        await promisify(execFile)(process.execPath, [script, '--' + campaign, output], {
          timeout: 150000,
          maxBuffer: 1048576,
          env: { ...process.env, ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE: '1' },
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
          /owned_realtime_message|synthetic-tenant|127\.0\.0\.1|Unicode: π/,
        );
        const observation = JSON.parse(
          await readFile(join(output, 'protocol-observation.json'), 'utf8'),
        );
        if (measured) {
          assert.equal(observation.actualJwksRequests, 5);
          assert.equal(observation.independentlyObservedHttpStreams, 480);
          assert.equal(observation.independentlyObservedSseEvents, 1440);
          assert.equal(observation.actualRuntimeAuthorizations, 480);
          assert.equal(observation.registeredOwnedListeners, 4);
          assert.equal(observation.activeObserverSockets, 0);
          assert.equal(observation.pendingObserverWork, 0);
          assert.equal(observation.maximumStreamsPerProfile, 120);
          assert.equal(
            observation.independentlyObservedUtf8Bytes,
            report.records.reduce((sum, row) => sum + row.completion.actualUtf8Bytes, 0),
          );
          for (const field of [
            'parentObserverResources',
            'parentAuthenticationResources',
            'parentIssuerResources',
          ])
            assert.equal(observation[field], null);
        } else assert.deepEqual(observation, { actualJwksRequests: 4, releaseGate: false });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            authenticatedWebSocketEcho: true,
            unauthenticatedTransportsRejected: true,
            unauthorizedTenantRejected: true,
            actualSseFrames: 3,
            exactUnicodeMultilineAndEmptyData: true,
            ownedResumeVerified: true,
            foreignUnknownAndExpiredCursorsRejected: true,
          });
          assert.equal(row.completion.checkedStreams, measured ? 120 : 0);
          assert.equal(row.completion.actualSourceSubscriptions, measured ? 122 : 2);
          assert.equal(
            row.completion.retiredSourceSubscriptions,
            row.completion.actualSourceSubscriptions,
          );
          assert.equal(row.completion.activeSourceSubscriptions, 0);
          assert.equal(row.completion.actualSourceEvents, measured ? 364 : 4);
          if (measured) {
            assert.equal(row.completion.sampledStreams, 100);
            assert.equal(row.completion.warmupStreams, 20);
            assert.equal(row.completion.actualEvents, 360);
            assert.equal(row.completion.independentlyVerifiedFrames, true);
            assert.equal(row.completion.peakRetainedReceipts, 120);
            assert.equal(row.completion.maximumRetainedReceipts, 128);
            assert.equal(row.completion.retainedEventBodies, 0);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'finiteSseResponse');
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
      delete unmarked.ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE;
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
