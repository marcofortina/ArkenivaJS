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
import { startWebhookFixture } from '../webhooks-fixture.mjs';

test('Owned webhook provider bridge rejects missing credentials and foreign claim namespaces', async () => {
  const authority = await startWebhookFixture();
  try {
    for (const [bearer, method, args] of [
      ['', 'secret', ['current']],
      [
        authority.fixture.bearer,
        'claimOnce',
        ['foreign.namespace', 'a'.repeat(64), new Date(Date.now() + 60000).toISOString()],
      ],
    ]) {
      const response = await globalThis.fetch(authority.fixture.endpoint, {
        method: 'POST',
        headers: { 'x-owned-provider': bearer, 'content-type': 'application/json' },
        body: JSON.stringify({ method, args }),
        signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 500);
      assert.deepEqual(await response.json(), {});
    }
    assert.equal(authority.state.secretReads, 0);
    assert.equal(await authority.durableCount(), 0);
  } finally {
    await authority.close();
  }
});

test(
  'Four webhook profiles prove actual SQL nonce claims, native signatures, byte fidelity and export privacy',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-webhook-harness-')),
      script = fileURLToPath(new URL('../webhooks.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        durable = JSON.parse(await readFile(join(output, 'durable-observation.json'), 'utf8'));
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.deepEqual(durable, { persistedClaims: 4, claimAttempts: 8, releaseGate: false });
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /owned-webhook-private-payload|owned-comparison-tenant|owned-receiver/,
      );
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          nativeSignatureMatched: true,
          unchangedBytesVerified: true,
          reserializedBodyRejected: true,
          replayRejected: true,
          parsedEventVerified: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const rejected = join(directory, 'sample'),
        env = { ...process.env };
      delete env.ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          env,
          timeout: 5000,
          maxBuffer: 1048576,
        }),
      );
      await assert.rejects(access(rejected), { code: 'ENOENT' });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Explicit webhook smoke retains actual paired samples with independently persisted one-use SQL claims',
  { timeout: 120000, skip: process.env.ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-webhook-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../webhooks.mjs', import.meta.url)), '--smoke', output],
        { timeout: 115000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        durable = JSON.parse(await readFile(join(output, 'durable-observation.json'), 'utf8'));
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-webhook-private-payload|owned-comparison-tenant|owned-receiver/,
      );
      let paired = 0,
        accepted = 0,
        attempted = 0,
        authorizations = 0,
        secretReads = 0,
        replayDenials = 0;
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0];
        assert.equal(measured.operation, 'sign-and-durable-verify');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          row.completion.actualPairedCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(
          row.completion.successfulPairedVerifications,
          row.completion.actualPairedCallbacks,
        );
        assert.equal(row.completion.finalReplayDenials, 1);
        paired += row.completion.actualPairedCallbacks;
        accepted += row.completion.expectedAcceptedClaims;
        attempted += row.completion.expectedClaimAttempts;
        authorizations += row.completion.expectedAuthorizations;
        secretReads += row.completion.expectedSecretReads;
        replayDenials += row.completion.finalReplayDenials;
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.deepEqual(durable, {
        persistedClaims: accepted,
        claimAttempts: attempted,
        releaseGate: false,
        measured: true,
        componentScope: 'paired-sign-and-durable-verify',
        actualPairedCallbacks: paired,
        successfulPairedVerifications: paired,
        finalReplayDenials: replayDenials,
        authorizations,
        secretReads,
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
