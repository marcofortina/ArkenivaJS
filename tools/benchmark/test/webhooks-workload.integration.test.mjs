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
      const rejected = join(directory, 'sample');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
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
