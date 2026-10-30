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
import { startOAuthFixture } from '../oauth-fixture.mjs';
import { nativeOAuth } from '../oauth-workload.mjs';

test(
  'OAuth fixture rejects an untrusted TLS issuer, missing provider credentials and foreign budget namespaces',
  { timeout: 15000 },
  async () => {
    const before = process.env.NODE_EXTRA_CA_CERTS,
      authority = await startOAuthFixture();
    try {
      await assert.rejects(nativeOAuth(authority.fixture));
      assert.equal(authority.issuerCounts.token, 0);
      for (const [bearer, method, args] of [
        ['', 'secret', ['client']],
        [authority.fixture.bearer, 'read', ['foreign.namespace', 'grant:1']],
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
      assert.equal(await authority.durableCount(), 0);
      assert.equal(authority.state.reads, 0);
      assert.equal(authority.state.authorizations, 0);
      assert.equal(process.env.NODE_EXTRA_CA_CERTS, before);
    } finally {
      await authority.close();
    }
    await assert.rejects(access(authority.trustAnchorFile), { code: 'ENOENT' });
  },
);

test(
  'Four OAuth profiles prove actual HTTPS machine grants, persisted SQL budget and private SDK exports',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-oauth-harness-')),
      script = fileURLToPath(new URL('../oauth.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      const durable = JSON.parse(await readFile(join(output, 'durable-observation.json'), 'utf8'));
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.deepEqual(durable, {
        persistedGrants: 8,
        actualTokenRequests: 8,
        authorizedGrants: 8,
        releaseGate: false,
      });
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /access\.|owned-oauth-tenant|owned-machine|https:\/\/127\.0\.0\.1/,
      );
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          authenticatedMachineGrants: 2,
          distinctTokens: true,
          finiteExpiryVerified: true,
          approvedScopeOnly: true,
          refreshReferenceAbsent: true,
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
