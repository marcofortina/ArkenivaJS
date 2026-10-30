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
import { oauthIterations, oauthWarmupIterations } from '../oauth-workload.mjs';

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
  'Verified and sampled OAuth profiles prove actual HTTPS machine grants, persisted SQL budget and private SDK exports',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-oauth-harness-')),
      script = fileURLToPath(new URL('../oauth.mjs', import.meta.url));
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
        const durable = JSON.parse(
          await readFile(join(output, 'durable-observation.json'), 'utf8'),
        );
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        const grants = report.records.reduce(
          (sum, row) =>
            sum + row.verification.authenticatedMachineGrants + row.completion.checkedGrants,
          0,
        );
        assert.equal(grants, 8 + (measured ? 4 * (oauthIterations + oauthWarmupIterations) : 0));
        for (const field of [
          'persistedGrants',
          'actualTokenRequests',
          'authorizedGrants',
          'persistedBudgetDelta',
          'committedBudgetWrites',
        ])
          assert.equal(durable[field], grants);
        assert.equal(durable.discoveryRequests, 4);
        assert.ok(durable.budgetRows >= 1 && durable.budgetRows <= 8);
        for (const field of [
          'interactiveAuthorizationRequests',
          'refreshRequests',
          'revocationRequests',
        ])
          assert.equal(durable[field], 0);
        for (const field of [
          'parentIssuerResources',
          'parentProviderResources',
          'postgresServerResources',
        ])
          assert.equal(durable[field], null);
        assert.match(durable.tokenValidationScope, /without opaque-token introspection/);
        assert.equal(durable.releaseGate, false);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(
          encoded + JSON.stringify(durable),
          /access\.|owned-oauth-tenant|owned-machine|https:\/\/127\.0\.0\.1/,
        );
        for (const row of report.records) {
          assert.equal(row.completion.sampledGrants, measured ? oauthIterations : 0);
          assert.equal(row.completion.warmupGrants, measured ? oauthWarmupIterations : 0);
          assert.equal(
            row.completion.checkedGrants,
            row.completion.sampledGrants + row.completion.warmupGrants,
          );
          for (const field of [
            'distinctTokens',
            'approvedScopeAndAudienceOnly',
            'finiteExpiryVerified',
            'refreshReferenceAbsent',
          ])
            assert.equal(row.completion[field], true);
          if (measured) {
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'clientCredentials');
            assert.equal(record.sampleCount, oauthIterations);
            assert.equal(record.warmupIterations, oauthWarmupIterations);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, record.sampleCount);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(record.throughputOpsPerSecond > 0);
            assert.ok(row.resource.elapsedMs > 0);
          } else {
            assert.equal(row.resource, null);
            assert.deepEqual(row.records, []);
          }
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
      }
      const rejected = join(directory, 'sample');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--full', rejected], {
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
