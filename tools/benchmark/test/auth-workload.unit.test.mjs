// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { createIssuer } from '../http-issuer.mjs';
import { nativeAuth, verifyAuth, authConnection } from '../auth-workload.mjs';

test(
  'Actual native and public JWT verification rejects forged provenance and never upgrades signed claims to MFA',
  { timeout: 15000 },
  async () => {
    const issuer = await createIssuer();
    let app, actual, tenant;
    try {
      const claims = { tenant_id: 'owned-auth-test-tenant', scope: 'owned:comparison' };
      const token = await issuer.token({ claims }),
        parts = token.split('.');
      parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
      const fixture = {
        issuer: issuer.origin,
        audience: issuer.audience,
        token,
        tenant: claims.tenant_id,
        scope: claims.scope,
        invalidTokens: [
          parts.join('.'),
          await issuer.token({ issuer: 'https://foreign.invalid', claims }),
          await issuer.token({ audience: 'api://foreign', claims }),
          await issuer.token({ expiration: '-1h', claims }),
        ],
      };
      assert.throws(() => authConnection({ issuer: 'http://foreign.invalid:1' }));
      app = await createApplication({
        service: { name: 'auth-comparison-test', version: '1.0.0', environment: 'test' },
        logging: { level: 'silent' },
        security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
        plugins: [
          loggingPlugin(),
          securityPlugin({
            jwksUrl: fixture.issuer + '/keys',
            allowInsecureLoopback: true,
            clockToleranceSeconds: 0,
            authorizeTenant: (_identity, value) => value === fixture.tenant,
          }),
        ],
      });
      await app.start();
      actual = app.resolve(COMPONENTS.auth);
      for (const service of [nativeAuth(fixture), actual])
        assert.equal((await verifyAuth(service, fixture)).actualSignatureAndClaimsVerified, true);
      const identity = await actual.verifyBearer('Bearer ' + token);
      assert.throws(() => actual.requireScope({ ...identity }, fixture.scope));
      assert.throws(() => actual.tenantFrom({ ...identity }));
      tenant = actual.tenantFrom(identity);
      assert.equal(actual.isVerifiedTenant(tenant), true);
      assert.equal(actual.isVerifiedTenant({ ...tenant }), false);
      const assuranceToken = await issuer.token({
        claims: { ...claims, assurance: 'phishing-resistant', acr: 'claimed-mfa' },
      });
      const unassured = await actual.verifyBearer('Bearer ' + assuranceToken);
      assert.throws(() => actual.requireAssurance(unassured, 'mfa'));
    } finally {
      try {
        await app?.stop();
        if (tenant) assert.equal(actual.isVerifiedTenant(tenant), false);
      } finally {
        await issuer.close();
      }
    }
  },
);

test(
  'Four JWT profiles verify actual crypto counters and sampled bearer calls without fabricated SDK instruments',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-auth-harness-'));
    const script = fileURLToPath(new URL('../auth.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 20000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(report.collector.receivedBodies, 0);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-auth-private-tenant|synthetic-user|127\.0\.0\.1/);
        assert.deepEqual(
          JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
          { actualJwksRequests: 4, releaseGate: false },
        );
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualSignatureAndClaimsVerified: true,
            issuerAudienceAndExpiryRejected: true,
            tamperedSignatureRejected: true,
            scopePolicyVerified: true,
            authenticatedTenantResolved: true,
          });
          assert.equal(row.completion.actualRejectedVerifications, 4);
          assert.equal(row.completion.observerFailures, 0);
          assert.equal(
            row.completion.actualSuccessfulVerifications,
            1 +
              row.records.reduce(
                (sum, record) => sum + record.sampleCount + record.warmupIterations,
                0,
              ),
          );
          assert.equal(row.records.length, mode === '--smoke' ? 1 : 0);
          if (mode === '--verify') assert.equal(row.resource, null);
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) {
            assert.equal(row.quality.instruments, 0);
            assert.equal(row.quality.spansStarted, 0);
            assert.equal(row.quality.metricSeries, 0);
          }
          for (const operation of row.records) {
            assert.equal(operation.operation, 'verifyBearer');
            assert.ok(operation.sampleCount >= 1000);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
