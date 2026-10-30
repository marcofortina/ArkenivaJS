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
import { loggingPlugin } from '@arkenivajs/logging';
import { sessionsPlugin, SESSIONS_CAPABILITY } from '@arkenivajs/security-sessions';
import { startSessionsFixture } from '../sessions-fixture.mjs';
import { nativeSessions, sessionsPorts, sessionsSettings } from '../sessions-workload.mjs';

test(
  'Actual session providers fail closed, owner epochs revoke valid tokens and production rejects test-only ports',
  { timeout: 30000 },
  async () => {
    const authority = await startSessionsFixture();
    let app, production;
    try {
      const settings = sessionsSettings(authority.fixture);
      app = await createApplication({
        service: { name: 'sessions-comparison-test', version: '1.0.0', environment: 'test' },
        logging: { level: 'silent' },
        plugins: [loggingPlugin(), sessionsPlugin(settings)],
      });
      await app.start();
      const denied = await globalThis.fetch(authority.fixture.endpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer invalid' },
        body: JSON.stringify({ method: 'grant', args: [] }),
      });
      assert.equal(denied.status, 400);
      await denied.arrayBuffer();
      let refreshed = 0;
      const clients = [];
      for (const service of [
        await nativeSessions(authority.fixture),
        app.resolve(SESSIONS_CAPABILITY),
      ]) {
        const grant = await sessionsPorts(authority.fixture).exchange('grant', []);
        for (const fault of ['store', 'hmac', 'authority']) {
          authority.fault(fault, true);
          try {
            await assert.rejects(service.validate(grant.token));
            assert.equal((await authority.verify(refreshed)).persistedRefreshedSessions, refreshed);
          } finally {
            authority.fault(fault, false);
          }
        }
        const identity = await service.validate(grant.token);
        refreshed++;
        assert.equal(identity.authenticatedAt, grant.authenticatedAt);
        assert.equal(identity.assuredAt, grant.assuredAt);
        assert.equal(identity.assurance, 'mfa');
        clients.push({ service, grant });
        assert.equal((await authority.verify(refreshed)).persistedRefreshedSessions, refreshed);
      }
      await authority.revokeOwner();
      for (const { service, grant } of clients) await assert.rejects(service.validate(grant.token));
      production = await createApplication({
        service: {
          name: 'sessions-production-rejection',
          version: '1.0.0',
          environment: 'production',
        },
        logging: { level: 'silent' },
        plugins: [loggingPlugin(), sessionsPlugin(settings)],
      });
      await assert.rejects(production.start());
      assert.equal((await authority.verify(2)).persistedRefreshedSessions, 2);
    } finally {
      try {
        const closed = await Promise.allSettled([production?.stop(), app?.stop()]);
        assert.ok(closed.every((result) => result.status === 'fulfilled'));
      } finally {
        await authority.close();
      }
    }
  },
);

test(
  'Four session profiles preserve original MFA time while validating actual SQL state and activity HMACs',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sessions-harness-'));
    const script = fileURLToPath(new URL('../sessions.mjs', import.meta.url));
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
      assert.doesNotMatch(encoded, /ss1\.[0-9a-f-]{36}\.|127\.0\.0\.1/);
      const durable = JSON.parse(await readFile(join(output, 'durable-observation.json'), 'utf8'));
      assert.equal(durable.persistedRefreshedSessions, 4);
      assert.ok(durable.committedActivityUpdates >= 4 && durable.committedActivityUpdates <= 8);
      assert.equal(durable.originalAuthenticationAndMfaTimesPreserved, true);
      assert.equal(durable.persistedHmacsVerified, true);
      assert.equal(durable.releaseGate, false);
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          actualValidationsVerified: 2,
          wrongSecretRejected: true,
          originalAuthenticationTimePreserved: true,
          originalMfaTimePreserved: true,
          assuranceUnchanged: true,
          idleRefreshVerified: true,
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
