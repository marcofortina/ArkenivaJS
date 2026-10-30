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
import { sessionsIterations, sessionsWarmupIterations } from '../sessions-workload.mjs';

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
  'Verified and sampled session profiles reconcile raw latency with actual SQL state, authority and activity HMACs',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sessions-harness-'));
    const script = fileURLToPath(new URL('../sessions.mjs', import.meta.url));
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
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /ss1\.[0-9a-f-]{36}\.|127\.0\.0\.1/);
        const durable = JSON.parse(
          await readFile(join(output, 'durable-observation.json'), 'utf8'),
        );
        assert.equal(durable.persistedRefreshedSessions, 4);
        const actualValidations = report.records.reduce(
          (sum, row) => sum + row.completion.successfulValidations,
          0,
        );
        assert.ok(
          durable.committedActivityUpdates >= 4 &&
            durable.committedActivityUpdates <= actualValidations,
        );
        assert.equal(durable.originalAuthenticationAndMfaTimesPreserved, true);
        assert.equal(durable.persistedHmacsVerified, true);
        assert.equal(durable.releaseGate, false);
        assert.equal(durable.observation.successfulValidations, actualValidations);
        assert.equal(durable.observation.rejectedWrongSecrets, 4);
        assert.equal(durable.observation.persistedAttemptDelta, actualValidations + 4);
        assert.ok(durable.observation.persistedAttemptRows > 0);
        assert.equal(durable.observation.protocol.resolved, actualValidations);
        assert.equal(durable.observation.protocol.authorized, actualValidations);
        assert.equal(durable.observation.protocol.epochs, 2 * actualValidations);
        assert.equal(durable.observation.protocol.verified, actualValidations + 4);
        assert.equal(durable.observation.protocol.providerFailures, 0);
        if (measured) {
          assert.equal(durable.parentCampaignResource.postgresServerResources, null);
          assert.equal(durable.parentCampaignResource.releaseGate, false);
          assert.ok(durable.parentCampaignResource.elapsedMs > 0);
          assert.ok(durable.parentCampaignResource.cpuDeltaMicros.user >= 0);
          assert.ok(durable.parentCampaignResource.cpuDeltaMicros.system >= 0);
          assert.match(
            durable.parentCampaignResource.scope,
            /not attributable to individual profiles/,
          );
        } else assert.equal(durable.parentCampaignResource, undefined);
        assert.doesNotMatch(JSON.stringify(durable), /ss1\.[0-9a-f-]{36}\.|127\.0\.0\.1/);
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualValidationsVerified: 2,
            wrongSecretRejected: true,
            originalAuthenticationTimePreserved: true,
            originalMfaTimePreserved: true,
            assuranceUnchanged: true,
            idleRefreshVerified: true,
          });
          assert.equal(row.completion.sampledValidations, measured ? sessionsIterations : 0);
          assert.equal(row.completion.warmupValidations, measured ? sessionsWarmupIterations : 0);
          assert.equal(
            row.completion.successfulValidations,
            2 + row.completion.sampledValidations + row.completion.warmupValidations,
          );
          if (measured) {
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'validate');
            assert.equal(record.sampleCount, sessionsIterations);
            assert.equal(record.warmupIterations, sessionsWarmupIterations);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, record.sampleCount);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(record.throughputOpsPerSecond > 0);
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
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--full', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
