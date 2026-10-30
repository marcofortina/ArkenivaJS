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
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import { startMagiclinkFixture } from '../magiclink-fixture.mjs';
import { nativeMagiclink, magiclinkPorts, magiclinkSettings } from '../magiclink-workload.mjs';

test(
  'Actual magic-link providers fail closed without consuming SQL state and production rejects test-only ports',
  { timeout: 30000 },
  async () => {
    const authority = await startMagiclinkFixture();
    let app, production;
    try {
      const settings = magiclinkSettings(authority.fixture);
      app = await createApplication({
        service: { name: 'magiclink-comparison-test', version: '1.0.0', environment: 'test' },
        logging: { level: 'silent' },
        plugins: [loggingPlugin(), magicLinksPlugin(settings)],
      });
      await app.start();
      const denied = await globalThis.fetch(authority.fixture.endpoint, {
        method: 'POST',
        headers: { authorization: 'Bearer invalid' },
        body: JSON.stringify({ method: 'grant', args: [] }),
      });
      assert.equal(denied.status, 400);
      await denied.arrayBuffer();
      let consumed = 0;
      for (const service of [
        nativeMagiclink(authority.fixture),
        app.resolve(MAGICLINK_CAPABILITY),
      ]) {
        const grant = await magiclinkPorts(authority.fixture).exchange('grant', []);
        const context = { method: 'POST', purpose: 'login' };
        for (const fault of ['store', 'hmac', 'authority']) {
          authority.fault(fault, true);
          try {
            await assert.rejects(service.consume(grant.token, context));
            assert.equal((await authority.verify(consumed)).persistedConsumedLinks, consumed);
          } finally {
            authority.fault(fault, false);
          }
        }
        assert.equal((await service.consume(grant.token, context)).intent, 'login');
        consumed++;
        await assert.rejects(service.consume(grant.token, context));
        assert.equal((await authority.verify(consumed)).persistedConsumeQuota, consumed);
      }
      production = await createApplication({
        service: {
          name: 'magiclink-production-rejection',
          version: '1.0.0',
          environment: 'production',
        },
        logging: { level: 'silent' },
        plugins: [loggingPlugin(), magicLinksPlugin(settings)],
      });
      await assert.rejects(production.start());
      assert.equal((await authority.verify(2)).committedAtomicBatches, 2);
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
  'Four magic-link profiles verify concurrent redemption and optionally sample bounded public issuance plus exact durable consumption',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-magiclink-harness-'));
    const script = fileURLToPath(new URL('../magiclink.mjs', import.meta.url));
    try {
      for (const campaign of ['verify', 'smoke']) {
        const measured = campaign === 'smoke';
        const output = join(directory, campaign);
        await promisify(execFile)(process.execPath, [script, '--' + campaign, output], {
          timeout: 150000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8');
        const report = JSON.parse(encoded);
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /ml1\.[0-9a-f-]{36}\.|127\.0\.0\.1/);
        const observation = JSON.parse(
          await readFile(join(output, 'durable-observation.json'), 'utf8'),
        );
        if (measured) {
          assert.equal(observation.persistedConsumedLinks, 484);
          assert.equal(observation.persistedConsumeQuota, 484);
          assert.equal(observation.committedAtomicBatches, 484);
          for (const field of [
            'sampledIssueRequests',
            'independentlyCheckedSampleLinks',
            'independentlyObservedHmacVerifications',
            'independentlyObservedConsumeAuthorizations',
            'uniqueNonceCount',
            'independentReplayRejections',
          ])
            assert.equal(observation[field], 480);
          assert.equal(observation.sampledOwnerCount, 8);
          assert.equal(observation.maximumIssueAndConsumePerSampleOwner, 60);
          assert.equal(observation.configuredClaimsPerHour, 64);
          assert.equal(observation.mailDeliveries, 0);
          for (const field of [
            'parentIssuerResources',
            'parentProviderResources',
            'postgresServerResources',
          ])
            assert.equal(observation[field], null);
        } else
          assert.deepEqual(observation, {
            persistedConsumedLinks: 4,
            persistedConsumeQuota: 4,
            committedAtomicBatches: 4,
            releaseGate: false,
          });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualConsumeVerified: true,
            concurrentWinnerCount: 1,
            concurrentLoserCount: 1,
            replayRejected: true,
            getPrefetchRejected: true,
            wrongPurposeRejected: true,
          });
          assert.equal(row.completion.checkedConsumptions, measured ? 120 : 0);
          if (measured) {
            assert.equal(row.completion.sampledLinks, 100);
            assert.equal(row.completion.warmupLinks, 20);
            assert.equal(row.completion.verifiedOwnerAndIntent, true);
            assert.equal(row.completion.uniqueIssueIds, true);
            assert.equal(row.completion.peakRetainedResults, 120);
            assert.equal(row.completion.maximumRetainedResults, 128);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'issueAndConsume');
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
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--full', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
