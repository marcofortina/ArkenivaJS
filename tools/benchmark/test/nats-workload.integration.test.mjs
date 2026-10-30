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
import { connectNats } from '../nats-workload.mjs';

test(
  'Native NATS comparison verifies the healthy mutual-TLS fixture before rejecting its wrong-SAN peer',
  { timeout: 15000 },
  async () => {
    assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
    assert.ok(process.env.ARKENIVA_NATS_WRONG_SAN_URL);
    const healthy = await connectNats({ url: process.env.ARKENIVA_NATS_URL });
    try {
      await healthy.flush();
    } finally {
      await healthy.drain();
    }
    await assert.rejects(connectNats({ url: process.env.ARKENIVA_NATS_WRONG_SAN_URL }));
  },
);

test(
  'Four NATS profiles verify exact actual wire envelopes in both directions without inventing broker acknowledgment',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-nats-harness-'));
    const script = fileURLToPath(new URL('../nats.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 20000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8');
      const report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(encoded, /owned-nats-private-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          nativeToServiceVerified: true,
          serviceToNativeVerified: true,
          actualMessagesObserved: 2,
          exactEnvelopeVerified: true,
          correlationPreserved: true,
          inventedTenantAbsent: true,
          acknowledged: false,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--verify', join(directory, 'untrusted')], {
          env: { ...process.env, ARKENIVA_NATS_URL: process.env.ARKENIVA_NATS_WRONG_SAN_URL },
          timeout: 10000,
          maxBuffer: 1048576,
        }),
      );
      const unsupported = join(directory, 'unsupported'),
        env = { ...process.env };
      delete env.ARKENIVA_NATS_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], {
          env,
          timeout: 5000,
        }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'Explicit Core NATS smoke retains real flush-plus-dual-observation samples and retires all owned subscriptions',
  { timeout: 135000, skip: process.env.ARKENIVA_NATS_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-nats-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../nats.mjs', import.meta.url)), '--smoke', output],
        { timeout: 130000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /owned-nats-private-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0],
          observed = row.completion;
        assert.equal(measured.operation, 'publish-flush-and-dual-observed-receipt');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          observed.actualPublicationCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(observed.completedPublications, observed.actualPublicationCallbacks);
        assert.equal(observed.nativeObservedDeliveries, observed.actualPublicationCallbacks);
        assert.equal(observed.serviceHandlerDeliveries, observed.actualPublicationCallbacks);
        assert.equal(observed.unacknowledgedReceipts, observed.actualPublicationCallbacks);
        assert.ok(observed.observedEnvelopeBytes > 0);
        assert.equal(observed.activeCallbacks, 0);
        assert.equal(observed.pendingReceipts, 0);
        assert.equal(observed.ownedSubscriptions, 0);
        assert.equal(observed.independentConnections, 0);
        assert.equal(observed.peakConcurrentCallbacks, 1);
        assert.equal(observed.acknowledged, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
