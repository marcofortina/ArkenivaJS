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
import { connectAmqp } from '../amqp-workload.mjs';
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Native AMQPS comparison verifies a healthy authenticated connection before rejecting the wrong hostname',
  { timeout: 15000 },
  async () => {
    const metadata = JSON.parse(await readFile(process.env.ARKENIVA_AMQP_FIXTURE, 'utf8'));
    assert.match(metadata.container, /^arkenivajs-amqp-[a-z0-9_-]+$/);
    const fixture = { url: metadata.uris.service, caFile: metadata.caFile };
    const healthy = await connectAmqp(fixture);
    await healthy.close();
    await assert.rejects(connectAmqp(fixture, true));
  },
);

test(
  'Four AMQP profiles verify and measure actual publisher confirms with independent exact message readback and topology retirement',
  { timeout: 60000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-amqp-harness-'));
    const script = fileURLToPath(new URL('../amqp.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 40000,
          maxBuffer: 1048576,
          env: { ...process.env, ARKENIVA_AMQP_BENCHMARK_DISPOSABLE: '1' },
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8');
        const report = JSON.parse(encoded);
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-amqp-private-body|fixture\.comparison\.|127\.0\.0\.1/);
        assert.deepEqual(
          JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
          {
            ownedMessagesRemaining: 0,
            ownedConsumersRemaining: 0,
            ownedResourcesRemoved: true,
            releaseGate: false,
          },
        );
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            nativeToServiceVerified: true,
            serviceToNativeVerified: true,
            exactHeadersAndBodyVerified: true,
            brokerConfirmObserved: true,
            mandatoryReturnObserved: true,
            queuesDrained: true,
            inventedTenantAbsent: true,
          });
          assert.deepEqual(row.completion, {
            workloadPublications: mode === '--smoke' ? 120 : 0,
            measuredPublications: mode === '--smoke' ? 100 : 0,
            warmupPublications: mode === '--smoke' ? 20 : 0,
            confirmedPublications: mode === '--smoke' ? 120 : 0,
            independentlyReadMessages: mode === '--smoke' ? 120 : 0,
            independentlyReadBytes: mode === '--smoke' ? 122880 : 0,
          });
          if (mode === '--smoke') {
            assert.equal(row.records.length, 1);
            const [record] = row.records;
            assert.equal(record.operation, 'publishConfirmed');
            assert.equal(record.sampleCount, 100);
            assert.equal(record.warmupIterations, 20);
            assertRawLatencySamples(record);
            assert.ok(row.resource.elapsedMs > 0);
            assert.ok(row.resource.memoryBytes.peakRss > 0);
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
