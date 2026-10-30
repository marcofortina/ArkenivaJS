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
  'Four AMQP profiles verify actual confirms, mandatory returns, exact binary delivery and owned topology retirement',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-amqp-harness-'));
    const script = fileURLToPath(new URL('../amqp.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8');
      const report = JSON.parse(encoded);
      assert.equal(report.measured, false);
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
