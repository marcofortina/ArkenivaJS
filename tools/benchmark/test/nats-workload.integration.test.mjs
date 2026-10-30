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
