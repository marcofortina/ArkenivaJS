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
import { realtimeSettings } from '../realtime-workload.mjs';

test('Realtime comparison rejects foreign issuer and ambiguous origins before listener creation', () => {
  for (const issuer of [
    'http://foreign.invalid:1',
    'https://127.0.0.1:1',
    'http://u:p@127.0.0.1:1',
    'http://127.0.0.1:1/another',
  ])
    assert.throws(() => realtimeSettings({ issuer }));
});

test(
  'Four actual realtime profiles preserve authenticated native WebSocket and SSE protocols without trusting forged tenants',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-realtime-harness-'));
    const script = fileURLToPath(new URL('../realtime.mjs', import.meta.url));
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
      assert.doesNotMatch(
        encoded,
        /owned_realtime_message|synthetic-tenant|127\.0\.0\.1|Unicode: π/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { actualJwksRequests: 4, releaseGate: false },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          authenticatedWebSocketEcho: true,
          unauthenticatedTransportsRejected: true,
          unauthorizedTenantRejected: true,
          actualSseFrames: 3,
          exactUnicodeMultilineAndEmptyData: true,
          ownedResumeVerified: true,
          foreignUnknownAndExpiredCursorsRejected: true,
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
