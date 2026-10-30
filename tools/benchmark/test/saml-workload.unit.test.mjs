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
import { samlConnection } from '../saml-workload.mjs';

test('SAML comparison rejects foreign signing bridges and ambiguous transport before reading signing material', () => {
  for (const endpoint of [
    'http://127.0.0.1:1/response',
    'https://foreign.invalid:1/response',
    'https://u:p@127.0.0.1:1/response',
    'https://127.0.0.1:1/response?bypass=true',
  ])
    assert.throws(() => samlConnection({ endpoint, caFile: '/owned/ca' }));
});

test(
  'Four actual SAML profiles verify SP and IdP signatures, correlated identities, replay and audience rejection',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-harness-'));
    const script = fileURLToPath(new URL('../saml.mjs', import.meta.url));
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
        /synthetic-account|untrusted-tenant-hint|private-session-index|127\.0\.0\.1|BEGIN PRIVATE KEY/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        {
          actualVerifiedSignedRequests: 12,
          actualSignedResponses: 12,
          releaseGate: false,
        },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          signedMetadataVerified: true,
          actualSpSignaturesVerifiedByIdp: 3,
          signedIdentityVerified: true,
          replayRejected: true,
          tamperingAndWrongAudienceRejected: true,
          tenantHintNotTrusted: true,
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
