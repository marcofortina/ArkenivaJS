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
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'Four supervised SAML profiles verify every signed Redirect creation without sending measured IdP requests',
  { timeout: 145000, skip: process.env.ARKENIVA_SAML_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../saml.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-saml-correlation-|SAMLRequest|RelayState|AuthnRequest|synthetic-account|untrusted-tenant-hint|BEGIN PRIVATE KEY|127\.0\.0\.1/,
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
        assert.equal(row.verification.signedMetadataVerified, true);
        assert.equal(row.verification.actualSpSignaturesVerifiedByIdp, 3);
        assert.equal(row.verification.signedIdentityVerified, true);
        assert.equal(row.verification.replayRejected, true);
        assert.equal(row.verification.tamperingAndWrongAudienceRejected, true);
        assert.equal(row.verification.tenantHintNotTrusted, true);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'signedRedirectCreation');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assertRawLatencySamples(record);
        assert.equal(value.sampledCreations, 100);
        assert.equal(value.warmupCreations, 20);
        assert.equal(value.verifiedSignedCreations, 120);
        assert.equal(value.uniqueCorrelationsVerified, 120);
        assert.ok(value.signedQueryBytes > 0 && value.requestXmlBytes > 0);
        assert.equal(value.retainedCorrelationIdentifiers, 0);
        assert.equal(value.actualMeasuredIdpRequests, 0);
        assert.equal(value.durableReplayStore, false);
        const resource = row.processTreeResource;
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality)
          for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'])
            assert.equal(row.quality[key], 0);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
