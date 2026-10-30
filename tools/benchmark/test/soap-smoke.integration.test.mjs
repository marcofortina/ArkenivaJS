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
import { requireSoapProcessTreeResource } from '../soap-workload.mjs';

test(
  'Explicit SOAP smoke measures verified ReadStock with independent decoded XML and receipt integrity',
  { timeout: 145000, skip: process.env.ARKENIVA_SOAP_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../soap.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        protocol = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-soap-private-sku|arkenivajs-soap-comparison-|127\.0\.0\.1/,
      );
      let calls = 0;
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0],
          observed = row.completion;
        assert.equal(measured.operation, 'read-stock-verified-https');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          observed.actualCallCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(observed.successfulDecodedCalls, observed.actualCallCallbacks);
        assert.equal(
          observed.totalCalls,
          observed.verificationCalls + observed.successfulDecodedCalls,
        );
        assert.deepEqual(observed.inputCounts, [observed.totalCalls / 2, observed.totalCalls / 2]);
        assert.equal(observed.distinctLocalCorrelations, observed.totalCalls);
        assert.equal(observed.distinctServerReceipts, observed.totalCalls);
        assert.equal(observed.activeCallbacks, 0);
        assert.equal(observed.peakConcurrentCallbacks, 1);
        assert.equal(observed.retainedReceipts, 0);
        assert.equal(observed.ownedWorkloadLeases, 0);
        assert.match(observed.receiptDigest, /^[a-f0-9]{64}$/);
        requireSoapProcessTreeResource(row.processTreeResource);
        calls += observed.totalCalls;
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.equal(protocol.actualNativeRequests, calls);
      assert.equal(protocol.decodedResponseCount, calls);
      assert.equal(protocol.independentReceiptIntegrity, true);
      assert.equal(protocol.activeRequests, 0);
      assert.equal(protocol.activeConnections, 0);
      assert.equal(protocol.failedRequests, 0);
      assert.ok(protocol.peakActiveRequests <= 4);
      assert.ok(protocol.peakConnections <= 4);
      assert.ok(protocol.observedRequestXmlBytes > 0);
      assert.ok(protocol.observedResponseXmlBytes > 0);
      assert.equal(protocol.releaseGate, false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
