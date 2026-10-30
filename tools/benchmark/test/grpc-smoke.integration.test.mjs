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
import { requireGrpcProcessTreeResource } from '../grpc-workload.mjs';

test(
  'Explicit gRPC unary smoke retains real mutual-TLS echo samples and independent protobuf receipt integrity',
  { timeout: 145000, skip: process.env.ARKENIVA_GRPC_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../grpc.mjs', import.meta.url)), '--smoke', output],
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
        /owned-grpc-private-value|arkenivajs-grpc-comparison-|127\.0\.0\.1|PRIVATE KEY/,
      );
      let unary = 0,
        callbacks = 0,
        streams = 0,
        streamedMessages = 0;
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0],
          observed = row.completion;
        assert.equal(measured.operation, 'mutual-tls-unary-bounce');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          observed.actualUnaryCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(observed.successfulUnaryEchoes, observed.actualUnaryCallbacks);
        assert.equal(
          observed.totalUnaryCalls,
          observed.verificationUnaryCalls + observed.successfulUnaryEchoes,
        );
        assert.equal(observed.verificationStreams, 1);
        assert.equal(observed.verificationStreamMessages, 3);
        assert.equal(observed.activeCallbacks, 0);
        assert.equal(observed.peakConcurrentCallbacks, 1);
        assert.equal(observed.retainedReceipts, 0);
        assert.equal(observed.serviceClosed, true);
        assert.match(observed.receiptDigest, /^[a-f0-9]{64}$/);
        requireGrpcProcessTreeResource(row.processTreeResource);
        unary += observed.totalUnaryCalls;
        callbacks += observed.actualUnaryCallbacks;
        streams += observed.verificationStreams;
        streamedMessages += observed.verificationStreamMessages;
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.equal(protocol.actualUnaryCalls, unary);
      assert.equal(protocol.actualStreamCalls, streams);
      assert.equal(protocol.actualStreamedMessages, streamedMessages);
      assert.equal(protocol.distinctFixtureReceipts, callbacks);
      assert.equal(protocol.independentReceiptIntegrity, true);
      assert.equal(protocol.activeHandlers, 0);
      assert.equal(protocol.activeBridgeRequests, 0);
      assert.equal(protocol.rejectedBridgeRequests, 0);
      assert.ok(protocol.peakBridgeRequests <= 4);
      assert.equal(protocol.releaseGate, false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
