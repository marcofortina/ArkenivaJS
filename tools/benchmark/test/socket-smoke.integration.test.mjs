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

test(
  'Sampled TCP profiles reconcile independent client lifecycles with actual listener counters',
  { timeout: 145000, skip: process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.scenarios.length, 5);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.unixPathRemoved, true);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'tcp64IndependentClient');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.values.length, 100);
        assert.equal(value.sampledEchoes, 100);
        assert.equal(value.warmupEchoes, 20);
        assert.equal(value.checkedEchoes, 120);
        assert.equal(value.independentClientProcessesWaited, 120);
        assert.equal(value.acceptedConnections, 120);
        assert.equal(value.receivedApplicationBytes, 7680);
        assert.equal(value.sentApplicationBytes, 7680);
        assert.equal(value.listenerClosed, true);
        assert.equal(value.opaqueKernelBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.receivedBytes, 64);
          assert.equal(measurement.byteIdentityVerified, true);
          assert.ok(measurement.firstByteMs >= 0);
          assert.ok(measurement.exchangeElapsedMs >= measurement.firstByteMs);
        }
        const resource = row.processTreeResource;
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
