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
import { sftpSampleBytes, sftpPressureBytes } from '../sftp-workload.mjs';

test(
  'Explicit SFTP smoke proves actual streamed bytes, passive SDK pressure and independent remote cleanup',
  { timeout: 145000, skip: process.env.ARKENIVA_SFTP_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sftp-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../sftp.mjs', import.meta.url)), '--smoke', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        protocol = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.inputs.clientTcpNoDelay, true);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(
        encoded,
        /owned-sftp-private-content|owned-ssh-literal|BEGIN OPENSSH PRIVATE KEY|owned-comparison-/,
      );
      assert.equal(protocol.ownedFilesRemaining, 0);
      assert.equal(protocol.releaseGate, false);
      assert.equal(protocol.externalServerResourcesIncluded, false);
      assert.equal(protocol.independentReadbacks.length, 4);
      assert.deepEqual(
        protocol.independentReadbacks.map((value) => value.bytes),
        [sftpSampleBytes, sftpPressureBytes, sftpSampleBytes, sftpPressureBytes],
      );
      for (const value of protocol.independentReadbacks) {
        assert.equal(value.digestVerified, true);
        assert.equal(value.nativeHandleClosed, true);
      }
      for (const row of report.records) {
        assert.equal(row.verification.awaitedDownloadVerified, true);
        assert.equal(row.verification.literalCommandVerified, true);
        assert.equal(row.records.length, 1);
        const [record] = row.records,
          { streams, pressure } = row.completion;
        assert.equal(record.operation, 'download-validated-byte-stream');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
        assert.equal(streams.actualCallbacks, 120);
        assert.equal(streams.downloadBytes, streams.actualCallbacks * sftpSampleBytes);
        assert.equal(
          streams.measurements.filter((value) => value.phase === 'measured').length,
          100,
        );
        assert.equal(streams.measurements.filter((value) => value.phase === 'warmup').length, 20);
        assert.equal(
          streams.destinationCallbacks,
          streams.measurements.reduce((sum, value) => sum + value.callbacks, 0),
        );
        for (const value of streams.measurements) {
          assert.equal(value.bytes, sftpSampleBytes);
          assert.ok(value.firstByteMs >= 0 && value.elapsedMs > 0);
          assert.ok(value.firstByteMs <= value.elapsedMs);
          assert.equal(value.bytesPerSecond, (value.bytes * 1000) / value.elapsedMs);
          assert.ok(value.maximumDeliveredChunkBytes > 0);
          assert.equal(value.digestVerified, true);
          assert.equal(value.receiptVerified, true);
          assert.equal(value.concurrentDestinationCallbacksMaximum, 1);
        }
        assert.equal(pressure.bytes, sftpPressureBytes);
        assert.equal(pressure.sdkBytesReadAtPlateau, pressure.sdkBytesReadAfterHold);
        assert.ok(pressure.sdkBytesReadAtPlateau < pressure.bytes);
        assert.ok(pressure.sdkReadableQueueBytesAtPlateau > 0);
        assert.ok(
          pressure.peakObservedSdkReadableQueueBytes >= pressure.sdkReadableQueueBytesAtPlateau,
        );
        assert.ok(pressure.actualConsumerHoldMs >= 40);
        assert.equal(pressure.destinationSettledDuringHold, false);
        assert.equal(pressure.sdkReachedEofDuringHold, false);
        assert.equal(pressure.nativeHandleClosed, true);
        assert.equal(pressure.digestVerified, true);
        assert.equal(pressure.observedScope, 'client-sdk-readable-only');
        assert.equal(pressure.opaqueSshSocketServerBufferBytes, null);
        assert.equal(pressure.remoteProducerPressureEstablished, false);
        assert.equal(row.completion.postProbeHealthy, true);
        assert.equal(row.completion.clientTcpNoDelay, true);
        assert.equal(row.completion.documentedNativeClientReturned, true);
        assert.equal(row.completion.uploadTimingSupported, false);
        assert.equal(row.processTreeResource.scope, 'whole-supervised-lifecycle');
        assert.equal(row.processTreeResource.allChildrenWaited, true);
        assert.equal(row.processTreeResource.remainingOwnedProcesses, 0);
        assert.equal(row.processTreeResource.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(row.processTreeResource.externalServerResourcesIncluded, false);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
