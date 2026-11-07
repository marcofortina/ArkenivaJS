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

test(
  'Sampled Unix4KiB profiles reconcile independent clients and owned socket retirement',
  { timeout: 145000, skip: process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-unix-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke-unix', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.scenarioId, 'socket-unix-independent-client-lifecycle');
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.inputs.sampledTransport, 'unix');
      assert.equal(report.inputs.sampledPayloadBytes, 4096);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.scenarios.length, 5);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.unixPathRemoved, true);
        assert.equal(row.verification.independentClientProcessesWaited, 6);
        assert.equal(row.verification.acceptedConnections, 5);
        assert.equal(row.verification.receivedApplicationBytes, 70016);
        assert.equal(row.verification.sentApplicationBytes, 70016);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'unix4096IndependentClient');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(
          record.rawLatency.values.every((sample) => Number.isFinite(sample) && sample >= 0),
        );
        assert.equal(value.sampledEchoes, 100);
        assert.equal(value.warmupEchoes, 20);
        assert.equal(value.checkedEchoes, 120);
        assert.equal(value.independentClientProcessesWaited, 120);
        assert.equal(value.acceptedConnections, 120);
        assert.equal(value.receivedApplicationBytes, 491520);
        assert.equal(value.sentApplicationBytes, 491520);
        assert.equal(value.sampledTransport, 'unix');
        assert.equal(value.sampledPayloadBytes, 4096);
        assert.equal(value.unixSocketOwned, true);
        assert.equal(value.unixSocketInodeStable, true);
        assert.equal(value.unixSocketMode, 0o600);
        assert.equal(value.unixPathRemoved, true);
        assert.equal(value.listenerClosed, true);
        assert.equal(value.opaqueKernelBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.receivedBytes, 4096);
          assert.equal(measurement.byteIdentityVerified, true);
          assert.ok(measurement.firstByteMs >= 0);
          assert.ok(measurement.exchangeElapsedMs >= measurement.firstByteMs);
        }
        assert.ok(row.resource.elapsedMs >= 0);
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        assert.ok(row.resource.cpuDeltaMicros.system >= 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
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

test(
  'Sampled TLS64 profiles reconcile fresh authorized handshakes and independent client lifecycles',
  { timeout: 145000, skip: process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-tls-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke-tls', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.scenarioId, 'socket-tls-independent-client-lifecycle');
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.inputs.sampledTransport, 'tls');
      assert.equal(report.inputs.sampledPayloadBytes, 64);
      assert.equal(report.inputs.minimumTlsVersion, 'TLSv1.3');
      assert.equal(report.inputs.sessionReuseAllowed, false);
      assert.equal(report.inputs.hostnameVerificationRequired, true);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.scenarios.length, 5);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.independentClientProcessesWaited, 6);
        assert.equal(row.verification.acceptedConnections, 5);
        assert.equal(row.verification.receivedApplicationBytes, 70016);
        assert.equal(row.verification.sentApplicationBytes, 70016);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'tls64IndependentClient');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(
          record.rawLatency.values.every((sample) => Number.isFinite(sample) && sample >= 0),
        );
        assert.equal(value.sampledEchoes, 100);
        assert.equal(value.warmupEchoes, 20);
        assert.equal(value.checkedEchoes, 120);
        assert.equal(value.independentClientProcessesWaited, 120);
        assert.equal(value.acceptedConnections, 120);
        assert.equal(value.receivedApplicationBytes, 7680);
        assert.equal(value.sentApplicationBytes, 7680);
        assert.equal(value.sampledTransport, 'tls');
        assert.equal(value.sampledPayloadBytes, 64);
        assert.equal(value.completedAuthorizedTlsHandshakes, 120);
        assert.equal(value.resumedTlsHandshakes, 0);
        assert.deepEqual(value.observedTlsProtocols, ['TLSv1.3']);
        assert.equal(value.observedTlsCiphers.length, 1);
        assert.match(value.observedTlsCiphers[0], /^TLS_/);
        assert.equal(value.listenerClosed, true);
        assert.equal(value.opaqueKernelBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.receivedBytes, 64);
          assert.equal(measurement.byteIdentityVerified, true);
          assert.ok(measurement.firstByteMs >= 0);
          assert.ok(measurement.exchangeElapsedMs >= measurement.firstByteMs);
          const tls = measurement.tls;
          assert.equal(tls.protocol, 'TLSv1.3');
          assert.equal(tls.cipher, value.observedTlsCiphers[0]);
          assert.equal(tls.authorized, true);
          assert.equal(tls.sessionReused, false);
          assert.equal(tls.certificateKeyType, 'ec');
          assert.equal(tls.certificateNamedCurve, 'prime256v1');
          assert.equal(tls.certificateKeyBits, 256);
          assert.equal(tls.certificateKeyBitsSource, 'EC P-256 named curve');
          for (const name of [
            'tcpConnectElapsedMs',
            'handshakeElapsedMs',
            'firstByteFromConnectMs',
            'exchangeFromConnectMs',
            'payloadFirstByteMs',
            'payloadExchangeElapsedMs',
          ])
            assert.ok(Number.isFinite(tls[name]) && tls[name] >= 0);
          assert.ok(tls.firstByteFromConnectMs >= tls.handshakeElapsedMs);
          assert.ok(tls.exchangeFromConnectMs >= tls.firstByteFromConnectMs);
          assert.ok(tls.payloadExchangeElapsedMs >= tls.payloadFirstByteMs);
          if (tls.ephemeralKeyInfo) {
            assert.equal(typeof tls.ephemeralKeyInfo.type, 'string');
            if (tls.ephemeralKeyInfo.name !== undefined)
              assert.equal(typeof tls.ephemeralKeyInfo.name, 'string');
            if (tls.ephemeralKeyInfo.size !== undefined)
              assert.ok(
                Number.isSafeInteger(tls.ephemeralKeyInfo.size) && tls.ephemeralKeyInfo.size > 0,
              );
          }
        }
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        assert.ok(row.resource.cpuDeltaMicros.system >= 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
        assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
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

test(
  'Sampled TCP64KiB profiles reconcile complete echoes and independent listener byte counters',
  { timeout: 145000, skip: process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-tcp64k-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke-tcp64k', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.scenarioId, 'socket-tcp64k-independent-client-lifecycle');
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.inputs.sampledTransport, 'tcp');
      assert.equal(report.inputs.sampledPayloadBytes, 65536);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.scenarios.length, 5);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.unixPathRemoved, true);
        assert.equal(row.verification.independentClientProcessesWaited, 6);
        assert.equal(row.verification.acceptedConnections, 5);
        assert.equal(row.verification.receivedApplicationBytes, 70016);
        assert.equal(row.verification.sentApplicationBytes, 70016);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'tcp65536IndependentClient');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(
          record.rawLatency.values.every((sample) => Number.isFinite(sample) && sample >= 0),
        );
        assert.equal(value.sampledEchoes, 100);
        assert.equal(value.warmupEchoes, 20);
        assert.equal(value.checkedEchoes, 120);
        assert.equal(value.independentClientProcessesWaited, 120);
        assert.equal(value.acceptedConnections, 120);
        assert.equal(value.receivedApplicationBytes, 7864320);
        assert.equal(value.sentApplicationBytes, 7864320);
        assert.equal(value.sampledTransport, 'tcp');
        assert.equal(value.sampledPayloadBytes, 65536);
        assert.equal(value.listenerClosed, true);
        assert.equal(value.opaqueKernelBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.receivedBytes, 65536);
          assert.equal(measurement.byteIdentityVerified, true);
          assert.ok(measurement.firstByteMs >= 0);
          assert.ok(measurement.exchangeElapsedMs >= measurement.firstByteMs);
          assert.equal(measurement.tls, undefined);
        }
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        assert.ok(row.resource.cpuDeltaMicros.system >= 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
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

test(
  'Sampled UDP256 profiles reconcile owned replies, local drops and monotonic handler observations',
  { timeout: 145000, skip: process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-udp-smoke-'));
    try {
      const output = join(directory, 'report');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke-udp', output],
        { timeout: 140000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.scenarioId, 'socket-udp-independent-client-lifecycle');
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.inputs.sampledTransport, 'udp');
      assert.equal(report.inputs.sampledPayloadBytes, 256);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.scenarios.length, 5);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.unixPathRemoved, true);
        assert.equal(row.verification.independentClientProcessesWaited, 6);
        assert.equal(row.verification.acceptedConnections, 5);
        assert.equal(row.verification.receivedApplicationBytes, 70016);
        assert.equal(row.verification.sentApplicationBytes, 70016);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          value = row.completion;
        assert.equal(record.operation, 'udp256IndependentClient');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, 100);
        assert.ok(
          record.rawLatency.values.every((sample) => Number.isFinite(sample) && sample >= 0),
        );
        assert.equal(value.sampledEchoes, 100);
        assert.equal(value.warmupEchoes, 20);
        assert.equal(value.checkedEchoes, 120);
        assert.equal(value.independentClientProcessesWaited, 120);
        assert.equal(value.acceptedConnections, 0);
        assert.equal(value.receivedApplicationBytes, 30720);
        assert.equal(value.sentApplicationBytes, 30720);
        assert.equal(value.sampledTransport, 'udp');
        assert.equal(value.sampledPayloadBytes, 256);
        assert.equal(value.sampledFamily, 'udp4');
        assert.equal(value.handlerReceivedDatagrams, 120);
        assert.equal(value.handlerRepliesCompleted, 120);
        assert.equal(value.handlerErrors, 0);
        assert.equal(value.activeHandlersAfterClose, 0);
        assert.equal(value.observedApplicationDrops, row.mode === 'BASELINE' ? null : 0);
        assert.equal(
          value.applicationDropObservation,
          row.mode === 'BASELINE'
            ? 'not-applicable-no-application-drop-queue'
            : 'framework-local-application-drop-counter',
        );
        assert.equal(value.observedSocketErrors, 0);
        assert.equal(value.handlerDurationMs.warmup.length, 20);
        assert.equal(value.handlerDurationMs.measured.length, 100);
        assert.ok(
          [...value.handlerDurationMs.warmup, ...value.handlerDurationMs.measured].every(
            (duration) => Number.isFinite(duration) && duration >= 0,
          ),
        );
        assert.equal(value.osNetworkLoss, null);
        assert.equal(value.deliveryGuaranteed, false);
        assert.equal(value.listenerClosed, true);
        assert.equal(value.opaqueKernelBufferBytes, null);
        assert.equal(value.measurements.length, 120);
        for (const measurement of value.measurements) {
          assert.equal(measurement.receivedBytes, 256);
          assert.equal(measurement.byteIdentityVerified, true);
          assert.ok(measurement.firstByteMs >= 0);
          assert.ok(measurement.exchangeElapsedMs >= measurement.firstByteMs);
          assert.equal(measurement.tls, undefined);
          assert.deepEqual(measurement.udp, {
            datagramsSent: 1,
            repliesFromExpectedPeer: 1,
            ignoredForeignDatagrams: 0,
            peerTupleVerified: true,
          });
        }
        assert.ok(row.resource.cpuDeltaMicros.user >= 0);
        assert.ok(row.resource.cpuDeltaMicros.system >= 0);
        const resource = row.processTreeResource;
        assert.equal(resource.scope, 'whole-supervised-lifecycle');
        assert.equal(resource.allChildrenWaited, true);
        assert.equal(resource.remainingOwnedProcesses, 0);
        assert.equal(resource.pythonObserverIncluded, false);
        assert.equal(resource.externalServerResourcesIncluded, false);
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
