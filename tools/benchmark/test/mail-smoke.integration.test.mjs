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
import { mailPrivateValues, attachmentBytes } from '../mail-workload.mjs';

test(
  'Explicit SMTP smoke retains real acceptance samples with independent bounded MIME receipt integrity',
  { timeout: 135000, skip: process.env.ARKENIVA_MAIL_BENCHMARK_DISPOSABLE !== '1' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../mail.mjs', import.meta.url)), '--smoke', output],
        { timeout: 130000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        protocol = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      for (const value of mailPrivateValues) assert.equal(encoded.includes(value), false);
      let accepted = 0,
        attachmentTotal = 0;
      for (const row of report.records) {
        assert.equal(row.measured, true);
        assert.ok(row.resource.elapsedMs > 0);
        assert.equal(row.records.length, 1);
        const measured = row.records[0],
          observed = row.completion;
        assert.equal(measured.operation, 'smtp-accepted-streamed-attachment');
        assert.equal(measured.sampleCount, 100);
        assert.equal(measured.warmupIterations, 20);
        assert.equal(measured.rawLatency.unit, 'milliseconds');
        assert.equal(measured.rawLatency.values.length, measured.sampleCount);
        assert.ok(
          measured.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
        );
        assert.equal(
          observed.actualSubmissionCallbacks,
          measured.sampleCount + measured.warmupIterations,
        );
        assert.equal(observed.acceptedSubmissions, observed.actualSubmissionCallbacks);
        assert.equal(
          observed.totalReceipts,
          observed.verificationAccepted + observed.acceptedSubmissions,
        );
        assert.equal(
          observed.expectedAttachmentBytes,
          observed.totalReceipts * attachmentBytes.length,
        );
        assert.match(observed.receiptDigest, /^[a-f0-9]{64}$/);
        assert.equal(observed.activeCallbacks, 0);
        assert.equal(observed.peakConcurrentCallbacks, 1);
        assert.equal(observed.retainedReceiptIds, 0);
        accepted += observed.totalReceipts;
        attachmentTotal += observed.expectedAttachmentBytes;
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.equal(protocol.acceptedMessages, accepted);
      assert.equal(protocol.attachmentBytes, attachmentTotal);
      assert.equal(protocol.envelopeRecipients, accepted);
      assert.equal(protocol.mimeRecipients, accepted);
      assert.ok(protocol.observedMimeBytes > attachmentTotal);
      assert.equal(protocol.failedMessages, 0);
      assert.equal(protocol.activeMessages, 0);
      assert.equal(protocol.activeConnections, 0);
      assert.equal(protocol.connectionsOpened, protocol.connectionsClosed);
      assert.ok(protocol.peakConnections <= 4);
      assert.ok(protocol.peakActiveMessages <= 4);
      assert.equal(protocol.secureSessions, protocol.authentications);
      assert.ok(protocol.authentications >= report.records.length);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
