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
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { kafkaPlugin } from '@arkenivajs/messaging-kafka';
import { startKafkaFixture } from '../kafka-fixture.mjs';
import { kafkaSettings } from '../kafka-workload.mjs';

test(
  'The independent Kafka observer rejects an unauthenticated receipt and production rejects the test-only secret resolver',
  { timeout: 20000 },
  async () => {
    const observer = await startKafkaFixture();
    let app;
    try {
      const response = await globalThis.fetch(observer.fixture.observerUrl + '/receipts', {
        method: 'POST',
        headers: { authorization: 'Bearer invalid' },
        body: JSON.stringify({ marker: 'untrusted', receipts: [] }),
      });
      assert.equal(response.status, 400);
      await response.arrayBuffer();
      app = await createApplication({
        service: {
          name: 'kafka-production-rejection',
          version: '1.0.0',
          environment: 'production',
        },
        logging: { level: 'silent' },
        plugins: [
          loggingPlugin(),
          kafkaPlugin(kafkaSettings({ ...observer.fixture, marker: observer.fixture.markers[0] })),
        ],
      });
      await assert.rejects(app.start());
    } finally {
      try {
        await app?.stop();
      } finally {
        await observer.close();
      }
    }
  },
);

test(
  'Four TLS/SASL Kafka profiles match actual independent offsets, tombstones, empty records and nullable headers',
  { timeout: 60000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-kafka-harness-'));
    const script = fileURLToPath(new URL('../kafka.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 55000,
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
        /owned-kafka-private-payload|untrusted-kafka-|owned-kafka-[0-9a-f]{32}|127\.0\.0\.1|fixture-allowed/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        {
          actualObservedRecords: 12,
          matchedProfileReceipts: 4,
          releaseGate: false,
        },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          actualBrokerAcknowledgments: 3,
          independentConsumerReceiptMatches: 3,
          binaryEmptyAndTombstonePreserved: true,
          repeatedNullableHeadersPreserved: true,
          exactOffsetOrderVerified: true,
          wireTenantHintRemainsUntrusted: true,
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
