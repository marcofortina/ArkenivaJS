// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixtureSettings, runKafkaExample } from '../dist/main.js';
test(
  'Packed public Kafka APIs retain broker offsets, binary and empty payloads, tombstones and untrusted headers',
  { timeout: 30000 },
  async () => {
    const result = await runKafkaExample(
      fixtureSettings(),
      'owned-example-' + randomUUID(),
      'test',
    );
    assert.deepEqual(
      result.received.map((record) => (record.value === null ? null : [...record.value])),
      [[0, 128, 255], [], null],
    );
    assert.ok(
      result.receipts.every(
        (receipt) =>
          receipt.status === 'acknowledged' && /^(?:0|[1-9][0-9]*)$/.test(receipt.offset),
      ),
    );
    assert.equal(new Set(result.receipts.map((receipt) => receipt.partition)).size, 1);
    assert.ok(BigInt(result.receipts[0]!.offset) < BigInt(result.receipts[1]!.offset));
    assert.ok(BigInt(result.receipts[1]!.offset) < BigInt(result.receipts[2]!.offset));
    for (const record of result.received) {
      assert.equal(record.verifiedTenant, undefined);
      assert.equal(
        Buffer.from(record.headers.tenant_id as Uint8Array).toString(),
        'untrusted-wire-claim',
      );
      assert.deepEqual(record.headers.repeated, [null, Buffer.from([0, 255]), Buffer.alloc(0)]);
    }
  },
);
