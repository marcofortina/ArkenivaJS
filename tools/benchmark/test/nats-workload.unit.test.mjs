// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { natsConnection, verifyNatsReceipt } from '../nats-workload.mjs';

test('NATS comparison rejects foreign destinations, missing mutual TLS and ambiguous namespaces before I/O', () => {
  for (const url of [
    'nats://user:pass@127.0.0.1:14223/',
    'tls://user:pass@foreign.invalid:14223/?prefix=owned.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=/owned/ca',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.*&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&prefix=foreign.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=relative&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key&rejectUnauthorized=false',
  ])
    assert.throws(() => natsConnection({ url }));
});

test('NATS entry rejects unsupported campaigns and unmarked smoke before fixture or evidence creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-nats-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_NATS_BENCHMARK_DISPOSABLE;
  delete env.ARKENIVA_NATS_DISPOSABLE;
  delete env.ARKENIVA_NATS_URL;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../nats.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full NATS campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Untimed NATS receipt validation requires exact paired observations and forbids invented authority or acknowledgment', () => {
  const fixture = {
      topic: 'owned.literal',
      marker: 'unit-private-payload',
      correlation: 'unit-private-correlation',
    },
    receipt = { messageId: randomUUID(), acknowledged: false },
    wire = {
      schemaVersion: 1,
      messageId: receipt.messageId,
      topic: fixture.topic,
      payload: { marker: fixture.marker, sequence: 7 },
      correlationId: fixture.correlation,
    },
    { schemaVersion, ...delivered } = wire,
    bytes = Buffer.byteLength(JSON.stringify(wire));
  assert.equal(schemaVersion, 1);
  assert.equal(verifyNatsReceipt(wire, delivered, receipt, fixture, 7, bytes), bytes);
  for (const changed of [
    { ...wire, messageId: randomUUID() },
    { ...wire, payload: { marker: fixture.marker, sequence: 8 } },
    { ...wire, correlationId: 'foreign-correlation' },
    { ...wire, tenant: { tenantId: 'untrusted-wire-tenant' } },
  ])
    assert.throws(() => verifyNatsReceipt(changed, delivered, receipt, fixture, 7, bytes));
  assert.throws(() =>
    verifyNatsReceipt(
      wire,
      { ...delivered, tenant: { tenantId: 'untrusted-wire-tenant' } },
      receipt,
      fixture,
      7,
      bytes,
    ),
  );
  assert.throws(() =>
    verifyNatsReceipt(wire, delivered, { ...receipt, acknowledged: true }, fixture, 7, bytes),
  );
  assert.throws(() => verifyNatsReceipt(wire, delivered, receipt, fixture, 7, bytes + 1));
});
