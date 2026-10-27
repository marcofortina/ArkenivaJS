// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureSettings, runAmqpExample } from '../dist/main.js';
test('The compiled public AMQPS consumer confirms, returns and manually acknowledges actual native deliveries', async () => {
  const fixture = await fixtureSettings();
  const result = await runAmqpExample(fixture.settings, fixture.exchange, fixture.queue);
  assert.equal(result.receipt.status, 'confirmed');
  assert.equal(result.returned.status, 'unroutable');
  assert.equal(result.message.messageId, result.receipt.messageId);
  assert.deepEqual(result.message.body, Uint8Array.of(0, 128, 255));
  assert.equal(result.message.headers.large, 9007199254740993n);
  assert.deepEqual(result.message.headers.bytes, Uint8Array.of(0, 128, 255));
  assert.equal(result.message.verifiedTenant, undefined);
  await assert.rejects(result.message.ack());
});
