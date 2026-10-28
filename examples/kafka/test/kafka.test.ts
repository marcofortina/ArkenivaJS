// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { kafkaPlugin, KAFKA_CAPABILITY } from '@arkenivajs/messaging-kafka';
test('The public Kafka factory and explicit capability import without opening native clients', () => {
  assert.equal(typeof kafkaPlugin, 'function');
  assert.equal(typeof KAFKA_CAPABILITY, 'symbol');
});
