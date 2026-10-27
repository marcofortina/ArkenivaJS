// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { amqpPlugin, AMQP_CAPABILITY } from '@arkenivajs/messaging-amqp';
test('The public AMQP consumer imports explicit factories and its capability without I/O', () => {
  assert.equal(typeof amqpPlugin, 'function');
  assert.equal(typeof AMQP_CAPABILITY, 'symbol');
});
