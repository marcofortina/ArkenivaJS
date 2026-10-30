// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { amqpConnection } from '../amqp-workload.mjs';

test('AMQP comparison rejects foreign targets, plaintext and URI transport overrides before I/O', () => {
  for (const url of [
    'amqp://user:pass@127.0.0.1:5672/owned',
    'amqps://user:pass@foreign.invalid:5671/owned',
    'amqps://127.0.0.1:5671/owned',
    'amqps://user:pass@127.0.0.1:5671/owned?rejectUnauthorized=false',
    'amqps://user:pass@127.0.0.1:5671/owned#fragment',
  ])
    assert.throws(() => amqpConnection({ url, caFile: '/owned/ca' }));
  assert.throws(() =>
    amqpConnection({ url: 'amqps://user:pass@127.0.0.1:5671/owned', caFile: 'relative' }),
  );
});
