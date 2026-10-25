// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SQL_TIMEOUT_MS,
  DEFAULT_POOL_ACQUIRE_TIMEOUT_MS,
  DEFAULT_METER_QUEUE_CAPACITY,
  METER_EVENT_SCHEMA_VERSION,
} from '@arkenivajs/core';

test('EK-CORE-003 documented public defaults retain their exact literal types and values', () => {
  const shutdown: 30000 = DEFAULT_SHUTDOWN_TIMEOUT_MS;
  const http: 10000 = DEFAULT_HTTP_TIMEOUT_MS;
  const sql: 15000 = DEFAULT_SQL_TIMEOUT_MS;
  const acquire: 5000 = DEFAULT_POOL_ACQUIRE_TIMEOUT_MS;
  const queue: 10000 = DEFAULT_METER_QUEUE_CAPACITY;
  const schema: '1.0.0' = METER_EVENT_SCHEMA_VERSION;
  assert.deepEqual(
    { shutdown, http, sql, acquire, queue, schema },
    {
      shutdown: 30000,
      http: 10000,
      sql: 15000,
      acquire: 5000,
      queue: 10000,
      schema: '1.0.0',
    },
  );
});
