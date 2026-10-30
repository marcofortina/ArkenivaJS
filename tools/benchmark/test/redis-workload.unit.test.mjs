// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { redisConnection } from '../redis-workload.mjs';

test('Redis comparison rejects unowned targets, unverified transport and arbitrary namespaces before I/O', () => {
  const namespace = 'redis-comparison:' + 'a'.repeat(32) + ':';
  for (const url of [
    'redis://user:pass@127.0.0.1:1',
    'rediss://user:pass@foreign.invalid:1',
    'rediss://127.0.0.1:1',
    'rediss://user:pass@127.0.0.1:1?sslca=relative',
  ])
    assert.throws(() => redisConnection({ url, namespace }));
  assert.throws(() =>
    redisConnection({
      url: 'rediss://user:pass@127.0.0.1:1?sslca=/owned/ca',
      namespace: 'foreign:',
    }),
  );
});
