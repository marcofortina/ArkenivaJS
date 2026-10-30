// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cacheConnection } from '../cache-workload.mjs';

test('Redis comparison rejects unowned or unverified targets before opening a socket', () => {
  for (const url of [
    'redis://user:pass@127.0.0.1:1',
    'rediss://user:pass@foreign.invalid:1',
    'rediss://127.0.0.1:1',
    'rediss://user:pass@127.0.0.1:1?sslca=relative',
  ]) {
    assert.throws(() =>
      cacheConnection({ url, namespace: 'cache-comparison:' + 'a'.repeat(32) + ':' }),
    );
  }
});
