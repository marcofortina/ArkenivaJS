// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mongodbConnection } from '../mongodb-workload.mjs';

test('MongoDB comparison rejects foreign targets, unverified TLS and non-owned collection names before I/O', () => {
  const collection = 'comparison_' + 'a'.repeat(32);
  for (const url of [
    'mongodb://user:pass@foreign.invalid:27017/owned?tls=true&tlsCAFile=/owned/ca&directConnection=true',
    'mongodb://user:pass@localhost:27017/owned?tls=false&tlsCAFile=/owned/ca&directConnection=true',
    'mongodb://user:pass@localhost:27017/owned?tls=true&tlsCAFile=relative&directConnection=true',
    'mongodb://user:pass@localhost:27017/owned?tls=true&tlsCAFile=/owned/ca&directConnection=true&tlsInsecure=true',
    'mongodb://user:pass@localhost:27017/owned?tls=true&TLS=false&tlsCAFile=/owned/ca&directConnection=true',
  ])
    assert.throws(() => mongodbConnection({ url, collection }));
  assert.throws(() =>
    mongodbConnection({
      url: 'mongodb://user:pass@localhost:27017/owned?tls=true&tlsCAFile=/owned/ca&directConnection=true',
      collection: 'foreign',
    }),
  );
});
