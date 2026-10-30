// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sqlQueryConnection, sqlQueryInput } from '../sql-query-workload.mjs';

test('SQL comparison rejects unowned targets and unverified TLS before opening connections', () => {
  for (const url of [
    'postgres://user:pass@foreign.invalid:5432/owned?sslmode=verify-full&sslrootcert=/owned/ca',
    'postgres://user:pass@127.0.0.1:5432/owned?sslmode=require',
    'postgres://user:pass@127.0.0.1:5432/owned?sslmode=verify-full&sslrootcert=relative',
    'postgres://127.0.0.1:5432/owned',
    'https://127.0.0.1:5432/owned',
  ])
    assert.throws(() => sqlQueryConnection({ url }));
  const input = sqlQueryInput({ marker: "literal ' ; --" });
  assert.equal(input.bindings.marker, "literal ' ; --");
  assert.equal(Object.isFrozen(input), true);
  assert.equal(Object.isFrozen(input.bindings), true);
  assert.doesNotMatch(input.text, /literal/);
});
