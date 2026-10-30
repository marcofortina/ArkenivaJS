// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mysqlQueryConnection, mysqlQueryInput } from '../mysql-query-workload.mjs';

test('MySQL comparison rejects unowned or unverified endpoints and keeps exact bigint out of SQL text', () => {
  for (const url of [
    'mysql://user:pass@foreign.invalid:3306/owned?ssl=verify-full&sslca=/owned/ca',
    'mysql://user:pass@localhost:3306/owned?ssl=disable',
    'mysql://user:pass@localhost:3306/owned?ssl=verify-full&sslca=relative',
    'mysql://user:pass@localhost:3306/owned?ssl=verify-full&sslca=/owned/ca&ssl=disable',
    'mysql://user:pass@localhost:3306/owned?ssl=verify-full&sslca=/owned/ca#fragment',
  ])
    assert.throws(() => mysqlQueryConnection({ url }));
  const input = mysqlQueryInput({ marker: "literal ' ; --", exact: '9007199254740993' });
  assert.equal(input.bindings.exact, 9007199254740993n);
  assert.equal(Object.isFrozen(input), true);
  assert.equal(Object.isFrozen(input.bindings), true);
  assert.doesNotMatch(input.text, /9007199254740993|literal/);
});
