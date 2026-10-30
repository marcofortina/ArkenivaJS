// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mariadbQueryConnection, mariadbQueryInput } from '../mariadb-query-workload.mjs';

test('MariaDB comparison rejects unowned or unverified endpoints and captures an exact native bigint bind', () => {
  for (const url of [
    'mariadb://user:pass@foreign.invalid:3306/owned?ssl=verify-full&sslca=/owned/ca',
    'mariadb://user:pass@localhost:3306/owned?ssl=disable',
    'mariadb://user:pass@localhost:3306/owned?ssl=verify-full&sslca=relative',
    'mariadb://user:pass@localhost:3306/owned?ssl=verify-full&sslca=/owned/ca&ssl=disable',
    'mysql://user:pass@localhost:3306/owned?ssl=verify-full&sslca=/owned/ca',
  ])
    assert.throws(() => mariadbQueryConnection({ url }));
  const input = mariadbQueryInput({ marker: "literal ' ; --", exact: '9007199254740993' });
  assert.equal(input.bindings.exact, 9007199254740993n);
  assert.equal(Object.isFrozen(input), true);
  assert.equal(Object.isFrozen(input.bindings), true);
  assert.doesNotMatch(input.text, /9007199254740993|literal/);
});
