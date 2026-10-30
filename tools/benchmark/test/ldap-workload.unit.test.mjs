// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ldapSettings } from '../ldap-workload.mjs';

test('LDAP comparison admits only a fixed verified owned endpoint before secret access', () => {
  for (const url of [
    'ldap://127.0.0.1:1',
    'ldaps://foreign.invalid:1',
    'ldaps://127.0.0.1:1/foreign',
    'ldaps://user:pass@127.0.0.1:1',
  ])
    assert.throws(() => ldapSettings({ url }));
});
