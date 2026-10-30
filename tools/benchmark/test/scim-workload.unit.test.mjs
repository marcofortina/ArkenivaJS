// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scimConnection } from '../scim-workload.mjs';

test('SCIM comparison rejects foreign bridges and authority overrides before provider I/O', () => {
  for (const bridgeUrl of [
    'http://foreign.invalid:1',
    'https://127.0.0.1:1',
    'http://user:pass@127.0.0.1:1',
    'http://127.0.0.1:1/provider',
    'http://127.0.0.1:1?override=true',
    'http://127.0.0.1:1#fragment',
  ])
    assert.throws(() => scimConnection({ bridgeUrl, issuer: 'http://127.0.0.1:2' }));
});
