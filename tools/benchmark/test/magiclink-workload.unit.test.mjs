// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { magiclinkPorts } from '../magiclink-workload.mjs';

test('Magic-link comparison rejects foreign provider endpoints and request authority overrides before I/O', () => {
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://user:pass@127.0.0.1:1/provider',
    'http://127.0.0.1:1/provider?override=true',
    'http://127.0.0.1:1/foreign',
  ])
    assert.throws(() => magiclinkPorts({ endpoint, bearer: 'owned-test-only' }));
});
