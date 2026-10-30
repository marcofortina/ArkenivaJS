// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { oauthPorts } from '../oauth-workload.mjs';

test('OAuth comparison rejects foreign, unverified or credential-bearing fixture targets before provider I/O', () => {
  const base = { endpoint: 'http://127.0.0.1:1/provider', issuer: 'https://127.0.0.1:2' };
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://user:pass@127.0.0.1:1/provider',
    'http://127.0.0.1:1/provider?other=yes',
  ])
    assert.throws(() => oauthPorts({ ...base, endpoint }));
  for (const issuer of [
    'http://127.0.0.1:2',
    'https://foreign.invalid:2',
    'https://127.0.0.1:2/path',
    'https://user:pass@127.0.0.1:2',
  ])
    assert.throws(() => oauthPorts({ ...base, issuer }));
});
