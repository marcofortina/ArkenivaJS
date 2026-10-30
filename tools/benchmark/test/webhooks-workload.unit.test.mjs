// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { webhookPorts } from '../webhooks-workload.mjs';

test('Webhook comparison rejects foreign provider targets before accessing a secret or store', () => {
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://127.0.0.1:1/other',
  ])
    assert.throws(() => webhookPorts({ endpoint }));
});
