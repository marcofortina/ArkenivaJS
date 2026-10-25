// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { runEtcdExample } from '../../dist/main.js';

test('The etcd guide executes real binary values, acknowledged CAS, watch events and lease cleanup', async () => {
  const result = await runEtcdExample();
  assert.deepEqual(
    { ...result, revision: 'observed' },
    {
      firstAccepted: true,
      secondAccepted: false,
      mode: 'enabled',
      revision: 'observed',
      version: '1',
      leaseDeleted: true,
    },
  );
  assert.match(result.revision, /^[1-9]\d*$/);
});
