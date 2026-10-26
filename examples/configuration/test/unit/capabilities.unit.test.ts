// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { runCapabilitiesExample } from '../../src/capabilities.js';

const expected = {
  initializationValue: 2,
  readyValue: 4,
  missingOptional: true,
  closedCode: 'EK_LIFECYCLE_STATE',
  releasedHandleCode: 'EK_RESOURCE_CLOSED',
};
test('The configured symbol service resolves its dependency and retains independent application ownership', async () => {
  assert.deepEqual(await Promise.all([runCapabilitiesExample(), runCapabilitiesExample()]), [
    expected,
    expected,
  ]);
});
test('The capability example is an executable ESM program with safe output and completed cleanup', () => {
  const result = spawnSync(process.execPath, ['dist/capabilities.js'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), expected);
});
