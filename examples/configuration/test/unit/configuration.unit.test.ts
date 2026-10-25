// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runConfigurationExample } from '../../src/main.js';
import { KitError } from '@arkenivajs/core';

test('Configuration guide runs with YAML and explicit environment precedence', async () => {
  assert.deepEqual(await runConfigurationExample(), { greeting: 'Hello from YAML' });
  assert.deepEqual(
    await runConfigurationExample({ ARKENIVAJS_GREETING: 'Hello from environment' }),
    { greeting: 'Hello from environment' },
  );
});
test('Configuration guide rejects an invalid or unknown environment field', async () => {
  for (const environment of [{ ARKENIVAJS_GREETING: '' }, { ARKENIVAJS_UNKNOWN: 'value' }])
    await assert.rejects(
      runConfigurationExample(environment),
      (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
    );
});

test('The documented configuration CLI accepts the native Node environment object', () => {
  const file = new URL('../../../dist/main.js', import.meta.url);
  const output = execFileSync(process.execPath, [file.pathname], {
    encoding: 'utf8',
    env: { ...process.env, ARKENIVAJS_GREETING: 'Hello from CLI' },
  });
  assert.deepEqual(JSON.parse(output), { greeting: 'Hello from CLI' });
});
