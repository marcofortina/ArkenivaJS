// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { exerciseCli } from '../dist/main.js';

test('The actual CLI produces a strictly compilable service with a real HTTP greeting and an idempotent dependency edit', async () => {
  assert.deepEqual(await exerciseCli(), {
    greeting: { greeting: 'Hello from owned-service' },
    dependencyAdded: true,
    idempotent: true,
    sourceUnchanged: true,
    packageBin: true,
    recentModulesAdded: true,
  });
});
