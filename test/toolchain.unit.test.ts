// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
test('EK-CORE-003 workspace uses strict ESM and private packages', () => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {
    private: boolean;
    type: string;
  };
  assert.equal(pkg.private, true);
  assert.equal(pkg.type, 'module');
});
