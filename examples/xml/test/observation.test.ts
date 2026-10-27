// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { observeXml } from './observation-fixture.js';
for (const mode of ['standard', 'detailed'] as const)
  test(
    'Actual XML workers expose native facts without document content in ' + mode + ' SDK exports',
    () => observeXml(false, mode),
  );
