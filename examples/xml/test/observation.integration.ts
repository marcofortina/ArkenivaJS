// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { observeXml } from './observation-fixture.js';
for (const mode of ['standard', 'detailed'] as const)
  test('Actual XSD validation exports private native facts through the ' + mode + ' SDK', () =>
    observeXml(true, mode),
  );
