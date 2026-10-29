// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/process.js';
for (const mode of ['standard', 'detailed'] as const)
  test(
    `Installed public CIE HTTPS login, cookie-bound callback, canonical mapping and ${mode} observation privacy`,
    { timeout: 30000 },
    () => runOidcWorker('public', mode),
  );
