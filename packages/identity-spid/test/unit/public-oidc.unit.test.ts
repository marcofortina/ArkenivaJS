// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/oidc-worker-process.js';

for (const mode of ['standard', 'detailed'] as const)
  test(
    `Public application SPID OIDC verifies federation, canonical identity, lifecycle and private ${mode} SDK observations`,
    { timeout: 30000 },
    () => runOidcWorker('public', mode),
  );
