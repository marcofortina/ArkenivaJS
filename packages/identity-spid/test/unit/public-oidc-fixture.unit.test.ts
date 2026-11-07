// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/oidc-worker-process.js';

for (const mode of ['standard', 'detailed'] as const)
  test(
    `Reusable public OIDC fixture closes its real listeners and service after failed ${mode} work`,
    { timeout: 30000 },
    () =>
      runOidcWorker(
        'public',
        mode,
        new URL('../fixtures/public-oidc-fixture-worker.js', import.meta.url),
      ),
  );
