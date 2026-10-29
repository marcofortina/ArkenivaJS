// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/process.js';

test(
  'Public SPID SAML HTTPS Redirect, cookie-bound POST ACS and canonical tenant mapping',
  { timeout: 30000 },
  () =>
    runOidcWorker(
      'public',
      'detailed',
      new URL('../fixtures/public-saml-worker.js', import.meta.url),
    ),
);
