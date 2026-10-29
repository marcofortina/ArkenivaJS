// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/oidc-worker-process.js';

test(
  'Native AuthService provenance and approved policies bind OIDC evidence to canonical tenant identity',
  { timeout: 30000 },
  () => runOidcWorker(true),
);
