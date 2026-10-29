// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/oidc-worker-process.js';

test(
  'Actual HTTPS native OIDC exchanges verify private-key JWT, protected state, signatures, encryption and assurance',
  { timeout: 30000 },
  () => runOidcWorker(),
);
