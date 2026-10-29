// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { runOidcWorker } from '../fixtures/oidc-worker-process.js';

test(
  'Public application SPID OIDC verifies real federation, canonical identity, profile isolation and lifecycle',
  { timeout: 30000 },
  () => runOidcWorker('public'),
);
