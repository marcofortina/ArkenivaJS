// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { securityPlugin } from '@arkenivajs/security';
import { runPureWorker } from './pure-worker.mjs';
import {
  authConnection,
  nativeAuth,
  verifyAuth,
  authWorkload,
  completeAuth,
} from './auth-workload.mjs';

runPureWorker({
  name: 'auth',
  asynchronous: true,
  iterations: 1000,
  warmupIterations: 100,
  native: nativeAuth,
  framework(fixture) {
    authConnection(fixture);
    return {
      plugin: securityPlugin({
        jwksUrl: fixture.issuer + '/keys',
        allowInsecureLoopback: true,
        clockToleranceSeconds: 0,
        authorizeTenant: (_identity, tenant) => tenant === fixture.tenant,
      }),
      key: COMPONENTS.auth,
      security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
    };
  },
  verify: verifyAuth,
  workload: authWorkload,
  complete: completeAuth,
});
