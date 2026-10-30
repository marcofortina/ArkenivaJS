// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { scimPlugin, SCIM_CAPABILITY } from '@arkenivajs/security-scim';
import { runPureWorker } from './pure-worker.mjs';
import {
  grantScim,
  nativeScim,
  rememberScimOwner,
  scimSettings,
  verifyScim,
} from './scim-workload.mjs';

runPureWorker({
  name: 'scim',
  native: nativeScim,
  async framework(fixture, mode) {
    await grantScim(fixture);
    return {
      plugin: scimPlugin(scimSettings(fixture)),
      key: SCIM_CAPABILITY,
      plugins: [
        securityPlugin({
          allowInsecureLoopback: true,
          jwksUrl: fixture.issuer + '/keys',
          authorizeTenant: (_identity, tenant) => tenant === fixture.grant.tenant,
        }),
        apiPlugin({ dependencies: ['security', ...(mode === 'FRAMEWORK' ? [] : ['telemetry'])] }),
      ],
      security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
      http: { host: '127.0.0.1', port: 0 },
      configure: rememberScimOwner,
    };
  },
  verify: verifyScim,
});
