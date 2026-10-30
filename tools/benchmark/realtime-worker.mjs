// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { realtimePlugin } from '@arkenivajs/realtime';
import { runPureWorker } from './pure-worker.mjs';
import { nativeRealtime, realtimeSettings, verifyRealtime } from './realtime-workload.mjs';

runPureWorker({
  name: 'realtime',
  native: nativeRealtime,
  framework(fixture, mode) {
    return {
      plugin: realtimePlugin(realtimeSettings(fixture)),
      key: COMPONENTS.api,
      plugins: [
        securityPlugin({
          allowInsecureLoopback: true,
          jwksUrl: fixture.issuer + '/keys',
          authorizeTenant: (_identity, tenant) => tenant === fixture.tenant,
        }),
        apiPlugin({ dependencies: ['security', ...(mode === 'FRAMEWORK' ? [] : ['telemetry'])] }),
      ],
      security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
      http: { host: '127.0.0.1', port: 0 },
      telemetryOptions: { labelValues: { route: ['/socket', '/events', 'unmatched'] } },
    };
  },
  verify: verifyRealtime,
  close: (service) => service.close(),
});
