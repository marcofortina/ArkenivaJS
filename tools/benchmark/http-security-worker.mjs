// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityHttpPlugin } from '@arkenivajs/security-http';
import { runPureWorker } from './pure-worker.mjs';
import {
  headerSettings,
  configureHeaders,
  nativeHeaders,
  verifyHeaders,
  headerWorkload,
} from './http-security-workload.mjs';

runPureWorker({
  name: 'http-security',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeHeaders,
  framework(fixture, mode) {
    const authority = headerSettings();
    return {
      plugin: securityHttpPlugin(authority.settings),
      plugins: [apiPlugin({ dependencies: mode === 'FRAMEWORK' ? [] : ['telemetry'] })],
      http: { host: '127.0.0.1', port: 0 },
      telemetryOptions: { labelValues: { route: ['/headers', '/failure', 'unmatched'] } },
      key: COMPONENTS.api,
      configure: (app) => configureHeaders(app, fixture),
      dispose: authority.close,
    };
  },
  verify: verifyHeaders,
  workload: headerWorkload,
  close: (service) => service.close(),
});
