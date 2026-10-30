// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { proxyPlugin } from '@arkenivajs/proxy';
import { runPureWorker } from './pure-worker.mjs';
import { proxyRoute, nativeProxyService, verifyProxy } from './proxy-workload.mjs';

runPureWorker({
  name: 'proxy',
  native: nativeProxyService,
  framework(fixture, mode) {
    return {
      plugin: proxyPlugin({ routes: [proxyRoute(fixture)] }),
      plugins: [apiPlugin({ dependencies: mode === 'FRAMEWORK' ? [] : ['telemetry'] })],
      http: { host: '127.0.0.1', port: 0 },
      key: COMPONENTS.api,
      telemetryOptions: { labelValues: { route: ['/comparison/*'], 'peer.service': ['owned'] } },
    };
  },
  verify: verifyProxy,
  close: (service) => service.close(),
});
