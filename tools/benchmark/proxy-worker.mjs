// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { proxyPlugin } from '@arkenivajs/proxy';
import { runPureWorker } from './pure-worker.mjs';
import {
  proxyRoute,
  nativeProxyService,
  verifyProxy,
  proxyExchange,
  createProxySampling,
  proxyIterations,
  proxyWarmupIterations,
} from './proxy-workload.mjs';

const sampling = new WeakMap();

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
  async verify(service, fixture) {
    const result = await verifyProxy(service, fixture);
    if (fixture.sampleGets)
      sampling.set(
        service,
        createProxySampling(() => proxyExchange(service, fixture, 'GET')),
      );
    return result;
  },
  asynchronous: true,
  iterations: proxyIterations,
  warmupIterations: proxyWarmupIterations,
  retainRawSamples: true,
  workload: (service) => sampling.get(service).workload,
  complete(service, context) {
    try {
      if (!context.measure) {
        assert.equal(sampling.has(service), false);
        assert.deepEqual(context.records, []);
        return { sampledGets: 0, warmupGets: 0, checkedResponses: 0 };
      }
      return sampling.get(service).complete(context);
    } finally {
      sampling.delete(service);
    }
  },
  close: (service) => service.close(),
});
