// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { realtimePlugin } from '@arkenivajs/realtime';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeRealtime,
  realtimeSettings,
  verifyRealtime,
  rememberRealtimeOwner,
  prepareRealtimeSampling,
  realtimeSourceStats,
  realtimeIterations,
  realtimeWarmupIterations,
} from './realtime-workload.mjs';

const sampling = new WeakMap();

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
      configure: rememberRealtimeOwner,
    };
  },
  async verify(service, fixture) {
    const result = await verifyRealtime(service, fixture);
    if (fixture.sampleStreams)
      sampling.set(service, await prepareRealtimeSampling(service, fixture));
    return result;
  },
  asynchronous: true,
  iterations: realtimeIterations,
  warmupIterations: realtimeWarmupIterations,
  retainRawSamples: true,
  workload: (service) => sampling.get(service).workload,
  complete(service, context) {
    try {
      const completion = context.measure
        ? sampling.get(service).complete(context)
        : { sampledStreams: 0, warmupStreams: 0, checkedStreams: 0 };
      if (!context.measure) {
        assert.equal(sampling.has(service), false);
        assert.deepEqual(context.records, []);
      }
      const stats = realtimeSourceStats(context.fixture);
      assert.equal(stats.opened, 2 + completion.checkedStreams);
      assert.equal(stats.closed, stats.opened);
      assert.equal(stats.active, 0);
      assert.equal(stats.events, 4 + 3 * completion.checkedStreams);
      return {
        ...completion,
        actualSourceSubscriptions: stats.opened,
        retiredSourceSubscriptions: stats.closed,
        activeSourceSubscriptions: stats.active,
        actualSourceEvents: stats.events,
      };
    } finally {
      sampling.delete(service);
    }
  },
  close: (service) => service.close(),
});
