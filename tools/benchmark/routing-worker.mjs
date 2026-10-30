// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setImmediate } from 'node:timers/promises';
import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { tenantRoutingPlugin, TENANT_ROUTING_CAPABILITY } from '@arkenivajs/tenant-routing';
import { runPureWorker } from './pure-worker.mjs';
import { routingPrivateValues } from './routing-fixture.mjs';
import {
  ROUTING_COMPARISON,
  calculatePath,
  capabilitiesPath,
  routingCorpus,
  nativeRouting,
  verifyRouting,
  routingIterations,
  routingWarmupIterations,
  routingWorkload,
  completeRoutingWorkload,
} from './routing-workload.mjs';

export const routingAdapter = {
  name: 'tenant-routing',
  asynchronous: true,
  iterations: routingIterations,
  warmupIterations: routingWarmupIterations,
  retainRawSamples: true,
  native: nativeRouting,
  async framework(fixture, mode) {
    const corpus = routingCorpus(fixture),
      metered = mode === 'STANDARD' || mode === 'DETAILED';
    const workspace = metered
      ? await mkdtemp(join(tmpdir(), 'arkenivajs-routing-comparison-'))
      : undefined;
    return {
      key: ROUTING_COMPARISON,
      security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
      http: {
        host: '127.0.0.1',
        port: 0,
        protocol: 'https',
        tls: { privateKeyFile: fixture.privateKeyFile, certificateFile: fixture.certificateFile },
      },
      ...(metered ? { metering: { enabled: true, exporter: 'jsonl', path: 'usage.jsonl' } } : {}),
      plugins: [
        securityPlugin({
          allowInsecureLoopback: true,
          jwksUrl: fixture.issuer + '/keys',
          authorizeTenant: (_identity, tenant) =>
            [fixture.tenant, fixture.otherTenant, fixture.emptyTenant].includes(tenant),
        }),
        ...(metered ? [meteringPlugin({ workspace, dependencies: ['telemetry'] })] : []),
        apiPlugin({ dependencies: ['security', ...(metered ? ['telemetry', 'metering'] : [])] }),
        tenantRoutingPlugin({
          registry: { loadSnapshot: async () => corpus.registry },
          handlers: corpus.handlers,
          authorize: corpus.authorize,
          activation: 'startup',
          maxCapabilities: 1,
        }),
      ],
      plugin: {
        id: 'routing-comparison-probe',
        version: '0.1.0',
        capabilities: new Set(),
        dependencies: ['tenant-routing', 'api', 'security', ...(metered ? ['metering'] : [])],
        init(context) {
          const routing = context.require(TENANT_ROUTING_CAPABILITY),
            auth = context.require(COMPONENTS.auth);
          context.provide(ROUTING_COMPARISON, {
            api: context.require(COMPONENTS.api),
            stats: corpus.stats,
            async resolution(token) {
              return routing.api.resolve(
                'orders.calculate',
                auth.tenantFrom(await auth.verifyBearer('Bearer ' + token)),
              );
            },
            ...(metered ? { meter: context.require(COMPONENTS.meter), workspace } : {}),
          });
        },
        close() {},
      },
      telemetryOptions: {
        labelValues: {
          route: [calculatePath, capabilitiesPath, '/api/order-status', '/api/denied', 'unmatched'],
        },
      },
      dispose: () => (workspace ? rm(workspace, { recursive: true, force: true }) : undefined),
    };
  },
  verify: verifyRouting,
  workload: routingWorkload,
  async complete(service, options) {
    const workload = completeRoutingWorkload(service, options);
    if (!service.meter) return { technicalUsageEnabled: false, ...workload };
    const { fixture } = options;
    await setImmediate();
    await service.meter.flush();
    const events = (await readFile(join(service.workspace, 'usage.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    const children = events.filter((event) => event.operation.startsWith('orders.')),
      parents = events.filter((event) => event.operation === 'http.request');
    assert.equal(children.length, workload.expectedUsageChildren);
    assert.equal(new Set(children.map((event) => event.tenantId)).size, 2);
    for (const child of children) {
      const parent = parents.find((event) => event.operationId === child.parentOperationId);
      assert.ok(parent);
      assert.equal(parent.tenantId, child.tenantId);
      assert.equal(parent.requestId, child.requestId);
      assert.equal(child.counters['tenant.routing.operations']?.value, 1);
      assert.ok(Object.values(child.counters).every((counter) => counter.unit !== 'bytes'));
      assert.equal(child.status, 'ok');
      assert.equal(child.quality.complete, true);
    }
    assert.equal(service.meter.snapshot().activeSessions, 0);
    const meterQuality = service.meter.stats();
    assert.equal(meterQuality.dropped, 0);
    assert.equal(meterQuality.failedExports, 0);
    assert.equal(meterQuality.queueDepth, 0);
    assert.equal(meterQuality.exported, meterQuality.enqueued);
    assert.equal(events.length, meterQuality.exported);
    assert.equal(new Set(events.map((event) => event.operationId)).size, events.length);
    const encoded = JSON.stringify(events);
    for (const value of routingPrivateValues(fixture)) assert.equal(encoded.includes(value), false);
    assert.doesNotMatch(encoded, /implementationId|registryRevision|registryActivationGeneration/);
    return {
      technicalUsageEnabled: true,
      ...workload,
      routingChildren: children.length,
      httpParents: parents.length,
      tenantCount: 2,
      duplicateChildByteCounters: 0,
      meterDroppedEvents: meterQuality.dropped,
      meterFailedExports: meterQuality.failedExports,
    };
  },
  close: (service) => service.close(),
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(routingAdapter);
