// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { setImmediate } from 'node:timers/promises';
import { COMPONENTS } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { graphqlPlugin } from '@arkenivajs/graphql';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { runPureWorker } from './pure-worker.mjs';
import {
  GRAPHQL_COMPARISON,
  graphqlCorpus,
  nativeGraphql,
  verifyGraphql,
  graphqlWorkload,
  graphqlObservations,
} from './graphql-workload.mjs';

export const graphqlAdapter = {
  name: 'graphql',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeGraphql,
  async framework(fixture, mode) {
    const corpus = graphqlCorpus(fixture),
      metered = mode === 'STANDARD' || mode === 'DETAILED';
    const workspace = metered
      ? await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-comparison-'))
      : undefined;
    return {
      key: GRAPHQL_COMPARISON,
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
            [fixture.tenant, fixture.otherTenant].includes(tenant),
        }),
        ...(metered ? [meteringPlugin({ workspace, dependencies: ['telemetry'] })] : []),
        apiPlugin({ dependencies: ['security', ...(metered ? ['telemetry', 'metering'] : [])] }),
        graphqlPlugin({
          schema: corpus.schema,
          resolvers: corpus.resolvers,
          security: {
            auth: { required: true, scopes: ['orders:read'] },
            authorizeField: ({ context, field }) =>
              field.fieldName !== 'privateNote' &&
              corpus.authorized(context, field.operation === 'mutation'),
            limits: { maxDocumentBytes: 2048, maxVariablesBytes: 2048, maxResultBytes: 4096 },
          },
        }),
      ],
      plugin: {
        id: 'graphql-comparison-probe',
        version: '0.1.0',
        capabilities: new Set(),
        dependencies: ['graphql', 'api', ...(metered ? ['metering'] : [])],
        init(context) {
          const api = context.require(COMPONENTS.api);
          api.native().addHook('onRequest', async () => corpus.received());
          api
            .native()
            .addHook('onResponse', async (_request, reply) => corpus.completed(reply.statusCode));
          context.provide(GRAPHQL_COMPARISON, {
            api,
            stats: corpus.stats,
            protocol: corpus.protocol,
            ...(metered ? { meter: context.require(COMPONENTS.meter), workspace } : {}),
          });
        },
        close() {},
      },
      telemetryOptions: { labelValues: { route: ['/graphql', 'unmatched'] } },
      dispose: () => (workspace ? rm(workspace, { recursive: true, force: true }) : undefined),
    };
  },
  verify: verifyGraphql,
  workload: graphqlWorkload,
  async complete(service, context) {
    await setImmediate();
    const observations = graphqlObservations(service, context);
    if (!service.meter) return { ...observations, technicalUsageEnabled: false };
    await service.meter.flush();
    assert.equal(service.meter.snapshot().activeSessions, 0);
    const events = (await readFile(join(service.workspace, 'usage.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    const children = events.filter((event) => event.operation.startsWith('graphql.')),
      parents = events.filter((event) => event.operation === 'POST /graphql');
    assert.equal(children.length, observations.expectedGraphqlChildren);
    assert.equal(parents.length, observations.authenticatedHttpRequests);
    assert.equal(events.length, children.length + parents.length);
    assert.equal(new Set(children.map((event) => event.tenantId)).size, 2);
    for (const child of children) {
      const parent = parents.find((event) => event.operationId === child.parentOperationId);
      assert.ok(parent);
      assert.equal(parent.tenantId, child.tenantId);
      assert.equal(parent.requestId, child.requestId);
      assert.ok(Object.values(child.counters).every((counter) => counter.unit !== 'bytes'));
    }
    return {
      ...observations,
      technicalUsageEnabled: true,
      graphqlChildren: children.length,
      httpParents: parents.length,
      tenantCount: 2,
      duplicateGraphqlByteCounters: 0,
    };
  },
  close: (service) => service.close(),
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(graphqlAdapter);
