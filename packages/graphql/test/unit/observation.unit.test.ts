// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { COMPONENTS } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { fixture, send } from '../fixture.js';

interface Point {
  asDouble?: number;
  asInt?: string;
  count?: string;
  sum?: number;
  attributes?: { key: string; value: { stringValue?: string } }[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
  histogram?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
}

test(
  'Actual OpenTelemetry exports bounded GraphQL metrics and exactly one existing HTTP response-byte observation',
  { timeout: 15000 },
  async () => {
    const envelopes: Envelope[] = [];
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk);
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString()) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    let deniedEffects = 0;
    const f = await fixture(
      {
        schema:
          'type Item { value: String! } type Query { ping(secret: String): String! items: [Item!]! privateValue: String }',
        resolvers: {
          Query: {
            ping: (_parent, args) => args.secret ?? 'pong',
            items: () => [{ id: 1 }, { id: 2 }],
            privateValue: () => {
              deniedEffects++;
              return 'never-disclose';
            },
          },
        },
        loaders: {
          Item: {
            value: {
              load: async (requests) =>
                requests.map((request) => String((request.parent as { id: number }).id)),
            },
          },
        },
        security: {
          authorizeField: ({ field }) => field.fieldName !== 'privateValue',
          limits: { maxAliases: 1 },
        },
      },
      {
        telemetry: { mode: 'detailed', samplingRatio: 1 },
        plugins: [
          telemetryPlugin({
            endpoint: `http://127.0.0.1:${address.port}`,
            allowInsecureLoopback: true,
            exportTimeoutMs: 500,
            exportIntervalMs: 1000,
            labelValues: { route: ['/graphql'] },
          }),
        ],
      },
    );
    try {
      const authorization = await f.token();
      const accepted = await send(
        f.origin,
        {
          query:
            'query UserChosenName($secret: String!) { __typename ping(secret: $secret) items { value } }',
          variables: { secret: 'never-export-input' },
        },
        { headers: { authorization } },
      );
      assert.equal(accepted.status, 200, accepted.body);
      assert.deepEqual(accepted.json(), {
        data: {
          __typename: 'Query',
          ping: 'never-export-input',
          items: [{ value: '1' }, { value: '2' }],
        },
      });
      assert.equal((await send(f.origin, { query: '{ ping }' })).status, 401);
      assert.equal(
        (await send(f.origin, '{broken', { raw: true, headers: { authorization } })).status,
        400,
      );
      assert.equal(
        (await send(f.origin, { query: '{ a: ping b: ping }' }, { headers: { authorization } }))
          .status,
        400,
      );
      const denied = await send(
        f.origin,
        { query: '{ privateValue }' },
        { headers: { authorization } },
      );
      assert.equal(denied.status, 200, denied.body);
      assert.match(denied.body, /EK_GQL_FORBIDDEN/);
      assert.equal(deniedEffects, 0);
      await f.app.telemetry.flush();
      const metrics = envelopes.flatMap(
        (envelope) =>
          envelope.resourceMetrics?.flatMap((resource) =>
            resource.scopeMetrics.flatMap((scope) => scope.metrics),
          ) ?? [],
      );
      const named = (name: string) => metrics.filter((metric) => metric.name === name);
      const total = (name: string) =>
        named(name)
          .flatMap((metric) => metric.sum?.dataPoints ?? [])
          .reduce((sum, point) => sum + (point.asDouble ?? Number(point.asInt)), 0);
      assert.equal(total('arkenivajs.graphql.requests'), 5);
      assert.equal(total('arkenivajs.graphql.denied'), 4);
      for (const name of [
        'arkenivajs.graphql.operation.duration',
        'arkenivajs.graphql.field.duration',
      ])
        assert.ok(named(name).every((metric) => metric.unit === 's') && named(name).length > 0);
      assert.ok(
        named('arkenivajs.graphql.operation.complexity').some((metric) =>
          metric.histogram?.dataPoints.some((point) => Number(point.count) > 0 && point.sum! > 0),
        ),
      );
      assert.ok(
        named('arkenivajs.graphql.loader.batch_size').some((metric) =>
          metric.histogram?.dataPoints.some((point) => point.sum === 2),
        ),
      );
      assert.equal(
        named('http.server.request.duration')
          .flatMap((metric) => metric.histogram?.dataPoints ?? [])
          .reduce((sum, point) => sum + Number(point.count), 0),
        5,
      );
      assert.equal(
        named('arkenivajs.http.body.bytes')
          .flatMap((metric) => metric.histogram?.dataPoints ?? [])
          .reduce((sum, point) => sum + Number(point.count), 0),
        5,
      );
      assert.equal(metrics.filter((metric) => /graphql.*bytes/.test(metric.name)).length, 0);
      assert.doesNotMatch(
        JSON.stringify(envelopes) + f.logs(),
        /UserChosenName|never-export-input|tenant-a|Bearer |never-disclose/,
      );
      for (const attributes of [
        { 'graphql.kind': 'unapproved' },
        { 'graphql.outcome': 'unapproved' },
        { 'graphql.category': 'unapproved' },
        { 'graphql.field_group': 'Customer.private' },
        { tenant_id: 'tenant-a' },
      ])
        assert.throws(
          () => f.app.telemetry.addCounter('arkenivajs.graphql.requests', 1, attributes),
          { code: 'EK_CONFIG_INVALID' },
        );
    } finally {
      await f.close();
      collector.closeAllConnections();
      await new Promise<void>((resolve) => collector.close(() => resolve()));
    }
  },
);

test('Throwing diagnostic providers cannot repeat a mutation or bypass field policy', async () => {
  const broken = () => {
    throw new Error('Private diagnostic failure');
  };
  const telemetry: Telemetry = {
    withSpan: broken,
    measure: broken,
    addCounter: broken,
    recordHistogram: broken,
    setGauge: broken,
    flush: async () => {},
  };
  const provider: Plugin = {
    id: 'telemetry',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  let effects = 0;
  const f = await fixture(
    {
      schema: 'type Query { ping: String! } type Mutation { update: Int! denied: Int }',
      resolvers: {
        Query: { ping: () => 'pong' },
        Mutation: { update: () => ++effects, denied: () => ++effects },
      },
      security: { authorizeField: ({ field }) => field.fieldName !== 'denied' },
    },
    { plugins: [provider], telemetry: { mode: 'detailed' } },
  );
  try {
    const headers = { authorization: await f.token() };
    const accepted = await send(f.origin, { query: 'mutation { update }' }, { headers });
    assert.equal(accepted.status, 200, accepted.body);
    assert.deepEqual(accepted.json(), { data: { update: 1 } });
    const denied = await send(f.origin, { query: 'mutation { denied }' }, { headers });
    assert.equal(denied.status, 200, denied.body);
    assert.match(denied.body, /EK_GQL_FORBIDDEN/);
    assert.equal(effects, 1);
    assert.doesNotMatch(accepted.body + denied.body + f.logs(), /Private diagnostic failure/);
  } finally {
    await f.close();
  }
});
