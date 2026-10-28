// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { managed } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import type { ScimRecord } from '../../dist/index.js';
import { fixture } from '../fixture.js';

interface Point {
  attributes: { key: string; value?: { stringValue?: string } }[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
  histogram?: { dataPoints: Point[] };
  gauge?: { dataPoints: Point[] };
}
interface Envelope {
  resourceMetrics?: { scopeMetrics: { metrics: Metric[] }[] }[];
  resourceSpans?: unknown[];
}
for (const mode of ['standard', 'detailed'] as const)
  test(`Actual ${mode} SCIM SDK exports contain no bearer, user, tenant, profile or provider error data`, async () => {
    const f = await fixture(),
      envelopes: Envelope[] = [],
      logs: string[] = [];
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Envelope);
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const address = collector.address();
    assert.ok(address && typeof address === 'object');
    const sink = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString('utf8'));
        done();
      },
    });
    const app = await createApplication({
      service: { name: 'scim-observation', version: '1.0.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode, samplingRatio: 1 },
      plugins: [
        loggingPlugin({ destination: sink }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + address.port,
          allowInsecureLoopback: true,
          exportIntervalMs: 60000,
          exportTimeoutMs: 1000,
        }),
      ],
    });
    const markers = [
      'private-profile-user',
      'private-external-account',
      'private-storage-credential',
      'tenant-a',
      'provisioning-integration',
    ];
    let owner: ReturnType<typeof managed> | undefined;
    try {
      await app.start();
      owner = managed(capture(f.settings), undefined, undefined, {
        logger: app.logger,
        telemetry: app.telemetry,
      });
      owner.service.registerUsers(f.provider('Users'));
      const request = await f.request('POST', '/Users', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: markers[0],
        externalId: markers[1],
        active: true,
      });
      markers.push(request.headers.authorization!);
      const created = await owner.service.handle(request);
      assert.equal(created.status, 201);
      const value = created.body as ScimRecord;
      markers.push(value.id);
      const mutation = await f.request('PATCH', '/Users/' + value.id, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'replace', path: 'active', value: false }],
      });
      assert.equal(
        (
          await owner.service.handle({
            ...mutation,
            headers: { ...mutation.headers, 'if-match': created.headers.etag },
          })
        ).status,
        200,
      );
      assert.equal(
        (
          await owner.service.handle({
            ...mutation,
            headers: { ...mutation.headers, 'if-match': created.headers.etag },
          })
        ).status,
        412,
      );
      assert.equal(
        (
          await owner.service.handle(
            await f.request('GET', '/Users/' + value.id, undefined, 'tenant-b'),
          )
        ).status,
        403,
      );
      f.storageAvailable(false);
      assert.equal((await owner.service.handle(await f.request('GET', '/Users'))).status, 503);
      await app.telemetry.flush();
      await app.logger.flush();
    } finally {
      try {
        await owner?.close();
        await app.stop();
      } finally {
        collector.closeAllConnections();
        await new Promise<void>((resolve) => collector.close(() => resolve()));
        sink.end();
        await f.close();
      }
    }
    const metrics = envelopes
      .flatMap((envelope) => envelope.resourceMetrics ?? [])
      .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
    for (const name of ['scim.operations', 'scim.operation.duration.ms', 'scim.operations.active'])
      assert.ok(
        metrics.some((metric) => metric.name === name),
        name,
      );
    assert.ok(
      metrics.some(
        (metric) => metric.name === 'scim.operation.duration.ms' && metric.unit === 'ms',
      ),
    );
    assert.ok(envelopes.some((envelope) => (envelope.resourceSpans?.length ?? 0) > 0));
    const serialized = JSON.stringify({ envelopes, logs });
    for (const marker of markers)
      assert.ok(!serialized.includes(marker), 'Sensitive SCIM data was exported');
    for (const metric of metrics.filter((metric) => metric.name.startsWith('scim.')))
      for (const point of [
        ...(metric.sum?.dataPoints ?? []),
        ...(metric.histogram?.dataPoints ?? []),
        ...(metric.gauge?.dataPoints ?? []),
      ])
        for (const attribute of point.attributes)
          assert.ok(
            ['scim.operation', 'scim.resource', 'scim.outcome', 'scim.direction'].includes(
              attribute.key,
            ),
          );
  });
