// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { records } from '../fixtures/events.js';
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
import { createServer } from 'node:http';
import { createHttpMeterExporter } from '@arkenivajs/metering';
async function collector() {
  const calls: {
    method: string | undefined;
    path: string | undefined;
    headers: Record<string, string | string[] | undefined>;
    body: unknown;
  }[] = [];
  let status = 202,
    hang = false;
  const server = createServer(async (request, reply) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    calls.push({
      method: request.method,
      path: request.url,
      headers: request.headers,
      body: JSON.parse(Buffer.concat(chunks).toString()),
    });
    if (hang) return;
    reply.statusCode = status;
    reply.end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    calls,
    status: (value: number) => {
      status = value;
    },
    hang: () => {
      hang = true;
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test('EK-METER-001 actual HTTP batches use fixed version/path/authentication and only durable-contract 202 acknowledgment', async () => {
  const server = await collector();
  const events = await records(2);
  const exporter = createHttpMeterExporter({
    endpoint: server.endpoint,
    environment: 'test',
    allowInsecureLoopback: true,
    authorization: () => 'Bearer fake-collector-token',
  });
  try {
    await exporter.export(events, {});
    const call = server.calls[0]!;
    assert.equal(call.method, 'POST');
    assert.equal(call.path, '/v1/metering/events');
    assert.equal(call.headers.authorization, 'Bearer fake-collector-token');
    assert.equal(call.headers['x-arkenivajs-metering-version'], '1.0.0');
    assert.deepEqual(call.body, { schemaVersion: '1.0.0', events });
    for (const status of [200, 401, 429, 503]) {
      server.status(status);
      await assert.rejects(
        exporter.export(events, {}),
        (error) =>
          code('EK_METER_EXPORT')(error) &&
          (error as KitError).retryable === (status >= 500 || status === 429),
      );
    }
    server.hang();
    await assert.rejects(exporter.export(events, { timeoutMs: 10 }), code('EK_TIMEOUT'));
  } finally {
    await exporter.close();
    await server.close();
  }
  await assert.rejects(exporter.export(events, {}), code('EK_RESOURCE_CLOSED'));
});

test('EK-METER-001 HTTP credentials, trust configuration and cancelled authorization fail before transport', async () => {
  const server = await collector();
  const events = await records();
  try {
    for (const policy of [
      { endpoint: server.endpoint },
      { endpoint: 'http://metadata.invalid', allowInsecureLoopback: true, environment: 'test' },
      { endpoint: server.endpoint + '/path', allowInsecureLoopback: true, environment: 'test' },
      {
        endpoint: 'https://collector.invalid',
        allowInsecureLoopback: true,
        environment: 'production',
      },
      { endpoint: 'https://user:password@collector.invalid' },
      { endpoint: 'invalid' },
    ])
      assert.throws(
        () => createHttpMeterExporter({ authorization: () => 'Bearer fake', ...policy } as never),
        code('EK_CONFIG_INVALID'),
      );
    for (const authorization of [
      () => 'Basic fake',
      () => 'Bearer fake\r\n',
      () => {
        throw new Error('fake-private-auth');
      },
    ]) {
      const exporter = createHttpMeterExporter({
        endpoint: server.endpoint,
        environment: 'test',
        allowInsecureLoopback: true,
        authorization,
      });
      try {
        await assert.rejects(exporter.export(events, {}), code('EK_METER_EXPORT'));
        await assert.rejects(exporter.export([], {}), code('EK_METER_EXPORT'));
      } finally {
        await exporter.close();
      }
    }
    const hanging = createHttpMeterExporter({
      endpoint: server.endpoint,
      environment: 'test',
      allowInsecureLoopback: true,
      authorization: () => new Promise<string>(() => {}),
    });
    await assert.rejects(
      hanging.export(events, { signal: AbortSignal.abort() }),
      code('EK_ABORTED'),
    );
    await assert.rejects(hanging.export(events, { timeoutMs: 5 }), code('EK_TIMEOUT'));
    await hanging.close();
    assert.equal(server.calls.length, 0);
  } finally {
    await server.close();
  }
});
