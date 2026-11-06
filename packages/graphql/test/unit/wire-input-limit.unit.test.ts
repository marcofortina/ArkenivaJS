// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Agent, request } from 'node:https';
import { fixture, tlsFiles } from '../fixture.js';

test('Oversized HTTPS JSON bodies reject both wire framings before tenant verification or field effects and preserve endpoint recovery', async () => {
  let tenants = 0,
    policies = 0,
    effects = 0;
  const tls = await tlsFiles(),
    agent = new Agent({ keepAlive: true, maxSockets: 1 });
  const f = await fixture(
    {
      schema: 'type Query { ping: String! }',
      resolvers: {
        Query: {
          ping(_parent, _args, context) {
            effects++;
            assert.equal(context.auth?.tenantId, 'tenant-a');
            return 'pong';
          },
        },
      },
      security: {
        authorizeField() {
          policies++;
          return true;
        },
        limits: { maxDocumentBytes: 32, maxVariablesBytes: 32 },
      },
    },
    {
      tls: tls.tls,
      authorizeTenant(tenant) {
        tenants++;
        return tenant === 'tenant-a';
      },
    },
  ).catch(async (error: unknown) => {
    agent.destroy();
    await tls.close();
    throw error;
  });
  try {
    const authorization = await f.token(),
      query = '{ ping }',
      variables = { x: 'wire-private-value' },
      encoded = Buffer.from(JSON.stringify({ query, variables })),
      body = Buffer.concat([encoded, Buffer.alloc(16 * 1024 - encoded.length, 0x20)]);
    assert.ok(Buffer.byteLength(query) <= 32);
    assert.ok(Buffer.byteLength(JSON.stringify(variables)) <= 32);
    assert.deepEqual(JSON.parse(body.toString()), { query, variables });
    const post = (bytes: Buffer, framing: 'content-length' | 'chunked') =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const outgoing = request(
          new URL('/graphql', f.origin),
          {
            method: 'POST',
            agent,
            ca: tls.ca,
            headers: {
              'content-type': 'application/json',
              authorization,
              'x-tenant-id': 'wire-forged-tenant',
              ...(framing === 'content-length'
                ? { 'content-length': String(bytes.length) }
                : { 'transfer-encoding': 'chunked' }),
            },
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on('data', (chunk: Buffer) => chunks.push(chunk));
            response.once('error', reject);
            response.once('end', () =>
              resolve({
                status: response.statusCode ?? 0,
                body: Buffer.concat(chunks).toString(),
              }),
            );
          },
        );
        outgoing.once('error', reject);
        outgoing.setTimeout(3000, () =>
          outgoing.destroy(new Error('The bounded HTTPS wire request timed out')),
        );
        for (let offset = 0; offset < bytes.length; offset += 1024)
          outgoing.write(bytes.subarray(offset, offset + 1024));
        outgoing.end();
      });
    for (const framing of ['content-length', 'chunked'] as const) {
      const rejected = await post(body, framing),
        result = JSON.parse(rejected.body) as {
          errors: readonly { extensions: { code: string } }[];
        };
      assert.equal(rejected.status, 413, rejected.body);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0]?.extensions.code, 'EK_GQL_INPUT_LIMIT');
      assert.equal(tenants, 0);
      assert.equal(policies, 0);
      assert.equal(effects, 0);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.doesNotMatch(
        rejected.body + f.logs(),
        /wire-private-value|wire-forged-tenant|Bearer |FST_ERR_CTP_BODY_TOO_LARGE|bodyLimit/,
      );
    }
    assert.equal(f.service.stats().rejected, 2);
    const recovered = await post(Buffer.from(JSON.stringify({ query })), 'content-length');
    assert.equal(recovered.status, 200, recovered.body);
    assert.deepEqual(JSON.parse(recovered.body), { data: { ping: 'pong' } });
    assert.ok(tenants > 0);
    assert.equal(policies, 1);
    assert.equal(effects, 1);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.equal(f.service.stats().rejected, 2);
    assert.doesNotMatch(f.logs(), /wire-private-value|wire-forged-tenant|Bearer /);
  } finally {
    agent.destroy();
    try {
      await f.close();
    } finally {
      await tls.close();
    }
  }
});
