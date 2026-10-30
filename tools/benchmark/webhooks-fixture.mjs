// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { securityStateFixture } from '../../examples/postgres/dist-test/integration/security-state-fixture.js';

/** Only the parent owns SQL credentials, authentication state and the ephemeral test key. */
export async function startWebhookFixture() {
  assert.equal(
    process.env.ARKENIVA_POSTGRES_DISPOSABLE,
    '1',
    'An owned disposable PostgreSQL fixture is required',
  );
  const backend = await securityStateFixture(),
    bearer = randomBytes(32).toString('base64url'),
    key = randomBytes(32),
    tasks = new Set();
  const state = { claims: 0, acceptedClaims: 0, authorizations: 0, secretReads: 0 };
  const identity = {
    issuer: 'https://webhook-comparison.invalid',
    subject: 'owned-receiver',
    audience: ['webhooks'],
    scopes: ['webhooks:use'],
    claims: {},
  };
  const principal = {
    issuer: identity.issuer,
    subject: identity.subject,
    tenant: {
      tenantId: 'owned-comparison-tenant',
      identity,
      verifiedAt: new Date().toISOString(),
      source: 'service-identity',
    },
  };
  const server = createServer((request, response) => {
    const task = (async () => {
      const supplied = Buffer.from(String(request.headers['x-owned-provider'] ?? '')),
        expected = Buffer.from(bearer);
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/provider');
      assert.equal(supplied.length, expected.length);
      assert.ok(timingSafeEqual(supplied, expected));
      const chunks = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        assert.ok(bytes <= 16384);
        chunks.push(chunk);
      }
      const { method, args } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      assert.ok(Array.isArray(args));
      let result;
      if (method === 'authorize') {
        assert.equal(args.length, 2);
        assert.ok(['webhooks.sign', 'webhooks.verify'].includes(args[0]));
        assert.equal(args[1].destinationId, 'receiver');
        assert.equal(args[1].eventId, 'owned-event');
        assert.ok(args[1].keyId === undefined || args[1].keyId === 'one');
        state.authorizations++;
        result = principal;
      } else if (method === 'secret') {
        assert.deepEqual(args, ['current']);
        state.secretReads++;
        result = { encoded: key.toString('base64url'), version: 'one' };
      } else {
        assert.equal(method, 'claimOnce');
        assert.equal(args.length, 3);
        assert.equal(args[0], 'webhooks.nonces.v1');
        assert.match(args[1], /^[a-f0-9]{64}$/);
        assert.ok(Date.parse(args[2]) > Date.now() && Date.parse(args[2]) <= Date.now() + 600000);
        result = await backend.store.claimOnce(...args, { timeoutMs: 5000 });
        state.claims++;
        if (result) state.acceptedClaims++;
      }
      response
        .writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify({ result }));
    })().catch(() => response.writeHead(500).end('{}'));
    tasks.add(task);
    void task.finally(() => tasks.delete(task));
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  const close = async () => {
    server.closeAllConnections();
    if (server.listening) await new Promise((done) => server.close(done));
    await Promise.allSettled([...tasks]);
    try {
      await backend.close();
    } finally {
      key.fill(0);
    }
  };
  try {
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    return {
      fixture: {
        endpoint: 'http://127.0.0.1:' + server.address().port + '/provider',
        bearer,
        marker: 'owned-webhook-private-payload',
      },
      privacyValues: [
        bearer,
        key.toString('base64url'),
        key.toString('hex'),
        principal.tenant.tenantId,
        principal.subject,
      ],
      state,
      async durableCount() {
        const result = await backend.app.sql.query('main', {
          text: `SELECT count(*)::integer AS count FROM ${backend.schema}.security_claims WHERE namespace='webhooks.nonces.v1'`,
        });
        return result.rows[0].count;
      },
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
