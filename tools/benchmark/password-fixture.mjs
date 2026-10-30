// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import * as argon2 from 'argon2';
import { securityStateFixture } from '../../examples/postgres/dist-test/integration/security-state-fixture.js';
import { nativePassword } from './password-workload.mjs';

/** Reuse the actual disposable SQL store; the loopback bridge exposes only its KDF budget calls. */
export async function startPasswordFixture(sampleVerifies = false) {
  assert.equal(typeof sampleVerifies, 'boolean');
  assert.equal(
    process.env.ARKENIVA_POSTGRES_DISPOSABLE,
    '1',
    'An owned disposable PostgreSQL fixture is required',
  );
  const backend = await securityStateFixture(),
    bearer = randomBytes(32).toString('base64url'),
    plain = randomBytes(24).toString('base64url'),
    tasks = new Set(),
    state = { completedCalls: 0, readCalls: 0, compareAndSetCalls: 0, committedWrites: 0 };
  const server = createServer((request, response) => {
    if (tasks.size >= 8) {
      response.writeHead(503, { connection: 'close' }).end();
      return;
    }
    const task = (async () => {
      const supplied = Buffer.from(String(request.headers['x-owned-provider'] ?? '')),
        expected = Buffer.from(bearer);
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/budget');
      assert.equal(supplied.length, expected.length);
      assert.ok(timingSafeEqual(supplied, expected));
      const chunks = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        assert.ok(bytes <= 16384);
        chunks.push(chunk);
      }
      const { method, args } = JSON.parse(Buffer.concat(chunks).toString());
      assert.ok(['read', 'compareAndSet'].includes(method));
      assert.ok(Array.isArray(args));
      assert.equal(args.length, method === 'read' ? 2 : 4);
      assert.equal(args[0], 'password.budgets.v1');
      const result = await backend.store[method](...args, { timeoutMs: 5000 });
      state.completedCalls++;
      if (method === 'read') state.readCalls++;
      else {
        state.compareAndSetCalls++;
        if (result.committed) state.committedWrites++;
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
  try {
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    const legacyPhc = await argon2.hash(plain, {
      type: argon2.argon2id,
      memoryCost: 4096,
      timeCost: 1,
      parallelism: 1,
      hashLength: 32,
    });
    const currentPhc = sampleVerifies ? (await nativePassword().hash(plain)).phc : undefined;
    if (sampleVerifies) assert.equal(await argon2.verify(currentPhc, plain), true);
    return {
      backend,
      state,
      fixture: {
        endpoint: 'http://127.0.0.1:' + server.address().port + '/budget',
        bearer,
        plain,
        legacyPhc,
        ...(sampleVerifies ? { sampleVerifies, currentPhc } : {}),
      },
      async durableCount() {
        const result = await backend.app.sql.query('main', {
          text: `SELECT COALESCE(sum((body::jsonb->>'count')::integer),0)::integer AS count FROM ${backend.schema}.security_records WHERE namespace='password.budgets.v1'`,
        });
        return result.rows[0].count;
      },
      async verifySampled(expectedBudget) {
        assert.equal(sampleVerifies, true);
        assert.equal(expectedBudget, 375);
        assert.equal(state.completedCalls, 2 * expectedBudget);
        assert.equal(state.readCalls, expectedBudget);
        assert.equal(state.compareAndSetCalls, expectedBudget);
        assert.equal(state.committedWrites, expectedBudget);
        assert.equal(await argon2.verify(currentPhc, plain), true);
        assert.equal(await argon2.verify(currentPhc, plain + 'x'), false);
        const quotas = await backend.app.sql.queryOne('main', {
          text: `SELECT COALESCE(sum((body::jsonb->>'count')::integer),0)::integer AS count,max((body::jsonb->>'count')::integer) AS maximum,bool_and(body::jsonb->>'kind'='kdf') AS kinds_valid,count(*)::integer AS buckets FROM ${backend.schema}.security_records WHERE namespace='password.budgets.v1'`,
        });
        assert.equal(quotas.kinds_valid, true);
        assert.ok(quotas.buckets > 0 && quotas.buckets <= expectedBudget);
        assert.ok(quotas.maximum > 0 && quotas.maximum <= 1000);
        const persistedBudget = quotas.count;
        assert.equal(persistedBudget, expectedBudget);
        return {
          persistedBudget,
          completedStoreCalls: state.completedCalls,
          successfulReadCalls: state.readCalls,
          successfulCompareAndSetCalls: state.compareAndSetCalls,
          committedBudgetWrites: state.committedWrites,
          independentlyVerifiedCurrentPhc: true,
          technicalLimitPerMinute: 1000,
          parentProviderResources: null,
          postgresServerResources: null,
          releaseGate: false,
        };
      },
      async close() {
        server.closeAllConnections();
        await new Promise((done) => server.close(done));
        await Promise.allSettled([...tasks]);
        await backend.close();
      },
    };
  } catch (error) {
    server.closeAllConnections();
    if (server.listening) await new Promise((done) => server.close(done));
    await backend.close();
    throw error;
  }
}
