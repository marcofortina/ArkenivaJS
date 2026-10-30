// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startServer } from '../../packages/security-oauth-client/dist-test/unit/server.js';
import { securityStateFixture } from '../../examples/postgres/dist-test/integration/security-state-fixture.js';

/** The parent owns a verified HTTPS issuer, SQL schema and authenticated test provider bridge. */
export async function startOAuthFixture() {
  assert.equal(
    process.env.ARKENIVA_POSTGRES_DISPOSABLE,
    '1',
    'An owned disposable PostgreSQL fixture is required',
  );
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-oauth-comparison-'));
  const trustAnchorFile = join(directory, 'issuer.pem'),
    keyFile = join(directory, 'issuer.key');
  const bearer = randomBytes(32).toString('base64url'),
    material = new Map([
      ['enc', randomBytes(32)],
      ['mac', randomBytes(32)],
    ]),
    tasks = new Set();
  const state = { reads: 0, writes: 0, committedWrites: 0, authorizations: 0 },
    budgetRows = new Map();
  const owner = createHash('sha256').update('arkenivajs.oauth.technical-budget.v1').digest('hex');
  let issuer, backend, bridge;
  const durableCount = async () => {
    const result = await backend.app.sql.query('main', {
      text: `SELECT COALESCE(sum((body::jsonb->>'count')::integer),0)::integer AS count FROM ${backend.schema}.security_records WHERE namespace='oauth.budgets.v1'`,
    });
    return result.rows[0].count;
  };
  const close = async () => {
    if (bridge) {
      bridge.closeAllConnections();
      if (bridge.listening) await new Promise((done) => bridge.close(done));
    }
    await Promise.allSettled([...tasks]);
    try {
      await issuer?.close();
    } finally {
      try {
        await backend?.close();
      } finally {
        for (const value of material.values()) value.fill(0);
        await rm(directory, { recursive: true, force: true });
      }
    }
  };
  try {
    await chmod(directory, 0o700);
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=Owned OAuth Comparison',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
        '-keyout',
        keyFile,
        '-out',
        trustAnchorFile,
      ],
      { timeout: 10000, maxBuffer: 65536 },
    );
    await chmod(keyFile, 0o600);
    issuer = await startServer({
      key: await readFile(keyFile),
      cert: await readFile(trustAnchorFile),
    });
    material.set('client', Buffer.from(issuer.secret));
    backend = await securityStateFixture();
    const identity = {
      issuer: 'https://oauth-comparison.invalid',
      subject: 'owned-machine',
      audience: ['oauth'],
      scopes: ['oauth:use'],
      claims: {},
    };
    const principal = {
      issuer: identity.issuer,
      subject: identity.subject,
      tenant: {
        tenantId: 'owned-oauth-tenant',
        identity,
        verifiedAt: new Date().toISOString(),
        source: 'service-identity',
      },
    };
    bridge = createServer((request, response) => {
      if (tasks.size >= 8) {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
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
          assert.equal(args[0], 'oauth.client_credentials');
          assert.equal(args[1].oauth?.clientId, 'owned');
          assert.equal(args[1].oauth.audience, issuer.audience);
          assert.deepEqual(args[1].oauth.scopes, ['orders.read']);
          state.authorizations++;
          result = principal;
        } else if (method === 'secret') {
          assert.equal(args.length, 1);
          assert.ok(material.has(args[0]));
          result = { encoded: material.get(args[0]).toString('base64url'), version: 'one' };
        } else {
          assert.ok(['read', 'compareAndSet'].includes(method));
          assert.equal(args[0], 'oauth.budgets.v1');
          assert.match(args[1], /^grant:\d{1,12}$/);
          if (method === 'read') {
            assert.equal(args.length, 2);
            result = await backend.store.read(...args, { timeoutMs: 5000 });
            state.reads++;
            if (!budgetRows.has(args[1])) {
              assert.ok(budgetRows.size < 8);
              budgetRows.set(args[1], { initial: result?.count ?? 0, committed: 0 });
            }
          } else {
            assert.equal(args.length, 4);
            const next = args[3];
            assert.deepEqual(
              Object.keys(next).sort(),
              ['count', 'expiresAt', 'kind', 'minute', 'ownerKey'].sort(),
            );
            assert.equal(next.kind, 'oauth-budget-v1');
            assert.equal(next.ownerKey, owner);
            assert.equal(args[1], 'grant:' + next.minute);
            assert.ok(
              Number.isSafeInteger(next.minute) &&
                Math.abs(next.minute - Math.floor(Date.now() / 60000)) <= 1,
            );
            assert.ok(Number.isSafeInteger(next.count) && next.count >= 1 && next.count <= 1000);
            assert.equal(next.expiresAt, new Date((next.minute + 2) * 60000).toISOString());
            result = await backend.store.compareAndSet(...args, { timeoutMs: 5000 });
            state.writes++;
            if (result.committed) {
              assert.ok(budgetRows.has(args[1]));
              budgetRows.get(args[1]).committed++;
              state.committedWrites++;
            }
          }
        }
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ result }));
      })().catch(() => {
        if (!response.destroyed) response.writeHead(500).end('{}');
      });
      tasks.add(task);
      void task.finally(() => tasks.delete(task));
    });
    bridge.requestTimeout = 5000;
    bridge.headersTimeout = 5000;
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    return {
      fixture: {
        endpoint: 'http://127.0.0.1:' + bridge.address().port + '/provider',
        bearer,
        issuer: issuer.issuer,
        clientId: issuer.clientId,
        redirectUri: issuer.redirectUri,
        audience: issuer.audience,
      },
      trustAnchorFile,
      state,
      issuerCounts: issuer.counts,
      privacyValues: [
        bearer,
        issuer.secret,
        principal.subject,
        principal.tenant.tenantId,
        ...[...material.values()].flatMap((value) => [
          value.toString('base64url'),
          value.toString('hex'),
        ]),
      ],
      durableCount,
      async verify(expectedGrants) {
        assert.ok(
          Number.isSafeInteger(expectedGrants) && expectedGrants >= 8 && expectedGrants <= 488,
        );
        const persistedGrants = await durableCount();
        assert.equal(persistedGrants, expectedGrants);
        assert.equal(issuer.counts.token, expectedGrants);
        assert.equal(issuer.counts.discovery, 4);
        for (const operation of ['authorize', 'refresh', 'revoke', 'jwks'])
          assert.equal(issuer.counts[operation], 0);
        assert.equal(state.authorizations, expectedGrants);
        assert.equal(state.reads, expectedGrants);
        assert.equal(state.writes, expectedGrants);
        assert.equal(state.committedWrites, expectedGrants);
        let persistedDelta = 0;
        for (const [id, baseline] of budgetRows) {
          const record = await backend.store.read('oauth.budgets.v1', id, { timeoutMs: 5000 });
          assert.equal(record.kind, 'oauth-budget-v1');
          assert.equal(record.ownerKey, owner);
          assert.equal(record.count, baseline.initial + baseline.committed);
          persistedDelta += record.count - baseline.initial;
        }
        assert.equal(persistedDelta, expectedGrants);
        return {
          persistedGrants,
          actualTokenRequests: issuer.counts.token,
          authorizedGrants: state.authorizations,
          persistedBudgetDelta: persistedDelta,
          committedBudgetWrites: state.committedWrites,
          budgetRows: budgetRows.size,
          discoveryRequests: issuer.counts.discovery,
          interactiveAuthorizationRequests: issuer.counts.authorize,
          refreshRequests: issuer.counts.refresh,
          revocationRequests: issuer.counts.revoke,
          parentIssuerResources: null,
          parentProviderResources: null,
          postgresServerResources: null,
          tokenValidationScope:
            'Worker checks token contents privately; independent parent verifies issuer request and durable budget counts, without opaque-token introspection',
          releaseGate: false,
        };
      },
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
