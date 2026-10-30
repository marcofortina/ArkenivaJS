// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer, get } from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { createAuthService } from '@arkenivajs/security';
import { createIssuer } from './http-issuer.mjs';

/** The independent parent consumes actual finite SSE responses under signed authentication. */
export async function startRealtimeFixture(sampleStreams = false) {
  assert.equal(typeof sampleStreams, 'boolean');
  const issuer = await createIssuer(),
    grants = new Map(),
    work = new Set(),
    requests = new Set(),
    privacyValues = [
      '127.0.0.1',
      'localhost',
      'synthetic-user',
      'synthetic-tenant',
      'owned_realtime_message',
      'Unicode: π 😀',
    ];
  let auth,
    bridge,
    closing = false,
    observerActive = false,
    registrations = 0,
    authorizations = 0,
    streams = 0,
    bytes = 0;
  const remember = (value) => {
    if (typeof value === 'string' && value && !privacyValues.includes(value))
      privacyValues.push(value);
  };
  const close = async () => {
    closing = true;
    try {
      bridge?.closeAllConnections();
      for (const request of requests)
        request.destroy(new Error('The owned realtime observer is closing'));
      if (bridge?.listening) await new Promise((done) => bridge.close(done));
      await Promise.allSettled([...work]);
      assert.equal(requests.size, 0);
    } finally {
      try {
        await auth?.close();
      } finally {
        await issuer.close();
      }
    }
  };
  try {
    const token = await issuer.token(),
      parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    const fixture = {
      issuer: issuer.origin,
      audience: issuer.audience,
      token,
      invalidToken: parts.join('.'),
      foreignTenantToken: await issuer.token({ claims: { tenant_id: 'foreign-tenant' } }),
      tenant: 'synthetic-tenant',
    };
    Object.values(fixture).forEach(remember);
    const expected = Buffer.from(
      ['Unicode: π 😀', 'first\nsecond\n', '']
        .map(
          (data, index) =>
            'id: ' +
            fixture.tenant +
            '_' +
            (index + 1) +
            '\nevent: update\n' +
            data
              .split('\n')
              .map((line) => 'data: ' + line + '\n')
              .join('') +
            '\n',
        )
        .join(''),
    );
    const expectedDigest = createHash('sha256').update(expected).digest('hex');
    remember(expected.toString());
    if (sampleStreams) {
      auth = await createAuthService({
        issuer: fixture.issuer,
        audience: fixture.audience,
        environment: 'test',
        allowInsecureLoopback: true,
        algorithms: ['RS256'],
        jwksUrl: fixture.issuer + '/keys',
        authorizeTenant: (_identity, tenant) => tenant === fixture.tenant,
      });
      const observerKey = randomBytes(32).toString('base64url');
      remember(observerKey);
      const authorize = async () => {
        const identity = await auth.verifyBearer('Bearer ' + token),
          tenant = auth.tenantFrom(identity);
        assert.equal(auth.isVerifiedTenant(tenant), true);
        assert.equal(tenant.tenantId, fixture.tenant);
        assert.equal(identity.issuer, fixture.issuer);
        assert.equal(identity.subject, 'synthetic-user');
      };
      async function observe(origin) {
        let outgoing,
          closed = Promise.resolve();
        const answer = new Promise((done, reject) => {
          outgoing = get(
            origin + '/events',
            {
              agent: false,
              headers: { authorization: 'Bearer ' + token, accept: 'text/event-stream' },
              signal: AbortSignal.timeout(4000),
            },
            (response) => {
              const chunks = [];
              let size = 0;
              response.on('data', (chunk) => {
                size += chunk.length;
                if (size > 4096)
                  response.destroy(new Error('The owned SSE observer exceeded its response bound'));
                else chunks.push(Buffer.from(chunk));
              });
              response.once('error', reject);
              response.once('aborted', () =>
                reject(new Error('The owned SSE observer received an incomplete response')),
              );
              response.once('end', () =>
                done({
                  status: response.statusCode,
                  mediaType: response.headers['content-type'],
                  body: Buffer.concat(chunks),
                }),
              );
            },
          );
          requests.add(outgoing);
          outgoing.once('error', reject);
          outgoing.once('socket', (socket) => {
            closed = new Promise((done) => {
              if (socket.closed) done();
              else socket.once('close', done);
            });
          });
        });
        try {
          const response = await answer;
          assert.equal(response.status, 200);
          assert.equal(response.mediaType, 'text/event-stream');
          assert.deepEqual(response.body, expected);
          assert.equal(createHash('sha256').update(response.body).digest('hex'), expectedDigest);
          return {
            actualHttpStatus: 200,
            actualEvents: 3,
            actualUtf8Bytes: response.body.length,
            tenantScopedFramesVerified: true,
            physicalSocketClosed: true,
          };
        } finally {
          outgoing.destroy();
          await closed;
          requests.delete(outgoing);
        }
      }
      bridge = createServer((request, response) => {
        if (closing || work.size >= 8) {
          response.writeHead(503, { connection: 'close' }).end();
          return;
        }
        const task = (async () => {
          assert.equal(request.method, 'POST');
          assert.equal(request.url, '/observe');
          const actual = Buffer.from(request.headers.authorization ?? ''),
            approved = Buffer.from('Bearer ' + observerKey);
          assert.equal(actual.length, approved.length);
          assert.ok(timingSafeEqual(actual, approved));
          const chunks = [];
          let size = 0;
          for await (const chunk of request) {
            size += chunk.length;
            assert.ok(size <= 4096);
            chunks.push(chunk);
          }
          const { method, args } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          assert.ok(Array.isArray(args) && args.length === 1);
          let result;
          if (method === 'register') {
            assert.ok(registrations < 4);
            registrations++;
            const origin = new URL(args[0]);
            assert.equal(origin.protocol, 'http:');
            assert.equal(origin.hostname, '127.0.0.1');
            assert.ok(origin.port && origin.origin === args[0]);
            await authorize();
            assert.equal(closing, false);
            const id = randomUUID();
            remember(id);
            remember(origin.origin);
            grants.set(id, { origin: origin.origin, completed: 0, active: false });
            result = { grantId: id, expectedUtf8Bytes: expected.length };
          } else {
            assert.equal(method, 'read');
            const grant = grants.get(args[0]);
            assert.ok(grant);
            assert.equal(grant.active, false);
            assert.ok(grant.completed < 120 && streams < 480);
            assert.equal(requests.size, 0);
            assert.equal(observerActive, false);
            grant.active = true;
            observerActive = true;
            try {
              await authorize();
              authorizations++;
              assert.equal(closing, false);
              result = await observe(grant.origin);
              grant.completed++;
              streams++;
              bytes += result.actualUtf8Bytes;
            } finally {
              grant.active = false;
              observerActive = false;
            }
          }
          response
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ result }));
        })()
          .catch(() => {
            if (!response.headersSent && !response.destroyed) response.writeHead(400).end();
            else response.destroy();
          })
          .finally(() => work.delete(task));
        work.add(task);
      });
      bridge.requestTimeout = 5000;
      bridge.headersTimeout = 5000;
      await new Promise((done, reject) => {
        bridge.once('error', reject);
        bridge.listen(0, '127.0.0.1', done);
      });
      Object.assign(fixture, {
        sampleStreams,
        observerUrl: 'http://127.0.0.1:' + bridge.address().port + '/observe',
        observerKey,
      });
      Object.values(fixture).forEach(remember);
    }
    return {
      fixture,
      privacyValues,
      close,
      observations: () => ({
        registeredOwnedListeners: grants.size,
        observedStreams: streams,
        activeObserverSockets: requests.size,
        completedAuthorizations: authorizations,
      }),
      verify(expectedStreams = 0) {
        assert.equal(expectedStreams, sampleStreams ? 480 : 0);
        const observed = issuer.observations();
        assert.equal(observed.jwks, sampleStreams ? 5 : 4);
        assert.equal(observed.discovery, 0);
        assert.equal(observed.unknown, 0);
        assert.equal(streams, expectedStreams);
        assert.equal(requests.size, 0);
        assert.equal(work.size, 0);
        assert.equal(observerActive, false);
        if (sampleStreams) {
          assert.equal(grants.size, 4);
          assert.ok(
            [...grants.values()].every(
              (grant) => grant.completed === 120 && grant.active === false,
            ),
          );
          assert.equal(authorizations, expectedStreams);
          assert.equal(bytes, expectedStreams * expected.length);
        }
        return {
          actualJwksRequests: observed.jwks,
          ...(sampleStreams
            ? {
                independentlyObservedHttpStreams: streams,
                independentlyObservedSseEvents: streams * 3,
                independentlyObservedUtf8Bytes: bytes,
                actualRuntimeAuthorizations: authorizations,
                registeredOwnedListeners: grants.size,
                activeObserverSockets: requests.size,
                pendingObserverWork: work.size,
                maximumStreamsPerProfile: 120,
                parentObserverResources: null,
                parentAuthenticationResources: null,
                parentIssuerResources: null,
              }
            : {}),
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
