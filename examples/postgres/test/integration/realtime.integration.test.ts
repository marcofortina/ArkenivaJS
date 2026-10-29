// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer, get } from 'node:http';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import type { Plugin, AuthService } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { createAuthService } from '@arkenivajs/security';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { realtimePlugin } from '@arkenivajs/realtime';
import type { SseSource } from '@arkenivajs/realtime';
import { createRealtimeTables, PostgresRealtimeSource } from '../../dist/realtime-source.js';
import { securityStateFixture } from './security-state-fixture.js';
import { startMfaIssuer } from './mfa-issuer.js';

async function listener(auth: AuthService, source: SseSource) {
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
  const address = reservation.address();
  assert.ok(address && typeof address === 'object');
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  const authority: Plugin = {
    id: 'durable-authentication',
    version: '1.0.0',
    capabilities: new Set(['auth']),
    init(context) {
      context.provide(COMPONENTS.auth, auth);
    },
    close() {},
  };
  const app = await createApplication({
    service: { name: 'durable-sse-example', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    http: { host: '127.0.0.1', port: address.port },
    plugins: [
      loggingPlugin(),
      authority,
      apiPlugin({ dependencies: [authority.id] }),
      realtimePlugin({
        routes: [{ kind: 'sse', path: '/events', sourceKey: 'orders', policyKey: 'standard' }],
        websocketHandlers: {},
        sseSources: { orders: source },
        policies: {
          standard: {
            requireAuth: true,
            maxConnectionsPerTenant: 4,
            maxMessageBytes: 16384,
            maxBufferBytes: 32768,
            heartbeatMs: 100,
            idleTimeoutMs: 5000,
          },
        },
        policy: { maxConcurrent: 8, timeoutMs: 2000 },
      }),
    ],
  });
  try {
    await app.start();
    return { app, origin: (app.api as ManagedApiServer).address()! };
  } catch (error) {
    await app.stop();
    throw error;
  }
}
function read(
  origin: string,
  authorization: string,
  count: number,
  cursor?: string,
  onComment?: () => void,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const outgoing = get(
      origin + '/events',
      {
        signal: AbortSignal.timeout(5000),
        headers: {
          authorization,
          accept: 'text/event-stream',
          ...(cursor ? { 'last-event-id': cursor } : {}),
        },
      },
      (response) => {
        let body = '',
          complete = false;
        const done = () => {
          if (complete) return;
          complete = true;
          resolve({ status: response.statusCode!, body });
        };
        response.on('data', (chunk: Buffer) => {
          body += chunk.toString('utf8');
          if (/(?:^|\n):[^\n]*\n\n/u.test(body)) onComment?.();
          if (
            count &&
            (body.match(/\nid: |^id: /g)?.length ?? 0) >= count &&
            body.endsWith('\n\n')
          ) {
            done();
            response.destroy();
          }
        });
        response.on('error', (error) => {
          if (!complete) reject(error);
        });
        response.once('end', done);
      },
    );
    outgoing.once('error', reject);
  });
}

test(
  'Real PostgreSQL replays ordered SSE after listener restart and enforces cursor ownership and retention before headers',
  { timeout: 20000 },
  async () => {
    const backend = await securityStateFixture(),
      issuer = await startMfaIssuer();
    const auth = await createAuthService({
      issuer: issuer.authority,
      audience: 'api://mfa-fixture',
      environment: 'test',
      allowInsecureLoopback: true,
      algorithms: ['RS256'],
      authorizeTenant: (_identity, tenant) => ['tenant-a', 'tenant-b'].includes(tenant),
    });
    let active: Awaited<ReturnType<typeof listener>> | undefined,
      releaseReplay = () => {};
    const peer = await createApplication({
      service: { name: 'durable-sse-peer', version: '1.0.0', environment: 'test' },
      plugins: [postgresPlugin()],
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 },
      },
    });
    try {
      await peer.start();
      await createRealtimeTables(backend.app.sql, 'main', backend.schema);
      const source = new PostgresRealtimeSource(backend.app.sql, auth, 'main', backend.schema),
        other = new PostgresRealtimeSource(peer.sql, auth, 'main', backend.schema);
      const authorization = await issuer.bearer(),
        otherAuthorization = await issuer.bearer({ tenant_id: 'tenant-b' });
      const tenant = auth.tenantFrom(await auth.verifyBearer(authorization)),
        otherTenant = auth.tenantFrom(await auth.verifyBearer(otherAuthorization));
      const first = await source.append(tenant, { type: 'order', data: 'first' }),
        second = await source.append(tenant, { type: 'order', data: 'second\nsecond line' });
      const foreign = await source.append(otherTenant, {
        type: 'order',
        data: 'foreign-private-event',
      });
      await Promise.all([
        source.append(tenant, { type: 'order', data: 'concurrent writer one' }),
        other.append(tenant, { type: 'order', data: 'concurrent writer two' }),
      ]);
      active = await listener(auth, source);
      const initial = await read(active.origin, authorization, 4);
      assert.equal(initial.status, 200);
      assert.ok(initial.body.includes(first));
      assert.ok(!initial.body.includes(foreign));
      assert.ok(!initial.body.includes('foreign-private-event'));
      await active.app.stop();
      const ready = new Promise<void>((resolve) => {
        releaseReplay = resolve;
      });
      active = await listener(auth, {
        kind: 'durable',
        usage: 'test-only',
        validateCursor: (context) => other.validateCursor(context),
        async *subscribe(context) {
          if (context.lastEventId === first) await ready;
          yield* other.subscribe(context);
        },
      });
      const replay = await read(active.origin, authorization, 3, first, releaseReplay);
      assert.equal(replay.status, 200);
      assert.ok(!replay.body.includes(first));
      assert.ok(
        replay.body.startsWith(':'),
        'A native heartbeat must precede the deliberately held replay',
      );
      const eventIds = (body: string) =>
        [...body.matchAll(/(?:^|\n)id: ([^\r\n]*)/gu)].map((match) => match[1]!);
      assert.equal(eventIds(replay.body)[0], second);
      assert.equal(eventIds(replay.body).length, 3);
      assert.deepEqual(eventIds(replay.body), eventIds(initial.body).slice(1));
      assert.equal((await read(active.origin, otherAuthorization, 0, first)).status, 409);
      assert.equal((await read(active.origin, authorization, 0, randomUUID())).status, 409);
      await source.retainFrom(tenant, second);
      assert.equal((await read(active.origin, authorization, 0, first)).status, 410);
      const retained = await read(active.origin, authorization, 2, second);
      assert.equal(retained.status, 200);
      assert.ok(!retained.body.includes(second));
      await assert.rejects(source.retainFrom(otherTenant, second), { reason: 'invalid' });
      await assert.rejects(source.retainFrom(tenant, first), { reason: 'expired' });
      await assert.rejects(source.retainFrom(tenant, '-'.repeat(36)), { reason: 'invalid' });
      await assert.rejects(source.append(tenant, { type: 'order', data: 'x'.repeat(8193) }), {
        code: 'EK_CONFIG_INVALID',
      });
      await assert.rejects(
        source.append(
          tenant,
          { type: 'order', data: 'cancelled' },
          { signal: AbortSignal.abort() },
        ),
        { code: 'EK_ABORTED' },
      );
      // Seed a complete valid retained partition in SQL to exercise its boundary without 1,000 round trips.
      await backend.app.sql.transaction('main', async (transaction) => {
        await transaction.execute({
          text: `INSERT INTO ${backend.schema}.realtime_events(scope,sequence,id,type,data) SELECT scope,n,gen_random_uuid(),'seed','bounded' FROM ${backend.schema}.realtime_events CROSS JOIN generate_series(2,1000) n WHERE id=:id`,
          bindings: { id: foreign },
        });
        await transaction.execute({
          text: `UPDATE ${backend.schema}.realtime_streams SET next_sequence=1001 WHERE scope=(SELECT scope FROM ${backend.schema}.realtime_events WHERE id=:id)`,
          bindings: { id: foreign },
        });
      });
      await assert.rejects(source.append(otherTenant, { type: 'order', data: 'overflow' }), {
        code: 'EK_REALTIME_BACKPRESSURE',
      });
      await peer.stop();
      const unavailable = await read(active.origin, authorization, 0, second);
      assert.equal(unavailable.status, 503);
      assert.ok(!unavailable.body.includes('SELECT'));
      assert.ok(!unavailable.body.includes(backend.schema));
      await assert.rejects(
        source.append({ ...tenant } as typeof tenant, { type: 'order', data: 'forged' }),
      );
    } finally {
      releaseReplay();
      await active?.app.stop();
      await peer.stop();
      await auth.close();
      await issuer.close();
      await backend.close();
    }
  },
);
