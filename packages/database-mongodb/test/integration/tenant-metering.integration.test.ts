// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { MongoClient } from 'mongodb';
import type { Collection } from 'mongodb';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { mongoConfiguration } from '../../dist/config.js';

test('Real MongoDB tenant filters use verified JWT identity and keep independent metering when tracing is off', async () => {
  assert.equal(process.env.ARKENIVA_MONGODB_DISPOSABLE, '1');
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-mongodb-tenant-')),
    name = 'tenant_' + randomBytes(12).toString('hex'),
    lines: string[] = [];
  const sink = new Writable({
    write(chunk, _encoding, done) {
      lines.push(String(chunk));
      done();
    },
  });
  const pair = await generateKeyPair('RS256'),
    publicKey = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'mongodb-tenant-test',
      alg: 'RS256',
      use: 'sig',
    };
  let authority = '';
  const issuer = createServer((request, reply) => {
    reply.setHeader('content-type', 'application/json');
    reply.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [publicKey] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  let app: Application | undefined, collection: Collection | undefined;
  try {
    await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
    const address = issuer.address();
    assert.ok(address && typeof address === 'object');
    authority = `http://127.0.0.1:${address.port}`;
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    assert.ok(reserved && typeof reserved === 'object');
    app = await createApplication({
      service: { name: 'mongodb-tenant-test', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: reserved.port },
      security: { issuer: authority, audience: 'api://mongodb-tenant-test' },
      databases: { documents: { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' } },
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'jsonl', path: 'events.jsonl' },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin(),
        meteringPlugin({ workspace, dependencies: ['telemetry'] }),
        mongodbPlugin(),
        apiPlugin({ dependencies: ['security', 'metering', 'telemetry', 'database-mongodb'] }),
      ],
    });
    const running = app;
    app.api.get<{ id: string }, Record<string, never>, never, { name: string }>('/customers/:id', {
      schema: {
        response: {
          type: 'object',
          properties: { name: { type: 'string' } },
          required: ['name'],
          additionalProperties: false,
        },
      },
      auth: { required: true, scopes: ['customers:read'] },
      async handler(context) {
        // MongoDB has no implicit tenant policy: every portable lookup and mutation carries verified identity.
        const filter = { id: context.params.id, tenantId: context.auth!.tenantId },
          row = await running.mongo!.findOne<{ name: string }>(name, filter, {
            signal: context.signal,
          });
        if (!row)
          throw new KitError({
            code: 'EK_HTTP_NOT_FOUND',
            message: 'Tenant customer was not found',
          });
        await running.mongo!.updateOne(
          name,
          filter,
          { $inc: { visits: 1 } },
          { signal: context.signal },
        );
        return { name: row.name };
      },
    });
    await app.start();
    const native = app.mongo!.native();
    assert.ok(native instanceof MongoClient);
    const configuration = mongoConfiguration(
      { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' },
      'test',
    );
    collection = native.db().collection(configuration.prefix + name);
    await collection.insertMany([
      { id: 'a', tenantId: 'tenant-A', name: 'private-customer-A', visits: 0 },
      { id: 'b', tenantId: 'tenant-B', name: 'private-customer-B', visits: 0 },
    ]);
    let queries = 0;
    native.on('commandStarted', (event) => {
      if (['find', 'update'].includes(event.commandName)) queries++;
    });
    const bearer = async (
      tenant: string,
      scope = 'customers:read',
      audience = 'api://mongodb-tenant-test',
    ) =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenant, scope })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'mongodb-tenant-test' })
        .setSubject('integration-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    const tokenA = await bearer('tenant-A'),
      tokenB = await bearer('tenant-B'),
      endpoint = (app.api as ManagedApiServer).address()!;
    const send = async (id: string, token?: string) => {
      const response = await fetch(endpoint + '/customers/' + id, {
        headers: {
          ...(token ? { authorization: token } : {}),
          'x-tenant-id': 'tenant-B',
          'x-forwarded-tenant': 'tenant-B',
        },
      });
      await response.arrayBuffer();
      return response.status;
    };
    assert.equal(await send('a', tokenA), 200);
    assert.equal(await send('b', tokenB), 200);
    assert.equal(await send('b', tokenA), 404);
    assert.equal(queries, 5);
    assert.equal(await send('b'), 401);
    assert.equal(
      await send('b', await bearer('tenant-B', 'customers:read', 'wrong-audience')),
      401,
    );
    assert.equal(await send('b', await bearer('tenant-B', 'unrelated')), 403);
    assert.equal(queries, 5);
    const stored = await collection.findOne({ id: 'b' });
    assert.equal(stored?.visits, 1);
    await app.meter!.flush();
    const events = (await readFile(join(workspace, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    assert.equal(events.length, 3);
    assert.deepEqual(events.map((event) => event.tenantId).sort(), [
      'tenant-A',
      'tenant-A',
      'tenant-B',
    ]);
    assert.deepEqual(events.map((event) => event.counters['db.query']!.value).sort(), [1, 2, 2]);
    for (const event of events) {
      assert.equal(event.traceId, undefined);
      assert.ok(event.counters['db.client.elapsed']!.value > 0);
      assert.ok(event.quality.missing.includes('driver_bytes_unavailable'));
      assert.equal(event.quality.complete, false);
    }
    assert.equal(app.meter!.stats().dropped, 0);
    await app.logger.flush();
    const logs = lines.join('');
    assert.equal(logs.includes(tokenA), false);
    assert.equal(logs.includes('private-customer'), false);
  } finally {
    try {
      if (collection && app?.state === 'READY') await collection.drop();
    } finally {
      try {
        await app?.stop();
      } finally {
        issuer.closeAllConnections();
        await new Promise<void>((resolve) => issuer.close(() => resolve()));
        sink.destroy();
        await rm(workspace, { recursive: true, force: true });
      }
    }
  }
});
