import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';

if (!process.env.ARKENIVA_POSTGRES_URL || process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
  throw new Error('Tenant SQL integration requires an explicit disposable PostgreSQL fixture');

test('EK-AUTH-002 verified JWT tenants remain isolated by live PostgreSQL RLS and independent metering with tracing off', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-pg-tenant-'));
  const schema = 'ak_' + randomBytes(12).toString('hex');
  assert.match(schema, /^[a-z][a-z0-9_]{0,62}$/);
  const lines: string[] = [];
  const sink = new Writable({
    write(chunk, _encoding, done) {
      lines.push(String(chunk));
      done();
    },
  });
  const pair = await generateKeyPair('RS256');
  const publicKey = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'sql-tenant-test',
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
  let app: Application | undefined,
    schemaCreated = false;
  try {
    await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
    const issuerAddress = issuer.address();
    assert.ok(issuerAddress && typeof issuerAddress === 'object');
    authority = `http://127.0.0.1:${issuerAddress.port}`;
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    assert.ok(reserved && typeof reserved === 'object');
    app = await createApplication({
      service: { name: 'postgres-tenant-test', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: reserved.port },
      security: {
        issuer: authority,
        audience: 'api://postgres-tenant-test',
        assuranceResolver(identity) {
          const time = identity.claims.auth_time;
          const age = typeof time === 'number' ? Date.now() / 1000 - time : Infinity;
          return identity.issuer === authority &&
            identity.claims.acr === 'urn:test:recent-mfa' &&
            Array.isArray(identity.claims.amr) &&
            identity.claims.amr.includes('otp') &&
            age >= 0 &&
            age <= 60
            ? 'mfa'
            : 'single-factor';
        },
      },
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_POSTGRES_URL', poolMax: 2 },
      },
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'jsonl', path: 'events.jsonl' },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin(),
        meteringPlugin({ workspace, dependencies: ['telemetry'] }),
        postgresPlugin(),
        apiPlugin({ dependencies: ['security', 'metering', 'telemetry', 'database-postgres'] }),
      ],
    });
    const running = app;
    app.api.get<{ id: string }, Record<string, never>, never, { id: string }>('/orders/:id', {
      schema: {
        response: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
          additionalProperties: false,
        },
      },
      auth: { required: true, scopes: ['orders:read'], assurance: 'mfa' },
      handler(context) {
        return running.sql.transaction(
          'main',
          async (tx) => {
            await tx.query({
              text: "SELECT set_config('arkeniva.tenant_id', :tenant, true)",
              bindings: { tenant: context.auth!.tenantId },
            });
            // RLS must enforce tenant isolation even when the lookup only filters the requested row id.
            const result = await tx.query<{ id: string }>({
              text: `SELECT id FROM ${schema}.orders WHERE id=:id`,
              bindings: { id: context.params.id },
            });
            if (!result.rows[0])
              throw new KitError({
                code: 'EK_HTTP_NOT_FOUND',
                message: 'Tenant order was not found',
              });
            return result.rows[0];
          },
          { signal: context.signal },
        );
      },
    });
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    schemaCreated = true;
    await app.sql.execute('main', {
      text: `CREATE TABLE ${schema}.orders(id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)`,
    });
    await app.sql.execute('main', {
      text: `INSERT INTO ${schema}.orders VALUES (:a,:tenantA),(:b,:tenantB)`,
      bindings: { a: 'a', tenantA: 'tenant-A', b: 'b', tenantB: 'tenant-B' },
    });
    await app.sql.execute('main', {
      text: `ALTER TABLE ${schema}.orders ENABLE ROW LEVEL SECURITY`,
    });
    await app.sql.execute('main', {
      text: `ALTER TABLE ${schema}.orders FORCE ROW LEVEL SECURITY`,
    });
    await app.sql.execute('main', {
      text: `CREATE POLICY tenant_boundary ON ${schema}.orders USING (tenant_id=current_setting('arkeniva.tenant_id',true)) WITH CHECK (tenant_id=current_setting('arkeniva.tenant_id',true))`,
    });
    const bearer = async (
      tenant: string,
      scope = 'orders:read',
      audience = 'api://postgres-tenant-test',
      mfa = true,
    ) =>
      'Bearer ' +
      (await new SignJWT({
        tenant_id: tenant,
        scope,
        acr: mfa ? 'urn:test:recent-mfa' : 'urn:test:password',
        amr: mfa ? ['pwd', 'otp'] : ['pwd'],
        auth_time: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'sql-tenant-test' })
        .setSubject('integration-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    const tokenA = await bearer('tenant-A'),
      tokenB = await bearer('tenant-B');
    const address = (app.api as ManagedApiServer).address()!;
    const send = async (id: string, authorization?: string, spoof = false) => {
      const reply = await fetch(address + '/orders/' + id, {
        headers: {
          ...(authorization ? { authorization } : {}),
          ...(spoof ? { 'x-tenant-id': 'tenant-B', 'x-forwarded-tenant': 'tenant-B' } : {}),
        },
      });
      await reply.arrayBuffer();
      return reply.status;
    };
    const before = app.sql.stats('main').operations!;
    assert.equal(await send('a', tokenA), 200);
    assert.equal(await send('b', tokenB), 200);
    assert.equal(await send('b', tokenA, true), 404);
    assert.equal(app.sql.stats('main').operations, before + 6);
    assert.equal(await send('b', undefined, true), 401);
    assert.equal(await send('b', await bearer('tenant-B', 'orders:read', 'wrong-audience')), 401);
    assert.equal(await send('b', await bearer('tenant-B', 'unrelated')), 403);
    assert.equal(await send('b', await bearer('tenant-B', 'orders:read', undefined, false)), 403);
    assert.equal(app.sql.stats('main').operations, before + 6);
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: `SELECT count(*)::int AS count FROM ${schema}.orders`,
      }),
      { count: 0 },
    );
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
    for (const event of events) {
      assert.equal(event.traceId, undefined);
      assert.equal(event.counters['db.query']!.value, 2);
      assert.ok(event.counters['db.client.elapsed']!.value > 0);
      assert.ok(event.quality.missing.includes('driver_bytes_unavailable'));
      assert.equal(event.quality.complete, false);
    }
    assert.equal(app.meter!.stats().dropped, 0);
    assert.equal(app.sql.stats('main').observerFailures, 0);
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT private_sql_log_marker_missing_column' }),
    );
    await app.logger.flush();
    const logs = lines.join('');
    assert.ok(!logs.includes(tokenA));
    assert.ok(!logs.includes('private_sql_log_marker_missing_column'));
  } finally {
    try {
      if (app && schemaCreated && app.state === 'READY')
        await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
    } finally {
      await app?.stop();
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
      sink.destroy();
      await rm(workspace, { recursive: true, force: true });
    }
  }
});
