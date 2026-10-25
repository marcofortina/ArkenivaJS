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
import { createApplication } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { securityPlugin } from '@arkenivajs/security';
import type { ManagedAuthService } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';
import { redisPlugin } from '@arkenivajs/database-redis';
import { cachePlugin, tenantCache } from '@arkenivajs/cache';

test('Real Redis cache uses verified JWT tenant authority and independent metering with tracing disabled', async () => {
  assert.equal(process.env.ARKENIVA_REDIS_DISPOSABLE, '1');
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-cache-tenant-')),
    namespace = 'cache-tenant:' + randomBytes(12).toString('hex') + ':',
    lines: string[] = [],
    sink = new Writable({
      write(chunk, _encoding, done) {
        lines.push(String(chunk));
        done();
      },
    });
  const pair = await generateKeyPair('RS256'),
    key = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'cache-integration',
      alg: 'RS256',
      use: 'sig',
    };
  let authority = '',
    app: Application | undefined;
  const issuer = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [key] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  try {
    await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
    const address = issuer.address();
    assert.ok(address && typeof address === 'object');
    authority = `http://127.0.0.1:${address.port}`;
    app = await createApplication({
      service: { name: 'cache-tenant-test', version: '1.0.0', environment: 'test' },
      security: { issuer: authority, audience: 'api://cache-tenant-test' },
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'jsonl', path: 'events.jsonl' },
      databases: { values: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin(),
        meteringPlugin({ workspace, dependencies: ['telemetry'] }),
        redisPlugin(),
        cachePlugin({ namespace }),
      ],
    });
    await app.start();
    const auth = app.auth as ManagedAuthService;
    const bearer = async (tenantId: string, audience = 'api://cache-tenant-test') =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenantId })
        .setProtectedHeader({ alg: 'RS256', kid: 'cache-integration', typ: 'JWT' })
        .setSubject('integration-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    const tokenA = await bearer('tenant-A'),
      tokenB = await bearer('tenant-B'),
      tenantA = auth.tenantFrom(await auth.verifyBearer(tokenA)),
      tenantB = auth.tenantFrom(await auth.verifyBearer(tokenB)),
      cacheA = tenantCache(app.cache!, auth, tenantA),
      cacheB = tenantCache(app.cache!, auth, tenantB);
    await app.meter!.measure({ tenant: tenantA, operation: 'cache.customer' }, async () => {
      await cacheA.set('customer', { name: 'private-cache-customer-A' });
      assert.deepEqual(await cacheA.get('customer'), { name: 'private-cache-customer-A' });
    });
    await app.meter!.measure({ tenant: tenantB, operation: 'cache.customer' }, async () => {
      await cacheB.set('customer', { name: 'private-cache-customer-B' });
      assert.deepEqual(await cacheB.get('customer'), { name: 'private-cache-customer-B' });
    });
    assert.throws(
      () => tenantCache(app!.cache!, auth, { ...tenantA, tenantId: tenantB.tenantId }),
      { code: 'EK_TENANT_UNVERIFIED' },
    );
    await assert.rejects(
      cacheA.get('tenant:' + Buffer.from(tenantB.tenantId).toString('base64url') + ':customer'),
      { code: 'EK_AUTH_FORBIDDEN' },
    );
    await assert.rejects(auth.verifyBearer(await bearer('tenant-B', 'wrong-audience')), {
      code: 'EK_AUTH_INVALID',
    });
    assert.deepEqual(await cacheA.get('customer'), { name: 'private-cache-customer-A' });
    await app.meter!.flush();
    const events = (await readFile(join(workspace, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    assert.equal(events.length, 2);
    assert.deepEqual(events.map((event) => event.tenantId).sort(), ['tenant-A', 'tenant-B']);
    for (const event of events) {
      assert.equal(event.traceId, undefined);
      // The actual Redis provider records backend work once; the convenience wrapper adds no fabricated database calls.
      assert.equal(event.counters['db.query']!.value, 2);
      assert.ok(event.counters['db.client.elapsed']!.value > 0);
      assert.ok(event.quality.missing.includes('driver_bytes_unavailable'));
      assert.equal(event.quality.complete, false);
    }
    assert.equal(app.meter!.stats().dropped, 0);
    await app.logger.flush();
    assert.equal(lines.join('').includes(tokenA), false);
    assert.equal(lines.join('').includes('private-cache-customer'), false);
    await auth.close();
    await assert.rejects(cacheA.get('customer'), { code: 'EK_TENANT_UNVERIFIED' });
  } finally {
    try {
      if (app?.state === 'READY')
        await app.redis!.del(
          ['tenant-A', 'tenant-B'].map(
            (id) => namespace + 'tenant:' + Buffer.from(id).toString('base64url') + ':customer',
          ),
        );
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
