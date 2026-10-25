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
import { messagingPlugin } from '@arkenivajs/messaging';
import type { MessageFailure } from '@arkenivajs/messaging';
import { setTimeout as delay } from 'node:timers/promises';

test('Real NATS detaches publisher tenant scope and persists independently verified consumer usage with tracing disabled', async () => {
  assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-message-tenant-')),
    topic = 'events.' + randomBytes(12).toString('hex'),
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
      kid: 'message-integration',
      alg: 'RS256',
      use: 'sig',
    };
  const failures: MessageFailure[] = [];
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
      service: { name: 'message-tenant-test', version: '1.0.0', environment: 'test' },
      security: { issuer: authority, audience: 'api://message-tenant-test' },
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'jsonl', path: 'events.jsonl' },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin(),
        meteringPlugin({ workspace, dependencies: ['telemetry'] }),
        messagingPlugin({
          connectionStringEnv: 'ARKENIVA_NATS_URL',
          onError: async (failure) => {
            failures.push(failure);
          },
        }),
      ],
    });
    await app.start();
    const auth = app.auth as ManagedAuthService;
    const bearer = async (tenantId: string, audience = 'api://message-tenant-test') =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenantId })
        .setProtectedHeader({ alg: 'RS256', kid: 'message-integration', typ: 'JWT' })
        .setSubject('integration-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    const tokenA = await bearer('tenant-A'),
      tokenB = await bearer('tenant-B'),
      tenantA = auth.tenantFrom(await auth.verifyBearer(tokenA)),
      tenantB = auth.tenantFrom(await auth.verifyBearer(tokenB));
    let handled = false;
    const subscription = await app.messaging!.subscribe<{ tenant: string }>(
      topic,
      async (message) => {
        assert.equal(app!.meter!.current(), undefined);
        assert.equal(message.tenant, undefined);
        assert.equal(message.payload.tenant, 'tenant-A');
        // Consumer authority is verified independently; payload tenant fields grant no accounting authority.
        await app!.meter!.measure({ tenant: tenantB, operation: 'message.consumer' }, async () => {
          assert.ok(app!.meter!.current());
        });
        handled = true;
      },
    );
    await app.meter!.measure(
      { tenant: tenantA, operation: 'message.publisher', requestId: 'publisher-request' },
      async () => {
        const publisher = app!.meter!.current();
        assert.equal(
          (await app!.messaging!.publish(topic, { tenant: 'tenant-A' })).acknowledged,
          false,
        );
        const until = performance.now() + 5000;
        while (!handled) {
          assert.ok(performance.now() < until, 'Independent message accounting did not settle');
          await delay(5);
        }
        assert.equal(app!.meter!.current(), publisher);
      },
    );
    await subscription.close();
    assert.deepEqual(failures, []);
    await assert.rejects(auth.verifyBearer(await bearer('tenant-B', 'wrong-audience')), {
      code: 'EK_AUTH_INVALID',
    });
    await app.meter!.flush();
    const events = (await readFile(join(workspace, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    assert.equal(events.length, 2);
    assert.deepEqual(events.map((event) => event.tenantId).sort(), ['tenant-A', 'tenant-B']);
    const publisher = events.find((event) => event.operation === 'message.publisher')!,
      consumer = events.find((event) => event.operation === 'message.consumer')!;
    assert.equal(consumer.tenantId, 'tenant-B');
    assert.equal(consumer.parentOperationId, undefined);
    assert.equal(consumer.requestId, undefined);
    assert.equal(consumer.counters['messaging.publish'], undefined);
    assert.equal(publisher.tenantId, 'tenant-A');
    assert.equal(publisher.counters['messaging.publish']!.value, 1);
    assert.ok(publisher.counters['messaging.client.elapsed']!.value > 0);
    assert.ok(publisher.counters['messaging.payload.bytes']!.value > 0);
    assert.equal(publisher.counters['messaging.payload.bytes']!.unit, 'bytes');
    assert.ok(publisher.quality.missing.includes('driver_bytes_unavailable'));
    assert.equal(publisher.quality.complete, false);
    for (const event of events) assert.equal(event.traceId, undefined);
    assert.equal(app.meter!.stats().dropped, 0);
    await app.logger.flush();
    assert.equal(lines.join('').includes(tokenA), false);
    assert.equal(lines.join('').includes(tokenB), false);
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
});
