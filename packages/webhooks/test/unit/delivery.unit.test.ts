// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, fixtureSettings } from './fixture.js';
import type { WebhookContext, WebhookSignature } from '../../dist/index.js';

async function sink(
  handler: (
    request: IncomingMessage,
    response: ServerResponse,
    body: Buffer,
  ) => Promise<void> | void,
) {
  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 65536) throw new Error('Fixture input overflow');
        chunks.push(chunk);
      }
      await handler(req, res, Buffer.concat(chunks));
    })().catch(() => {
      res.statusCode = 400;
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address !== 'object') throw new Error('Fixture receiver is unavailable');
  return {
    origin: 'http://127.0.0.1:' + address.port,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
const event = { id: 'one', type: 'orders.created', payload: { value: 'private-webhook-content' } };

test('A real HTTP receiver verifies exact native request bytes and independently consumes its nonce', async (t) => {
  let received = 0;
  const verify = async (body: Buffer, context: WebhookContext, signature: WebhookSignature) => {
    await f.asTenant('tenant-a', () => f.service.verify(body, signature, context));
    assert.equal(f.service.parseEvent(body).id, 'one');
  };
  const server = await sink(async (req, res, body) => {
    const context = JSON.parse(
      Buffer.from(String(req.headers['arkeniva-webhook-context']), 'base64url').toString('utf8'),
    ) as WebhookContext;
    const signature: WebhookSignature = {
      keyId: context.keyId,
      timestamp: context.timestamp,
      nonce: context.nonce,
      algorithm: 'hmac-sha256',
      signature: String(req.headers['arkeniva-webhook-signature']).slice(3),
    };
    await verify(body, context, signature);
    received++;
    res.statusCode = 202;
    res.end('{}');
  });
  t.after(server.close);
  const f = await fixture(fixtureSettings(server.origin));
  t.after(f.close);
  const receipt = await f.asTenant('tenant-a', () => f.service.send('receiver', event));
  assert.deepEqual(receipt, {
    destinationId: 'receiver',
    eventId: 'one',
    status: 'accepted',
    attemptCount: 1,
  });
  assert.equal(received, 1);
  assert.equal(f.claims.size, 1);
  assert.ok(!f.logs.join('').includes('private-webhook-content'));
});

test('Redirects are rejected without following an internal Location or retrying a non-transient response', async (t) => {
  let targetRequests = 0,
    redirects = 0;
  const target = await sink((_req, res) => {
    targetRequests++;
    res.end();
  });
  t.after(target.close);
  const source = await sink((_req, res) => {
    redirects++;
    res.writeHead(307, { location: target.origin + '/private' });
    res.end();
  });
  t.after(source.close);
  const settings = fixtureSettings(source.origin);
  settings.settings = {
    ...settings.settings,
    destinations: [{ ...settings.settings.destinations[0]!, maxRetries: 2, idempotent: true }],
  };
  const f = await fixture(settings);
  t.after(f.close);
  const receipt = await f.asTenant('tenant-a', () => f.service.send('receiver', event));
  assert.equal(receipt.status, 'rejected');
  assert.equal(receipt.attemptCount, 1);
  assert.equal(redirects, 1);
  assert.equal(targetRequests, 0);
});

test('A documented idempotent receiver gets bounded retries, identical event bytes and key, and fresh signed nonces', async (t) => {
  const bodies: string[] = [],
    identifiers: string[] = [],
    nonces: string[] = [];
  const server = await sink((req, res, body) => {
    bodies.push(body.toString());
    identifiers.push(String(req.headers['idempotency-key']));
    nonces.push(
      JSON.parse(
        Buffer.from(String(req.headers['arkeniva-webhook-context']), 'base64url').toString(),
      ).nonce,
    );
    res.statusCode = bodies.length < 3 ? 503 : 200;
    res.end('{}');
  });
  t.after(server.close);
  const settings = fixtureSettings(server.origin);
  settings.settings = {
    ...settings.settings,
    destinations: [{ ...settings.settings.destinations[0]!, maxRetries: 2, idempotent: true }],
  };
  const f = await fixture(settings);
  t.after(f.close);
  const receipt = await f.asTenant('tenant-a', () => f.service.send('receiver', event));
  assert.equal(receipt.status, 'accepted');
  assert.equal(receipt.attemptCount, 3);
  assert.equal(new Set(bodies).size, 1);
  assert.equal(new Set(identifiers).size, 1);
  assert.match(identifiers[0]!, /^[a-f0-9]{64}$/);
  assert.equal(new Set(nonces).size, 3);
});

test('Lost acknowledgements report unknown and never retry without the receiver guarantee', async (t) => {
  let received = 0;
  const server = await sink((req) => {
    received++;
    req.socket.destroy();
  });
  t.after(server.close);
  const f = await fixture(fixtureSettings(server.origin));
  t.after(f.close);
  const receipt = await f.asTenant('tenant-a', () => f.service.send('receiver', event));
  assert.deepEqual(receipt, {
    destinationId: 'receiver',
    eventId: 'one',
    status: 'unknown',
    attemptCount: 1,
  });
  await delay(20);
  assert.equal(received, 1);
});

test('Connect-time DNS and CIDR checks deny loopback rebinding without sending a body', async (t) => {
  let received = 0;
  const server = await sink((_req, res) => {
    received++;
    res.end();
  });
  t.after(server.close);
  const settings = fixtureSettings(server.origin.replace('127.0.0.1', 'localhost'));
  settings.settings = {
    ...settings.settings,
    destinations: [{ ...settings.settings.destinations[0]!, allowedCidrs: ['192.0.2.0/24'] }],
  };
  const f = await fixture(settings);
  t.after(f.close);
  const receipt = await f.asTenant('tenant-a', () => f.service.send('receiver', event));
  assert.equal(receipt.status, 'unknown');
  assert.equal(received, 0);
});

test('Abort after actual transmission preserves an unknown outcome and closes the native request without retry', async (t) => {
  let started!: () => void,
    received = 0;
  const entered = new Promise<void>((resolve) => {
    started = resolve;
  });
  const server = await sink(() => {
    received++;
    started();
  });
  t.after(server.close);
  const f = await fixture(fixtureSettings(server.origin));
  t.after(f.close);
  const controller = new AbortController(),
    pending = f.asTenant('tenant-a', () =>
      f.service.send('receiver', event, { signal: controller.signal }),
    );
  void pending.catch(() => undefined);
  await entered;
  controller.abort();
  await assert.rejects(pending, (error: unknown) => {
    assert.equal((error as { code: string }).code, 'EK_ABORTED');
    assert.equal((error as { details: { outcome: string } }).details.outcome, 'unknown');
    return true;
  });
  await delay(20);
  assert.equal(received, 1);
});
