// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function webhookPorts(fixture) {
  const url = new URL(fixture.endpoint);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/provider');
  assert.ok(url.port);
  const exchange = async (method, args) => {
    const response = await globalThis.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-owned-provider': fixture.bearer },
      body: JSON.stringify({ method, args }),
      signal: AbortSignal.timeout(5000),
      redirect: 'error',
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(Buffer.byteLength(body) <= 4096);
    return JSON.parse(body).result;
  };
  const deny = async () => {
    throw new Error('The webhook comparison exposes only atomic nonce claims');
  };
  return {
    authority: {
      usage: 'test-only',
      require: (action, _subject, context) => exchange('authorize', [action, context]),
    },
    secretProvider: {
      usage: 'test-only',
      async get(reference) {
        const value = await exchange('secret', [reference]);
        return { bytes: Buffer.from(value.encoded, 'base64url'), keyVersion: value.version };
      },
    },
    store: {
      securityLevel: 'test-only',
      claimOnce: (...args) => exchange('claimOnce', args.slice(0, 3)),
      ...Object.fromEntries(
        [
          'read',
          'compareAndSet',
          'atomicBatch',
          'listByOwner',
          'bumpOwnerEpoch',
          'currentOwnerEpoch',
        ].map((name) => [name, deny]),
      ),
    },
  };
}

export function webhookSettings(fixture) {
  const ports = webhookPorts(fixture);
  return {
    destinations: [
      {
        name: 'receiver',
        origin: 'http://127.0.0.1:9',
        hmacKeyRef: 'current',
        allowedCidrs: ['127.0.0.0/8'],
        maxRetries: 0,
        timeoutMs: 5000,
      },
    ],
    authority: ports.authority,
    secretProvider: ports.secretProvider,
    nonceStore: { store: ports.store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    policy: { maxConcurrent: 4, timeoutMs: 10000, maxInputBytes: 65536, maxOutputBytes: 65536 },
  };
}

async function nativeMac(body, context, tenant, secrets) {
  const secret = await secrets.get('current');
  try {
    assert.equal(secret.keyVersion, context.keyId);
    return createHmac('sha256', secret.bytes)
      .update(
        JSON.stringify([
          'arkenivajs.webhooks.v1',
          tenant,
          context.destinationId,
          context.eventId,
          context.timestamp,
          context.nonce,
          context.keyId,
        ]) + '\n',
      )
      .update(body)
      .digest('base64url');
  } finally {
    secret.bytes.fill(0);
  }
}

/** Independent native framing and actual shared SQL claims for the bounded valid corpus. */
export function nativeWebhooks(fixture) {
  const ports = webhookPorts(fixture);
  const principal = (action, context) => ports.authority.require(action, undefined, context);
  return {
    async sign(body, reference, context) {
      assert.equal(reference, 'current');
      const owner = await principal('webhooks.sign', context);
      return {
        algorithm: 'hmac-sha256',
        keyId: context.keyId,
        timestamp: context.timestamp,
        nonce: context.nonce,
        signature: await nativeMac(body, context, owner.tenant.tenantId, ports.secretProvider),
      };
    },
    async verify(body, signature, context) {
      const owner = await principal('webhooks.verify', context);
      const expected = Buffer.from(
          await nativeMac(body, context, owner.tenant.tenantId, ports.secretProvider),
          'base64url',
        ),
        actual = Buffer.from(signature.signature, 'base64url');
      assert.equal(actual.length, expected.length);
      assert.ok(timingSafeEqual(actual, expected));
      const digest = createHash('sha256')
        .update(
          JSON.stringify([
            'arkenivajs.webhooks.replay.v1',
            owner.issuer,
            owner.subject,
            owner.tenant.tenantId,
            context.destinationId,
            context.nonce,
          ]),
        )
        .digest('hex');
      assert.equal(
        await ports.store.claimOnce(
          'webhooks.nonces.v1',
          digest,
          new Date(Math.max(Date.now(), Date.parse(context.timestamp)) + 300001).toISOString(),
        ),
        true,
      );
      return {
        destinationId: context.destinationId,
        eventId: context.eventId,
        verifiedAt: new Date().toISOString(),
      };
    },
    parseEvent: (body) => JSON.parse(Buffer.from(body).toString('utf8')),
  };
}

export async function verifyWebhooks(service, fixture) {
  const context = {
    destinationId: 'receiver',
    eventId: 'owned-event',
    timestamp: new Date().toISOString(),
    nonce: randomBytes(24).toString('base64url'),
    keyId: 'one',
  };
  const event = { id: context.eventId, type: 'owned.event', payload: { value: fixture.marker } };
  // Spaces and trailing LF deliberately differ from compact serialization.
  const raw = Buffer.from(JSON.stringify(event, null, 2) + '\n');
  const signature = await service.sign(raw, 'current', context);
  const native = nativeWebhooks(fixture),
    expected = await native.sign(raw, 'current', context);
  assert.deepEqual(signature, expected);
  assert.deepEqual(JSON.parse(JSON.stringify(service.parseEvent(raw))), event);
  await assert.rejects(service.verify(Buffer.from(JSON.stringify(event)), expected, context));
  const verified = await service.verify(raw, expected, context);
  assert.equal(verified.destinationId, context.destinationId);
  assert.equal(verified.eventId, context.eventId);
  await assert.rejects(service.verify(raw, expected, context));
  return {
    nativeSignatureMatched: true,
    unchangedBytesVerified: true,
    reserializedBodyRejected: true,
    replayRejected: true,
    parsedEventVerified: true,
  };
}
