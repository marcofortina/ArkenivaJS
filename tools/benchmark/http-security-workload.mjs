// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { request } from 'node:http';
import Fastify from 'fastify';
import helmet from '@fastify/helmet';

export const headerPolicy = Object.freeze({
  contentSecurityPolicy: Object.freeze({
    'default-src': Object.freeze(["'self'"]),
    'object-src': Object.freeze(["'none'"]),
    'base-uri': Object.freeze(["'none'"]),
  }),
  hstsMaxAgeSeconds: 31536000,
  csrfEnabled: false,
  frameAncestors: Object.freeze(["'none'"]),
});

/** Fail-closed test dependencies are never used to authorize or persist a CSRF operation. */
export function headerSettings() {
  const key = randomBytes(32);
  const unavailable = async () => {
    throw new Error('CSRF dependencies are outside the header-only comparison');
  };
  const digest = async (domain, parts) =>
    createHmac('sha256', key)
      .update(JSON.stringify([domain, ...parts]))
      .digest('hex');
  return {
    settings: {
      policy: headerPolicy,
      csrfKeyRef: 'fixture://header-comparison',
      csrfStore: {
        securityLevel: 'test-only',
        operationTimeoutMs: 1000,
        store: Object.fromEntries(
          [
            'read',
            'claimOnce',
            'compareAndSet',
            'atomicBatch',
            'listByOwner',
            'bumpOwnerEpoch',
            'currentOwnerEpoch',
          ].map((name) => [name, unavailable]),
        ),
      },
      csrfHmac: {
        usage: 'test-only',
        algorithm: 'HMAC-SHA256',
        digest,
        async verify(domain, parts, expected) {
          const actual = Buffer.from(await digest(domain, parts));
          const candidate = Buffer.from(expected);
          return actual.length === candidate.length && timingSafeEqual(actual, candidate);
        },
      },
      authority: { usage: 'test-only', require: unavailable },
    },
    close: () => key.fill(0),
  };
}

export const responseSchema = {
  type: 'object',
  properties: { value: { type: 'string' } },
  required: ['value'],
  additionalProperties: false,
};

export function configureHeaders(app, fixture) {
  app.api.get('/headers', {
    schema: { response: responseSchema },
    auth: { required: false },
    handler: () => ({ value: fixture.marker }),
  });
  app.api.get('/failure', {
    schema: { response: responseSchema },
    auth: { required: false },
    handler() {
      throw new Error('The owned header comparison route failed');
    },
  });
}

/** Use native Helmet at response time, matching the wrapper's actual middleware phase. */
export async function nativeHeaders(fixture) {
  const server = Fastify({ logger: false });
  server.register(helmet, { global: false });
  server.addHook('onSend', async (_request, reply, payload) => {
    await reply.helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          ...headerPolicy.contentSecurityPolicy,
          'frame-ancestors': [...headerPolicy.frameAncestors],
        },
      },
      hsts: { maxAge: headerPolicy.hstsMaxAgeSeconds, includeSubDomains: false, preload: false },
      referrerPolicy: { policy: 'no-referrer' },
      xContentTypeOptions: true,
      xFrameOptions: false,
    });
    return payload;
  });
  server.get('/headers', { schema: { response: { 200: responseSchema } } }, async () => ({
    value: fixture.marker,
  }));
  server.get('/failure', async () => {
    throw new Error('The owned header comparison route failed');
  });
  try {
    await server.listen({ host: '127.0.0.1', port: 0 });
  } catch (error) {
    await server.close();
    throw error;
  }
  return {
    address: () => 'http://127.0.0.1:' + server.server.address().port,
    close: () => server.close(),
  };
}

export function headerExchange(service, path) {
  const url = new URL(service.address());
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.protocol, 'http:');
  assert.ok(url.port.length > 0);
  assert.ok(['/headers', '/missing', '/failure'].includes(path));
  return new Promise((resolve, reject) => {
    const outgoing = request(
      new URL(path, url),
      { agent: false, signal: AbortSignal.timeout(2000) },
      (response) => {
        let body = '';
        response.on('data', (chunk) => {
          body += chunk.toString('utf8');
          if (Buffer.byteLength(body) > 8192)
            response.destroy(new Error('The header response exceeds its capacity'));
        });
        response.once('error', reject);
        response.once('end', () =>
          resolve({ status: response.statusCode, headers: response.headers, body }),
        );
      },
    );
    outgoing.once('error', reject);
    outgoing.end();
  });
}

export async function verifyHeaders(service, fixture) {
  for (const [path, status] of [
    ['/headers', 200],
    ['/missing', 404],
    ['/failure', 500],
  ]) {
    const result = await headerExchange(service, path);
    assert.equal(result.status, status);
    assert.equal(
      result.headers['content-security-policy'],
      "default-src 'self';object-src 'none';base-uri 'none';frame-ancestors 'none'",
    );
    assert.equal(result.headers['strict-transport-security'], 'max-age=31536000');
    assert.equal(result.headers['x-content-type-options'], 'nosniff');
    assert.equal(result.headers['referrer-policy'], 'no-referrer');
    assert.equal(result.headers['content-security-policy-report-only'], undefined);
    if (status === 200) assert.deepEqual(JSON.parse(result.body), { value: fixture.marker });
  }
  if (service.stats) assert.equal(service.stats().observerFailures, 0);
  return { actualResponses: 3, successAndErrorHeaders: true, csrfMeasured: false };
}

export function headerWorkload(service) {
  return { headers: () => headerExchange(service, '/headers') };
}
