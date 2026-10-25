// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

/** Own a loopback-only synthetic issuer; credentials are never persisted or printed. */
export async function createIssuer() {
  const pair = await generateKeyPair('RS256');
  const key = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'benchmark-key',
    alg: 'RS256',
    use: 'sig',
  };
  let origin;
  const server = createServer((request, reply) => {
    reply.setHeader('content-type', 'application/json');
    if (request.url === '/keys') reply.end(JSON.stringify({ keys: [key] }));
    else if (request.url === '/.well-known/openid-configuration')
      reply.end(JSON.stringify({ issuer: origin, jwks_uri: origin + '/keys' }));
    else {
      reply.statusCode = 404;
      reply.end('{}');
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = 'http://127.0.0.1:' + server.address().port;
  let closing;
  return {
    origin,
    audience: 'api://performance',
    async token(options = {}) {
      assert.ok(options && typeof options === 'object');
      return new SignJWT({ tenant_id: 'synthetic-tenant', scope: 'orders:read', ...options.claims })
        .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
        .setSubject('synthetic-user')
        .setIssuer(options.issuer ?? origin)
        .setAudience(options.audience ?? 'api://performance')
        .setExpirationTime(options.expiration ?? '2h')
        .sign(pair.privateKey);
    },
    close() {
      return (closing ??= new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }));
    },
  };
}
