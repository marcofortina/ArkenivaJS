// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JWTPayload } from 'jose';

/** Disposable application-owned authority; signing keys never leave this closure. */
export async function startMfaIssuer() {
  const pair = await generateKeyPair('RS256');
  const key = { ...(await exportJWK(pair.publicKey)), kid: 'mfa-fixture', alg: 'RS256' };
  const server = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [key] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test issuer has no address');
  const authority = `http://127.0.0.1:${address.port}`;
  return {
    authority,
    async bearer(claims: JWTPayload = {}) {
      return (
        'Bearer ' +
        (await new SignJWT({
          tenant_id: 'tenant-a',
          sid: 'session-a',
          auth_time: Math.floor(Date.now() / 1000),
          scope: 'mfa:manage',
          ...claims,
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'mfa-fixture', typ: 'JWT' })
          .setIssuer(authority)
          .setSubject(typeof claims.sub === 'string' ? claims.sub : 'synthetic-account')
          .setAudience(typeof claims.aud === 'string' ? claims.aud : 'api://mfa-fixture')
          .setExpirationTime('2m')
          .sign(pair.privateKey))
      );
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
