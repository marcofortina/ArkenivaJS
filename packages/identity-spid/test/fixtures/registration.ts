// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { generateKeyPair, SignJWT } from 'jose';
import type { FederationOidcRegistration } from '../../dist/index.js';

const pair = await generateKeyPair('ES256');
export const signed = (entity: string, claims: Record<string, unknown> = {}) =>
  new SignJWT({
    iss: 'https://anchor.example.test',
    sub: entity,
    iat: Math.floor(Date.now() / 1000) - 1,
    exp: Math.floor(Date.now() / 1000) + 3600,
    id: 'https://anchor.example.test/openid_relying_party/public/',
    ...claims,
  })
    .setProtectedHeader({ alg: 'ES256', kid: 'public-root', typ: 'trust-mark+jwt' })
    .sign(pair.privateKey);
export async function registration(entity: string): Promise<FederationOidcRegistration> {
  return {
    authorityHints: ['https://anchor.example.test'],
    trustMarks: [await signed(entity)],
    organization: {
      organizationName: 'Fixture Organization',
      homepageUri: 'https://service.example.test',
      policyUri: 'https://service.example.test/privacy',
      contacts: ['office@example.test'],
      resolveEndpoint: 'https://service.example.test/resolve',
      logoUri: 'https://service.example.test/logo.svg',
    },
    signingAlgorithm: 'RS256',
    idTokenSigningAlgorithm: 'RS512',
    userInfoSigningAlgorithm: 'RS512',
    decryptionKeyRef: 'oidc-decryption-ref',
    userInfoEncryption: { algorithm: 'RSA-OAEP-256', encryption: 'A256CBC-HS512' },
    requestedClaims: ['name', 'family_name'],
  };
}
