// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from 'jose';
import type { FederationProfileV1 } from '../../dist/index.js';
import type { FederationHttp } from '../../dist/metadata-http.js';
import { configurationEndpoint } from '../../dist/resolver.js';

export const root = 'https://anchor.example.test',
  sa = 'https://authority.example.test',
  op = 'https://idp.example.test',
  aa = 'https://attributes.example.test';
export const types = {
  sa: root + '/intermediate/public/',
  op: root + '/openid_provider/public/',
  aa: root + '/oauth_resource/public/',
};
export const pairs = await Promise.all(Array.from({ length: 5 }, () => generateKeyPair('ES256'))),
  jwks = await Promise.all(
    pairs.map(async (pair, index) => ({
      keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'public-' + index }],
    })),
  );
export const now = () => Math.floor(Date.now() / 1000);
const sign = (
  issuer: string,
  subject: string | undefined,
  signing: number,
  typ: string,
  claims: Record<string, unknown> = {},
) =>
  new SignJWT({
    iss: issuer,
    ...(subject ? { sub: subject } : {}),
    iat: now() - 1,
    exp: now() + 300,
    ...claims,
  })
    .setProtectedHeader({ typ, alg: 'ES256', kid: 'public-' + signing })
    .sign(pairs[signing]!.privateKey);
export const statement = (
  issuer: string,
  subject: string,
  signing: number,
  delegated: number,
  claims: Record<string, unknown> = {},
) => sign(issuer, subject, signing, 'entity-statement+jwt', { jwks: jwks[delegated], ...claims });
export const mark = (
  issuer: string,
  subject: string,
  signing: number,
  type: string,
  claims: Record<string, unknown> = {},
) => sign(issuer, subject, signing, 'trust-mark+jwt', { id: type, ...claims });
export const entry = (type: string, token: string) => ({ id: type, trust_mark: token });
export async function membershipFixture(
  options: {
    catalog?: Record<string, unknown>;
    sa?: Record<string, unknown>;
    op?: Record<string, unknown>;
    opMark?: Record<string, unknown>;
    saMark?: Record<string, unknown>;
    status?: Record<string, unknown>;
    issuer?: string;
    signer?: number;
    root?: Record<string, unknown>;
  } = {},
) {
  const opIssuer = options.issuer ?? sa,
    signing = options.signer ?? 1,
    saMark = await mark(root, sa, 0, types.sa, options.saMark),
    opMark = await mark(opIssuer, op, signing, types.op, options.opMark),
    aaMark = await mark(root, aa, 0, types.aa);
  const metadata = (entity: string) => ({
    federation_fetch_endpoint: entity + '/fetch',
    federation_trust_mark_status_endpoint: entity + '/status',
  });
  const rootConfiguration = await statement(root, root, 0, 0, {
    constraints: { max_path_length: 2 },
    trust_mark_issuers: options.catalog ?? {
      [types.sa]: [root],
      [types.op]: [sa],
      [types.aa]: [root],
    },
    metadata: { federation_entity: metadata(root) },
    ...options.root,
  });
  const leafConfiguration = await statement(op, op, 2, 2, {
    authority_hints: [sa],
    metadata: { openid_provider: { issuer: op } },
    trust_marks: [entry(types.op, opMark)],
    ...options.op,
  });
  const records = new Map([
    [configurationEndpoint(root), rootConfiguration],
    [
      configurationEndpoint(sa),
      await statement(sa, sa, 1, 1, {
        authority_hints: [root],
        metadata: { federation_entity: metadata(sa) },
        trust_marks: [entry(types.sa, saMark)],
        ...options.sa,
      }),
    ],
    [root + '/fetch?' + new URLSearchParams({ sub: sa }), await statement(root, sa, 0, 1)],
    [sa + '/fetch?' + new URLSearchParams({ sub: op }), await statement(sa, op, 1, 2)],
    [
      configurationEndpoint(aa),
      await statement(aa, aa, 3, 3, {
        authority_hints: [root],
        metadata: { oauth_resource: {}, federation_entity: metadata(aa) },
        trust_marks: [entry(types.aa, aaMark)],
      }),
    ],
    [root + '/fetch?' + new URLSearchParams({ sub: aa }), await statement(root, aa, 0, 3)],
  ]);
  const reads: string[] = [],
    statuses: { endpoint: string; token: string }[] = [];
  const http: Pick<FederationHttp, 'statement' | 'trustMarkStatus'> = {
    async statement(endpoint, subject, operation) {
      assert.ok(operation?.signal instanceof AbortSignal);
      const key = endpoint + (subject ? '?' + new URLSearchParams({ sub: subject }) : '');
      reads.push(key);
      const encoded = records.get(key);
      if (!encoded) throw new Error('The fixture document is unavailable');
      return encoded;
    },
    async trustMarkStatus(endpoint, token, operation) {
      assert.ok(operation?.signal instanceof AbortSignal);
      statuses.push({ endpoint, token });
      const signer =
        endpoint === root + '/status'
          ? { entity: root, key: 0 }
          : endpoint === sa + '/status'
            ? { entity: sa, key: 1 }
            : { entity: aa, key: 3 };
      return sign(signer.entity, undefined, signer.key, 'trust-mark-status-response+jwt', {
        trust_mark: token,
        status: 'active',
        ...options.status,
      });
    },
  };
  const profile: FederationProfileV1 = {
    schemaVersion: '1.0.0',
    profileId: 'membership-profile',
    system: 'spid',
    protocol: 'oidc-federation',
    entityId: 'https://service.example.test',
    clientId: 'https://service.example.test',
    redirectUri: 'https://service.example.test/callback',
    signingKeyRef: 'signing-ref',
    expectedIssuers: [op],
    allowedAssurance: ['spid-l2'],
    subjectClaim: 'sub',
    tenantMappingId: 'approved-accounts',
    identityMappingVersion: '1',
    sessionTtlSeconds: 300,
    metadata: {
      trustAnchors: [
        {
          issuer: root,
          kid: 'public-0',
          publicKeyPem: await exportSPKI(pairs[0]!.publicKey),
          validFrom: new Date(Date.now() - 60000).toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      ],
      approvedMetadataEndpoints: [
        configurationEndpoint(root),
        root + '/fetch',
        root + '/status',
        configurationEndpoint(sa),
        sa + '/fetch',
        sa + '/status',
        configurationEndpoint(aa),
        aa + '/status',
      ],
      maxBytes: 65536,
      refreshIntervalSeconds: 30,
      maxChainDepth: 4,
      revocation: 'mandatory',
      stalePolicy: 'reject',
    },
  };
  return { profile, http, leafConfiguration, records, reads, statuses, saMark, opMark, aaMark };
}
