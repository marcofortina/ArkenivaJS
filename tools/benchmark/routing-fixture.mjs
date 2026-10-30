// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createIssuer } from './http-issuer.mjs';
import { tlsFiles } from '../../packages/graphql/dist-test/fixture.js';

/** The parent owns synthetic credentials and verified server TLS for every isolated profile. */
export async function startRoutingFixture() {
  const tls = await tlsFiles();
  let issuer;
  try {
    issuer = await createIssuer();
    const tenant = 'synthetic-tenant',
      otherTenant = 'routing-other-tenant',
      emptyTenant = 'routing-empty-tenant';
    const scopes = 'orders:write orders:denied';
    const token = await issuer.token({ claims: { scope: scopes } });
    const parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    return {
      fixture: {
        issuer: issuer.origin,
        audience: issuer.audience,
        tenant,
        otherTenant,
        emptyTenant,
        token,
        invalidToken: parts.join('.'),
        otherToken: await issuer.token({ claims: { tenant_id: otherTenant, scope: scopes } }),
        emptyToken: await issuer.token({ claims: { tenant_id: emptyTenant, scope: scopes } }),
        foreignToken: await issuer.token({
          claims: { tenant_id: 'unapproved-routing-tenant', scope: scopes },
        }),
        unscopedToken: await issuer.token({ claims: { scope: 'orders:observe' } }),
        expandedToken: await issuer.token({ claims: { scope: scopes + ' orders:read' } }),
        row: 'owned-routing-north-row',
        otherRow: 'owned-routing-south-row',
        implementationHint: 'unapproved-client-selection',
        ...tls.tls,
        ca: tls.ca.toString('base64'),
      },
      observations: issuer.observations,
      async close() {
        try {
          await issuer.close();
        } finally {
          await tls.close();
        }
      },
    };
  } catch (error) {
    try {
      await issuer?.close();
    } finally {
      await tls.close();
    }
    throw error;
  }
}

/** Registry trace identifiers are allowed diagnostics; tokens, payloads and trust coordinates are not. */
export function routingPrivateValues(fixture) {
  return [
    fixture.issuer,
    fixture.audience,
    fixture.token,
    fixture.invalidToken,
    fixture.otherToken,
    fixture.emptyToken,
    fixture.foreignToken,
    fixture.unscopedToken,
    fixture.expandedToken,
    fixture.row,
    fixture.otherRow,
    fixture.implementationHint,
    fixture.privateKeyFile,
    fixture.certificateFile,
    fixture.ca,
    'unapproved-routing-tenant',
    '127.0.0.1',
    'localhost',
  ];
}
