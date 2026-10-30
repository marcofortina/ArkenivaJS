// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createIssuer } from './http-issuer.mjs';
import { tlsFiles } from '../../packages/graphql/dist-test/fixture.js';

/** Parent-owned actual signing authority and private disposable HTTPS certificate. */
export async function startGraphqlFixture() {
  const tls = await tlsFiles();
  let issuer;
  try {
    issuer = await createIssuer();
    const token = await issuer.token({ claims: { scope: 'orders:read orders:write' } }),
      parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    return {
      fixture: {
        issuer: issuer.origin,
        audience: issuer.audience,
        token,
        invalidToken: parts.join('.'),
        readOnlyToken: await issuer.token(),
        otherTenantToken: await issuer.token({
          claims: { tenant_id: 'other-tenant', scope: 'orders:read orders:write' },
        }),
        foreignTenantToken: await issuer.token({ claims: { tenant_id: 'foreign-tenant' } }),
        tenant: 'synthetic-tenant',
        otherTenant: 'other-tenant',
        marker: 'owned-customer-π',
        privateMarker: 'owned-private-note-value',
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
