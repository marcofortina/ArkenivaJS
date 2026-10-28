// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from '../fixture.js';

for (const binding of ['redirect', 'post'] as const)
  test(
    `Native ${binding} SAML creates signed requests and accepts only a correlated signed assertion`,
    { timeout: 15000 },
    async () => {
      const f = await fixture(binding);
      try {
        const request = await f.service.beginLogin({ returnPath: '/app' });
        assert.equal(request.binding, binding);
        if (request.binding === 'redirect')
          assert.ok(new URL(request.redirectUrl).searchParams.get('Signature'));
        else {
          assert.equal(request.actionUrl, 'https://idp.fixture.invalid/login');
          assert.ok(
            Buffer.from(request.fields.SAMLRequest, 'base64').toString().includes('Signature'),
          );
        }
        const response = f.response(request.requestId),
          context = { inResponseTo: request.requestId, relayState: request.requestId };
        const identity = await f.service.consumeResponse(context, response);
        assert.equal(identity.subject, 'synthetic-account');
        assert.equal(identity.issuer, 'https://idp.fixture.invalid/entity');
        assert.deepEqual(identity.scopes, []);
        assert.equal(identity.assurance, 'single-factor');
        assert.equal(identity.claims.tenant_id, undefined);
        assert.deepEqual(identity.attributes.tenant_id, ['untrusted-tenant-hint']);
        await assert.rejects(f.service.consumeResponse(context, response), {
          code: 'EK_SAML_REPLAY',
        });
        const logout = await f.service.beginLogout(identity);
        assert.equal(logout.binding, binding);
        const completed = await f.logoutResponse(logout.requestId);
        await f.service.consumeLogoutResponse(completed);
        await assert.rejects(f.service.consumeLogoutResponse(completed), {
          code: 'EK_SAML_REPLAY',
        });
        assert.ok((await f.service.createMetadata()).includes('EntityDescriptor'));
        f.authorize(false);
        await assert.rejects(f.service.beginLogout(identity), { code: 'EK_SAML_ASSERTION' });
      } finally {
        await f.close();
      }
    },
  );
