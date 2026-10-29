// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { exportJWK } from 'jose';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { samlResponse } from '../fixtures/saml-response.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { checkMapping } from '../fixtures/mapping-checks.js';
import { FederationIdentityMapping } from '../../dist/identity-mapping.js';
import { FederationOidcCallback } from '../../dist/oidc-callback.js';

after(closeRegistryFixture);

test(
  'Actual SAML evidence enters the same canonical AuthService tenant, authority and expiry checks as OIDC',
  { timeout: 30000 },
  async () => {
    const f = await samlLoginFixture(),
      pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      jwk = {
        ...(await exportJWK(pair.publicKey)),
        kid: 'canonical-public',
        alg: 'ES256',
        use: 'sig',
      },
      server = createServer((_request, response) => {
        response.setHeader('content-type', 'application/jwk-set+json');
        response.end(JSON.stringify({ keys: [jwk] }));
      });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      const profile = f.document.profile,
        fresh = async (hint: string) => {
          const login = await f.runtime.run((call) =>
            f.login.begin(call, { ...f.input, tenantHint: hint }),
          );
          return f.runtime.run((call) =>
            f.login.consume(
              call,
              samlResponse(f, login, { expiresAt: new Date(Date.now() + 30000).toISOString() }),
            ),
          );
        },
        proof = await fresh('tenant-A');
      assert.throws(
        () =>
          new FederationIdentityMapping(
            f.settings,
            profile.profileId,
            Object.create(FederationOidcCallback.prototype) as FederationOidcCallback,
            {
              isVerifiedTenant: (value): value is never => {
                void value;
                return false;
              },
            },
          ),
        { code: 'EK_EID_PROFILE' },
      );
      await checkMapping(
        `http://127.0.0.1:${address.port}`,
        pair.privateKey,
        {
          profiles: [profile],
          identityMappers: f.settings.identityMappers,
          stateStore: f.settings.stateStore,
          secretProvider: f.settings.secretProvider,
          authority: f.settings.authority,
          policy: f.settings.policy,
          stateEncryptionKeyRefs: f.settings.encryptionRefs,
          stateMacKeyRefs: f.settings.macRefs,
        },
        profile,
        f.login,
        proof,
        f.runtime,
        fresh,
      );
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await f.close();
    }
  },
);
