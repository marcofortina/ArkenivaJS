// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import type {
  FederationOidcRegistration,
  FederationProfileV1,
  ItalianEidPluginSettings,
} from '../../dist/index.js';
import { capture, captureProfile } from '../../dist/settings.js';
import { transactionFixture } from '../fixtures/transactions.js';

const pair = await generateKeyPair('ES256');
const signed = (entity: string, claims: Record<string, unknown> = {}) =>
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
async function registration(entity: string): Promise<FederationOidcRegistration> {
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
test('Typed RP registration captures immutable application-owned data without provider I/O or accreditation claims', async () => {
  const f = await transactionFixture();
  let effects = 0;
  try {
    const input = await registration(f.profile.entityId),
      settings = capture(
        {
          ...f.settings,
          profiles: [{ ...f.profile, oidcRegistration: input }],
          secretProvider: {
            async get(): Promise<never> {
              effects++;
              throw new Error('Unexpected secret I/O');
            },
          },
        },
        'test',
      ),
      result = settings.profiles[0]!.oidcRegistration!;
    assert.equal(effects, 0);
    assert.equal(result.organization.organizationName, 'Fixture Organization');
    assert.equal(result.userInfoEncryption.encryption, 'A256CBC-HS512');
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.organization.contacts));
    assert.equal('trusted' in result, false);
    Reflect.set(input.organization, 'organizationName', 'Changed after capture');
    Reflect.set(input.authorityHints, '0', 'https://foreign.example.test');
    assert.equal(result.organization.organizationName, 'Fixture Organization');
    assert.deepEqual(result.authorityHints, ['https://anchor.example.test']);
  } finally {
    await f.close();
  }
});
test('RP registration rejects absent requirements, unsupported algorithms, wrong protocols and conflicting key purposes', async () => {
  const f = await transactionFixture();
  try {
    const input = await registration(f.profile.entityId);
    for (const mutation of [
      { authorityHints: [] },
      { authorityHints: [f.profile.entityId] },
      { trustMarks: [] },
      { organization: undefined },
      { signingAlgorithm: 'none' },
      { idTokenSigningAlgorithm: 'HS256' },
      { userInfoSigningAlgorithm: 'HS512' },
      { decryptionKeyRef: f.profile.signingKeyRef },
      { decryptionKeyRef: undefined },
      { userInfoEncryption: undefined },
      { userInfoEncryption: { algorithm: 'RSA_1_5', encryption: 'A256CBC-HS512' } },
      { idTokenEncryption: { algorithm: 'RSA-OAEP', encryption: 'unsupported' } },
      { requestedClaims: ['constructor'] },
      { requestedClaims: ['name', 'name'] },
      { unknown: true },
    ])
      assert.throws(
        () => captureProfile({ ...f.profile, oidcRegistration: { ...input, ...mutation } }),
        { code: 'EK_EID_PROFILE' },
      );
    assert.throws(
      () => captureProfile({ ...f.profile, protocol: 'saml2', oidcRegistration: input }),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        captureProfile({
          ...f.profile,
          clientId: 'https://other.example.test',
          oidcRegistration: input,
        }),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        capture(
          {
            ...f.settings,
            profiles: [
              {
                ...f.profile,
                oidcRegistration: { ...input, decryptionKeyRef: 'state-mac-current' },
              },
            ],
          },
          'test',
        ),
      { code: 'EK_EID_PROFILE' },
    );
  } finally {
    await f.close();
  }
});
test('Registration contacts use the selected validator and metadata URLs remain explicit HTTPS data', async () => {
  const f = await transactionFixture();
  try {
    const input = await registration(f.profile.entityId);
    for (const mutation of [
      { organizationName: '' },
      { organizationName: 'Unsafe\nName' },
      { homepageUri: 'http://service.example.test' },
      { policyUri: 'javascript:alert(1)' },
      { resolveEndpoint: 'https://user@service.example.test/resolve' },
      { contacts: [] },
      { contacts: ['not-an-email'] },
      { contacts: ['office@example..test'] },
      { logoUri: 'https://service.example.test/logo.png' },
      { unknown: true },
    ])
      assert.throws(
        () =>
          captureProfile({
            ...f.profile,
            oidcRegistration: { ...input, organization: { ...input.organization, ...mutation } },
          }),
        { code: 'EK_EID_PROFILE' },
      );
    const withoutLogo = { ...input.organization };
    Reflect.deleteProperty(withoutLogo, 'logoUri');
    const valid = captureProfile({
      ...f.profile,
      oidcRegistration: { ...input, organization: withoutLogo, requestedClaims: [] },
    });
    assert.deepEqual(valid.oidcRegistration!.requestedClaims, []);
    assert.equal(valid.oidcRegistration!.organization.logoUri, undefined);
  } finally {
    await f.close();
  }
});
test('Configured marks must be bounded unambiguous RP candidates for the exact application entity', async () => {
  const f = await transactionFixture();
  try {
    const input = await registration(f.profile.entityId);
    for (const claims of [
      { sub: 'https://foreign.example.test' },
      { id: 'https://anchor.example.test/oauth_resource/public/' },
      { exp: 1 },
      { iat: Math.floor(Date.now() / 1000) + 3600 },
      { exp: undefined },
      { trust_mark_type: 'https://anchor.example.test/openid_relying_party/public/' },
    ]) {
      const token = await signed(f.profile.entityId, claims);
      assert.throws(
        () => captureProfile({ ...f.profile, oidcRegistration: { ...input, trustMarks: [token] } }),
        { code: 'EK_EID_PROFILE' },
      );
    }
    assert.throws(
      () =>
        captureProfile({
          ...f.profile,
          oidcRegistration: { ...input, trustMarks: [input.trustMarks[0], input.trustMarks[0]] },
        }),
      { code: 'EK_EID_PROFILE' },
    );
    assert.throws(
      () =>
        captureProfile({
          ...f.profile,
          metadata: { ...f.profile.metadata, maxBytes: 100 },
          oidcRegistration: input,
        }),
      { code: 'EK_EID_PROFILE' },
    );
  } finally {
    await f.close();
  }
});
test('Executable registration objects, nested proxies and array accessors cannot run code', async () => {
  const f = await transactionFixture();
  let effects = 0;
  try {
    const input = await registration(f.profile.entityId),
      dangerous = {
        ...input,
        get organization(): FederationOidcRegistration['organization'] {
          effects++;
          throw new Error('Executable metadata');
        },
      };
    assert.throws(() => captureProfile({ ...f.profile, oidcRegistration: dangerous }), {
      code: 'EK_EID_PROFILE',
    });
    assert.throws(
      () =>
        captureProfile({
          ...f.profile,
          oidcRegistration: {
            ...input,
            organization: new Proxy(input.organization, {
              ownKeys() {
                effects++;
                return [];
              },
            }),
          },
        }),
      { code: 'EK_EID_PROFILE' },
    );
    const empty = new Proxy([] as string[], {
      get() {
        effects++;
        throw new Error('Executable empty array');
      },
    });
    assert.throws(
      () =>
        captureProfile({ ...f.profile, oidcRegistration: { ...input, requestedClaims: empty } }),
      { code: 'EK_EID_PROFILE' },
    );
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
test('Signature-only profile compatibility does not fabricate a missing RP registration', async () => {
  const f = await transactionFixture();
  try {
    const original: FederationProfileV1 = captureProfile(f.profile);
    const settings: ItalianEidPluginSettings = { ...f.settings, profiles: [original] };
    assert.equal(capture(settings, 'test').profiles[0]!.oidcRegistration, undefined);
  } finally {
    await f.close();
  }
});
