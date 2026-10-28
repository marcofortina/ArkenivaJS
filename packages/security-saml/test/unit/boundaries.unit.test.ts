// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSamlService } from '../../dist/index.js';
import { parse, NS, one, content, strongSignatures } from '../../dist/xml.js';
import { fixture } from '../fixture.js';

test('Native XML guard rejects oversized, deeply nested, ambiguous and executable content', () => {
  for (const xml of [
    '',
    '<!DOCTYPE x><x/>',
    '<!ENTITY x "value"><x/>',
    '<x>\0</x>',
    '<x>' + 'x'.repeat(262144) + '</x>',
    '<x>'.repeat(34) + '</x>'.repeat(34),
    '<x>' + '<v/>'.repeat(8193) + '</x>',
    '<x ' + Array.from({ length: 33 }, (_, n) => 'a' + n + '="v"').join(' ') + '/>',
    '<x><a ID="duplicate"/><b Id="duplicate"/></x>',
    '<x><a id=""/></x>',
    '<x><unclosed></x>',
  ])
    assert.throws(() => parse(xml));
  const root = parse(
    '<r xmlns:a="urn:fixture"><a:value>safe<![CDATA[ value]]></a:value><other/></r>',
  ).documentElement;
  assert.equal(content(one(root, 'urn:fixture', 'value')), 'safe value');
  assert.throws(() => one(root, 'urn:fixture', 'missing'));
  for (const xml of ['<x/>', '<x><v/></x>', '<x>\n</x>', '<x>oversized</x>'])
    assert.throws(() => content(parse(xml).documentElement, 4));
  const signature = (algorithm: string, digest: string, reference = '#owned') =>
    `<r xmlns:ds="${NS.signature}"><ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="${algorithm}"/><ds:Reference URI="${reference}"><ds:DigestMethod Algorithm="${digest}"/></ds:Reference></ds:SignedInfo></ds:Signature></r>`;
  const algorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    digest = 'http://www.w3.org/2001/04/xmlenc#sha256';
  strongSignatures(parse(signature(algorithm, digest)).documentElement);
  for (const xml of [
    '<r/>',
    signature('http://www.w3.org/2000/09/xmldsig#rsa-sha1', digest),
    signature(algorithm, 'http://www.w3.org/2000/09/xmldsig#sha1'),
    signature(algorithm, digest, 'https://foreign.invalid/key'),
  ])
    assert.throws(() => strongSignatures(parse(xml).documentElement));
});

test(
  'Configuration rejects accessors, proxies, unsafe provider methods and invalid native endpoints without invoking them',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    let invoked = 0;
    try {
      const accessor = { ...f.settings };
      Object.defineProperty(accessor, 'entityId', {
        get() {
          invoked++;
          return 'unsafe';
        },
      });
      assert.throws(() => createSamlService(accessor));
      assert.throws(() =>
        createSamlService(
          new Proxy(f.settings, {
            ownKeys() {
              invoked++;
              return [];
            },
          }),
        ),
      );
      for (const change of [
        { environment: 'unknown' },
        { binding: 'unknown' },
        { entityId: '\ud800' },
        { expectedAudience: '' },
        { clockSkewSeconds: -1 },
        { clockSkewSeconds: 0.5 },
        { acsUrl: 'https://user:password@sp.fixture.invalid/acs' },
        { acsUrl: 'https://sp.fixture.invalid/acs?query=1' },
        { acsUrl: 'https://sp.fixture.invalid/acs#fragment' },
        { acsUrl: 'invalid' },
        { trustedIdpMetadata: 1 },
        { secretProvider: { get: 3 } },
        { secretProvider: Object.create(null) },
        { replayStore: null },
        { signingCertificateRef: '' },
        { authority: {} },
      ])
        assert.throws(() => createSamlService({ ...f.settings, ...change } as never), {
          code: 'EK_SAML_CONFIGURATION',
        });
      for (const key of ['secretProvider', 'replayStore', 'authority'] as const) {
        const provider = { ...f.settings[key] };
        Object.defineProperty(
          provider,
          key === 'authority' ? 'require' : key === 'replayStore' ? 'read' : 'get',
          {
            get() {
              invoked++;
              throw new Error('Untrusted accessor ran');
            },
          },
        );
        assert.throws(() => createSamlService({ ...f.settings, [key]: provider } as never));
      }
      assert.equal(invoked, 0);
      const unsigned = { ...f.settings };
      Reflect.deleteProperty(unsigned, 'signingKeyRef');
      assert.throws(() => createSamlService(unsigned));
      const noSigning = { ...unsigned };
      Reflect.deleteProperty(noSigning, 'signingCertificateRef');
      assert.ok((await createSamlService(noSigning).createMetadata()).includes('EntityDescriptor'));
    } finally {
      await f.close();
    }
  },
);

test(
  'Malformed durable state, exhausted shared quota and failed atomic writes never produce a transfer or identity',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    try {
      const request = await f.service.beginLogin({ returnPath: '/app' }),
        response = f.response(request.requestId),
        context = { inResponseTo: request.requestId, relayState: request.requestId };
      for (const change of [
        { ownerKey: 'foreign-profile' },
        { kind: 'logout' },
        { id: '_foreign' },
        { binding: 'post' },
        { createdAt: 'invalid' },
        { expiresAt: '2000-01-01T00:00:00.000Z' },
        { returnPath: '//foreign.invalid' },
        { unknown: true },
      ]) {
        const service = createSamlService({
          ...f.settings,
          replayStore: {
            ...f.settings.replayStore,
            async read(...args) {
              const value = await f.settings.replayStore.read(...args);
              return value ? { ...value, ...change } : null;
            },
          },
        });
        await assert.rejects(service.consumeResponse(context, response));
      }
      for (const value of [false, 'not-a-boolean']) {
        let claims = 0;
        const service = createSamlService({
          ...f.settings,
          replayStore: {
            ...f.settings.replayStore,
            async claimOnce() {
              claims++;
              return value as boolean;
            },
          },
        });
        await assert.rejects(service.beginLogin({ returnPath: '/app' }), {
          code: 'EK_BACKEND_UNAVAILABLE',
        });
        assert.equal(claims, value === false ? 8 : 1);
      }
      const rejected = createSamlService({
        ...f.settings,
        replayStore: {
          ...f.settings.replayStore,
          async compareAndSet() {
            return { committed: false };
          },
        },
      });
      await assert.rejects(rejected.beginLogin({ returnPath: '/app' }), { code: 'EK_SAML_REPLAY' });
      assert.equal(
        (await f.service.consumeResponse(context, response)).subject,
        'synthetic-account',
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Untrusted identity snapshots and malformed secret provider values fail closed',
  { timeout: 20000 },
  async () => {
    const f = await fixture();
    try {
      const request = await f.service.beginLogin({ returnPath: '/app' }),
        identity = await f.service.consumeResponse(
          { inResponseTo: request.requestId, relayState: request.requestId },
          f.response(request.requestId),
        );
      for (const change of [
        { issuer: 'https://foreign.invalid' },
        { assurance: 'mfa' },
        { audience: [] },
        { scopes: ['admin'] },
        { claims: {} },
        { attributes: { name: ['x'.repeat(8193)] } },
        { sessionIndex: 'altered' },
        { attributes: { name: new Array(2) } },
        { subject: 'altered' },
      ])
        await assert.rejects(f.service.beginLogout({ ...identity, ...change } as never));
      const accessor = { ...identity };
      Object.defineProperty(accessor, 'attributes', {
        get() {
          throw new Error('Unsafe identity accessor');
        },
      });
      await assert.rejects(f.service.beginLogout(accessor), { code: 'EK_SAML_CONFIGURATION' });
      for (const response of ['', 'not base64', Buffer.from('not XML').toString('base64')])
        await assert.rejects(
          f.service.consumeResponse(
            { inResponseTo: request.requestId, relayState: request.requestId },
            response,
          ),
        );
      for (const bytes of [
        new Uint8Array(),
        new Uint8Array(32769),
        new Uint8Array(new SharedArrayBuffer(10)),
        'private-not-bytes',
      ]) {
        const service = createSamlService({
          ...f.settings,
          secretProvider: {
            async get() {
              return { bytes, keyVersion: 'fixture' } as never;
            },
          },
        });
        await assert.rejects(service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
      }
      for (const value of ['', 'invalid', 1])
        await assert.rejects(f.service.consumeLogoutResponse(value as string));
    } finally {
      await f.close();
    }
  },
);
