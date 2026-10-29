// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createVerify } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { getVerifiedXml } from '@node-saml/node-saml/lib/xml.js';
import { createSamlService } from '../../dist/index.js';
import type { SamlSettings } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';
import { parse, NS, one, content } from '../../dist/xml.js';
import { fixture } from '../fixture.js';

const level = (n: number) => 'https://www.spid.gov.it/SpidL' + n;
const context = (n: number) => ({
  classReferences: [level(n)],
  comparison: 'exact' as const,
  acceptedClassReferences: [level(n)],
});
const responseContext = (n: number) => (xml: string) =>
  xml
    .replace(
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    )
    .replace('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', level(n));

for (const binding of ['redirect', 'post'] as const)
  test(`Native signed SPID ${binding} minimum comparison accepts only explicitly configured equal or higher classes`, async () => {
    const f = await fixture(binding);
    try {
      const certificate = await readFile(join(f.directory, 'sp.pem'), 'utf8');
      const service = createSamlService({
        ...f.settings,
        authenticationRequestProfile: { kind: 'spid' },
        requestedAuthnContext: {
          classReferences: [level(2)],
          comparison: 'minimum',
          acceptedClassReferences: [level(2), level(3)],
        },
      });
      for (const n of [1, 2, 3]) {
        const login = await service.beginLogin({ returnPath: '/' }),
          xml =
            login.binding === 'post'
              ? Buffer.from(login.fields.SAMLRequest, 'base64').toString()
              : inflateRawSync(
                  Buffer.from(
                    new URL(login.redirectUrl).searchParams.get('SAMLRequest')!,
                    'base64',
                  ),
                ).toString();
        if (login.binding === 'post')
          assert.ok(getVerifiedXml(xml, parse(xml).documentElement, [certificate]));
        else {
          const target = new URL(login.redirectUrl),
            signed = target.search
              .slice(1)
              .split('&')
              .filter((part) => !part.startsWith('Signature='))
              .join('&');
          assert.equal(
            createVerify('RSA-SHA256')
              .update(signed)
              .verify(certificate, Buffer.from(target.searchParams.get('Signature')!, 'base64')),
            true,
          );
        }
        assert.equal(
          one(parse(xml).documentElement, NS.protocol, 'RequestedAuthnContext').getAttribute(
            'Comparison',
          ),
          'minimum',
        );
        const work = service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          f.response(login.requestId, { transformAssertion: responseContext(n) }),
        );
        if (n === 1) await assert.rejects(work, { code: 'EK_SAML_ASSERTION' });
        else {
          const identity = await work;
          assert.equal((identity.claims.saml as Record<string, unknown>).authnContext, level(n));
          assert.equal(identity.assurance, 'single-factor');
        }
      }
      const restricted = createSamlService({
          ...f.settings,
          authenticationRequestProfile: { kind: 'spid' },
          requestedAuthnContext: {
            classReferences: [level(2)],
            comparison: 'minimum',
            acceptedClassReferences: [level(2)],
          },
        }),
        login = await restricted.beginLogin({ returnPath: '/' });
      await assert.rejects(
        () =>
          restricted.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            f.response(login.requestId, { transformAssertion: responseContext(3) }),
          ),
        { code: 'EK_SAML_ASSERTION' },
      );
      const exact = createSamlService({
          ...f.settings,
          authenticationRequestProfile: { kind: 'spid' },
          requestedAuthnContext: context(2),
        }),
        old = await exact.beginLogin({ returnPath: '/' }),
        response = f.response(old.requestId, { transformAssertion: responseContext(2) });
      await assert.rejects(
        () =>
          service.consumeResponse(
            { inResponseTo: old.requestId, relayState: old.requestId },
            response,
          ),
        { code: 'EK_SAML_REPLAY' },
      );
      assert.equal(
        (
          await exact.consumeResponse(
            { inResponseTo: old.requestId, relayState: old.requestId },
            response,
          )
        ).subject,
        'synthetic-account',
      );
    } finally {
      await f.close();
    }
  });

for (const binding of ['redirect', 'post'] as const)
  test(`Origin-only SPID identifiers remain exact in native signed ${binding} requests`, async () => {
    const f = await fixture(binding);
    try {
      const entityId = new URL(f.settings.entityId).origin,
        certificate = await readFile(join(f.directory, 'sp.pem'), 'utf8'),
        service = createSamlService({
          ...f.settings,
          entityId,
          expectedAudience: entityId,
          requestedAuthnContext: context(2),
          authenticationRequestProfile: { kind: 'spid' },
        }),
        login = await service.beginLogin({ returnPath: '/' });
      let xml: string;
      if (login.binding === 'post') {
        xml = Buffer.from(login.fields.SAMLRequest, 'base64').toString();
        assert.ok(getVerifiedXml(xml, parse(xml).documentElement, [certificate]));
      } else {
        const target = new URL(login.redirectUrl),
          signed = ['SAMLRequest', 'RelayState', 'SigAlg']
            .map((name) =>
              target.search
                .slice(1)
                .split('&')
                .find((part) => part.startsWith(name + '='))!,
            )
            .join('&');
        assert.equal(
          createVerify('RSA-SHA256')
            .update(signed)
            .verify(certificate, Buffer.from(target.searchParams.get('Signature')!, 'base64')),
          true,
        );
        xml = inflateRawSync(
          Buffer.from(target.searchParams.get('SAMLRequest')!, 'base64'),
        ).toString();
      }
      const issuer = one(parse(xml).documentElement, NS.assertion, 'Issuer');
      assert.equal(content(issuer), entityId);
      assert.equal(issuer.getAttribute('NameQualifier'), entityId);
      assert.equal(entityId.endsWith('/'), false);
    } finally {
      await f.close();
    }
  });

for (const binding of ['redirect', 'post'] as const)
  test(
    `Native signed ${binding} SPID request formatting binds all three levels before SDK signing`,
    { timeout: 30000 },
    async () => {
      const f = await fixture(binding);
      try {
        const certificate = await readFile(join(f.directory, 'sp.pem'), 'utf8');
        for (const n of [1, 2, 3]) {
          const profile = {
              kind: 'spid' as const,
              ...(n === 1 ? {} : { attributeConsumingServiceIndex: n === 2 ? 0 : 65535 }),
            },
            service = createSamlService({
              ...f.settings,
              requestedAuthnContext: context(n),
              authenticationRequestProfile: profile,
            });
          const login = await service.beginLogin({ returnPath: '/private' });
          let xml: string;
          if (login.binding === 'redirect') {
            const target = new URL(login.redirectUrl),
              signed = ['SAMLRequest', 'RelayState', 'SigAlg']
                .map((name) =>
                  target.search
                    .slice(1)
                    .split('&')
                    .find((part) => part.startsWith(name + '='))!,
                )
                .join('&');
            assert.equal(
              createVerify('RSA-SHA256')
                .update(signed)
                .verify(certificate, Buffer.from(target.searchParams.get('Signature')!, 'base64')),
              true,
            );
            assert.equal(target.searchParams.get('RelayState'), login.requestId);
            xml = inflateRawSync(Buffer.from(target.searchParams.get('SAMLRequest')!, 'base64'), {
              maxOutputLength: 262144,
            }).toString('utf8');
          } else {
            xml = Buffer.from(login.fields.SAMLRequest, 'base64').toString('utf8');
            assert.ok(getVerifiedXml(xml, parse(xml).documentElement, [certificate]));
            assert.equal(login.fields.RelayState, login.requestId);
          }
          const root = parse(xml).documentElement,
            issuer = one(root, NS.assertion, 'Issuer'),
            policy = one(root, NS.protocol, 'NameIDPolicy');
          assert.equal(root.getAttribute('ID'), login.requestId);
          assert.equal(root.getAttribute('ForceAuthn'), n > 1 ? 'true' : '');
          assert.equal(root.hasAttribute('IsPassive'), false);
          assert.equal(root.getAttribute('ProtocolBinding'), NS.post);
          assert.equal(root.getAttribute('AssertionConsumerServiceURL'), f.settings.acsUrl);
          assert.equal(
            root.getAttribute('AttributeConsumingServiceIndex'),
            n === 1 ? '' : n === 2 ? '0' : '65535',
          );
          assert.equal(content(issuer, 2048), f.settings.entityId);
          assert.equal(issuer.getAttribute('NameQualifier'), f.settings.entityId);
          assert.equal(
            issuer.getAttribute('Format'),
            'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
          );
          assert.equal(
            policy.getAttribute('Format'),
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          );
          assert.equal(policy.hasAttribute('AllowCreate'), false);
          const proof = f.response(login.requestId, { transformAssertion: responseContext(n) });
          assert.equal(
            (
              await service.consumeResponse(
                { inResponseTo: login.requestId, relayState: login.requestId },
                proof,
              )
            ).subject,
            'synthetic-account',
          );
          await assert.rejects(
            () =>
              service.consumeResponse(
                { inResponseTo: login.requestId, relayState: login.requestId },
                proof,
              ),
            { code: 'EK_SAML_REPLAY' },
          );
          const other = await service.beginLogin({ returnPath: '/private' });
          await assert.rejects(
            () =>
              service.consumeResponse(
                { inResponseTo: other.requestId, relayState: other.requestId },
                f.response(other.requestId, {
                  transformAssertion: responseContext(n === 1 ? 2 : 1),
                }),
              ),
            { code: 'EK_SAML_ASSERTION' },
          );
        }
      } finally {
        await f.close();
      }
    },
  );

test(
  'SPID request formatting requires explicit signed bounded context and captures immutable policy data',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      const settings = {
        ...f.settings,
        requestedAuthnContext: context(2),
        authenticationRequestProfile: { kind: 'spid' as const, attributeConsumingServiceIndex: 1 },
      };
      let effects = 0;
      for (const profile of [
        null,
        {},
        { kind: 'other' },
        { kind: 'spid', unknown: true },
        ...[-1, 65536, 0.5, NaN, Infinity, '1', null].map((attributeConsumingServiceIndex) => ({
          kind: 'spid',
          attributeConsumingServiceIndex,
        })),
        Object.defineProperty({}, 'kind', {
          get() {
            effects++;
            return 'spid';
          },
        }),
        new Proxy(
          { kind: 'spid' },
          {
            ownKeys() {
              effects++;
              return ['kind'];
            },
          },
        ),
      ])
        assert.throws(
          () => createSamlService({ ...settings, authenticationRequestProfile: profile } as never),
          { code: 'EK_SAML_CONFIGURATION' },
        );
      for (const changed of [
        { requestedAuthnContext: undefined },
        { requestedAuthnContext: { ...context(2), comparison: 'maximum' } },
        { requestedAuthnContext: { ...context(2), comparison: 'better' } },
        {
          requestedAuthnContext: {
            ...context(2),
            comparison: 'minimum',
            acceptedClassReferences: [level(1), level(2)],
          },
        },
        {
          requestedAuthnContext: {
            ...context(2),
            comparison: 'minimum',
            acceptedClassReferences: [level(3)],
          },
        },
        {
          requestedAuthnContext: {
            ...context(2),
            comparison: 'minimum',
            acceptedClassReferences: [level(2), 'urn:example:foreign'],
          },
        },
        {
          requestedAuthnContext: {
            classReferences: [level(2), level(3)],
            comparison: 'exact',
            acceptedClassReferences: [level(2), level(3)],
          },
        },
        {
          requestedAuthnContext: {
            classReferences: ['urn:example:unknown'],
            comparison: 'exact',
            acceptedClassReferences: ['urn:example:unknown'],
          },
        },
        { signingKeyRef: undefined, signingCertificateRef: undefined },
        { signingCertificateRef: undefined },
        { signingCertificateRef: settings.signingKeyRef },
        { entityId: 'not-an-entity-uri', expectedAudience: 'not-an-entity-uri' },
        { entityId: 'http://127.0.0.1/entity', expectedAudience: 'http://127.0.0.1/entity' },
        { acsUrl: 'http://127.0.0.1/acs' },
        { expectedAudience: 'https://foreign.fixture.invalid/entity' },
      ])
        assert.throws(() => createSamlService({ ...settings, ...changed } as SamlSettings), {
          code: 'EK_SAML_CONFIGURATION',
        });
      assert.equal(effects, 0);
      const captured = capture(settings);
      settings.authenticationRequestProfile.attributeConsumingServiceIndex = 2;
      assert.equal(captured.authenticationRequestProfile!.attributeConsumingServiceIndex, 1);
      assert.equal(Object.isFrozen(captured.authenticationRequestProfile), true);
      assert.equal(capture(f.settings).authenticationRequestProfile, undefined);
    } finally {
      await f.close();
    }
  },
);

test(
  'Profile and attribute selection cannot consume another captured SAML request policy',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      const base = { ...f.settings, requestedAuthnContext: context(2) },
        ordinary = createSamlService(base),
        profiled = createSamlService({
          ...base,
          authenticationRequestProfile: { kind: 'spid', attributeConsumingServiceIndex: 1 },
        }),
        changed = createSamlService({
          ...base,
          authenticationRequestProfile: { kind: 'spid', attributeConsumingServiceIndex: 2 },
        });
      const first = await ordinary.beginLogin({ returnPath: '/private' }),
        response = f.response(first.requestId, { transformAssertion: responseContext(2) });
      await assert.rejects(
        () =>
          profiled.consumeResponse(
            { inResponseTo: first.requestId, relayState: first.requestId },
            response,
          ),
        { code: 'EK_SAML_REPLAY' },
      );
      assert.equal(
        (
          await ordinary.consumeResponse(
            { inResponseTo: first.requestId, relayState: first.requestId },
            response,
          )
        ).subject,
        'synthetic-account',
      );
      const second = await profiled.beginLogin({ returnPath: '/private' });
      await assert.rejects(
        () =>
          changed.consumeResponse(
            { inResponseTo: second.requestId, relayState: second.requestId },
            f.response(second.requestId, { transformAssertion: responseContext(2) }),
          ),
        { code: 'EK_SAML_REPLAY' },
      );
    } finally {
      await f.close();
    }
  },
);
