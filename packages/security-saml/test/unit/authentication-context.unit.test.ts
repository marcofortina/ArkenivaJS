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
import { parse, NS, one, children, content } from '../../dist/xml.js';
import { fixture } from '../fixture.js';

const level = (n: number) => 'https://www.spid.gov.it/SpidL' + n;
const policy = {
  classReferences: [level(2)],
  comparison: 'minimum' as const,
  acceptedClassReferences: [level(2), level(3)],
};
const changeContext = (value: string) => (xml: string) =>
  xml.replace(/<saml:AuthnContext>.*?<\/saml:AuthnContext>/u, value);
const context = (n: number) =>
  `<saml:AuthnContext><saml:AuthnContextClassRef>${level(n)}</saml:AuthnContextClassRef></saml:AuthnContext>`;

for (const binding of ['redirect', 'post'] as const) {
  test(
    `Native signed ${binding} requests express captured context policy and accept only approved signed classes`,
    { timeout: 30000 },
    async () => {
      const f = await fixture(binding);
      try {
        const input = {
            ...f.settings,
            requestedAuthnContext: {
              ...policy,
              classReferences: [...policy.classReferences],
              acceptedClassReferences: [...policy.acceptedClassReferences],
            },
          },
          service = createSamlService(input),
          certificate = await readFile(join(f.directory, 'sp.pem'), 'utf8');
        input.requestedAuthnContext.classReferences[0] = level(1);
        input.requestedAuthnContext.acceptedClassReferences.push(level(1));
        for (const n of [2, 3]) {
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
            xml = inflateRawSync(Buffer.from(target.searchParams.get('SAMLRequest')!, 'base64'), {
              maxOutputLength: 262144,
            }).toString('utf8');
          } else {
            xml = Buffer.from(login.fields.SAMLRequest, 'base64').toString('utf8');
            assert.ok(getVerifiedXml(xml, parse(xml).documentElement, [certificate]));
          }
          const requested = one(parse(xml).documentElement, NS.protocol, 'RequestedAuthnContext');
          assert.equal(requested.getAttribute('Comparison'), 'minimum');
          assert.deepEqual(
            children(requested, NS.assertion, 'AuthnContextClassRef').map((item) =>
              content(item, 2048),
            ),
            [level(2)],
          );
          const identity = await service.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            f.response(login.requestId, { transformAssertion: changeContext(context(n)) }),
          );
          assert.equal((identity.claims.saml as Record<string, unknown>).authnContext, level(n));
          assert.equal(identity.assurance, 'single-factor');
        }
        for (const rejected of [
          context(1),
          context(4),
          '<saml:AuthnContext/>',
          '<saml:AuthnContext><saml:AuthnContextClassRef>' +
            level(2) +
            '</saml:AuthnContextClassRef><saml:AuthnContextClassRef>' +
            level(3) +
            '</saml:AuthnContextClassRef></saml:AuthnContext>',
        ]) {
          const login = await service.beginLogin({ returnPath: '/private' });
          await assert.rejects(
            () =>
              service.consumeResponse(
                { inResponseTo: login.requestId, relayState: login.requestId },
                f.response(login.requestId, { transformAssertion: changeContext(rejected) }),
              ),
            { code: 'EK_SAML_ASSERTION' },
          );
        }
      } finally {
        await f.close();
      }
    },
  );
}

test(
  'Changed authentication context cannot consume transactions created under another policy',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      const first = createSamlService({ ...f.settings, requestedAuthnContext: policy }),
        second = createSamlService({
          ...f.settings,
          requestedAuthnContext: {
            classReferences: [level(3)],
            acceptedClassReferences: [level(3)],
            comparison: 'exact',
          },
        }),
        login = await first.beginLogin({ returnPath: '/private' }),
        response = f.response(login.requestId, { transformAssertion: changeContext(context(3)) });
      await assert.rejects(
        () =>
          second.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          ),
        { code: 'EK_SAML_REPLAY' },
      );
      assert.equal(
        (
          await first.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          )
        ).subject,
        'synthetic-account',
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Context configuration rejects malformed catalogs, contradictory exact policy and executable data',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      for (const value of [
        {},
        { ...policy, comparison: 'unknown' },
        { ...policy, classReferences: [] },
        { ...policy, acceptedClassReferences: [] },
        { ...policy, classReferences: [level(2), level(2)] },
        { ...policy, acceptedClassReferences: Array(9).fill(level(2)) },
        { ...policy, classReferences: ['javascript:untrusted'] },
        { ...policy, classReferences: ['http://untrusted.example.test/context'] },
        { ...policy, comparison: 'exact' },
        { ...policy, acceptedClassReferences: [level(2), 3] },
      ])
        assert.throws(
          () => createSamlService({ ...f.settings, requestedAuthnContext: value } as SamlSettings),
          { code: 'EK_SAML_CONFIGURATION' },
        );
      let effects = 0;
      const executable = {
        ...policy,
        get classReferences(): string[] {
          effects++;
          throw new Error('Executable context policy');
        },
      };
      assert.throws(() => createSamlService({ ...f.settings, requestedAuthnContext: executable }), {
        code: 'EK_SAML_CONFIGURATION',
      });
      assert.throws(
        () =>
          createSamlService({
            ...f.settings,
            requestedAuthnContext: new Proxy(policy, {
              ownKeys() {
                effects++;
                return [];
              },
            }),
          }),
        { code: 'EK_SAML_CONFIGURATION' },
      );
      assert.equal(effects, 0);
      const captured = capture({ ...f.settings, requestedAuthnContext: policy });
      assert.ok(Object.isFrozen(captured.requestedAuthnContext));
      assert.ok(Object.isFrozen(captured.requestedAuthnContext!.classReferences));
      assert.equal(capture(f.settings).requestedAuthnContext, undefined);
    } finally {
      await f.close();
    }
  },
);
