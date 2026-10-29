// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { fixture } from '../fixture.js';

const entity = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';

test('Generic SAML retains actual signed profile facts without imposing the SPID assertion policy', async () => {
  const f = await fixture();
  try {
    for (const variant of ['default', 'formats', 'no-before', 'advice'] as const) {
      const login = await f.service.beginLogin({ returnPath: '/' }),
        response = f.response(login.requestId, {
          transformAssertion(xml) {
            if (variant === 'formats')
              return xml.replace('<saml:Issuer>', `<saml:Issuer Format="${entity}">`);
            if (variant === 'no-before') return xml.replace(/ NotBefore="[^"]+"/u, '');
            if (variant === 'advice')
              return xml.replace('</saml:Assertion>', '<saml:Advice/></saml:Assertion>');
            return xml;
          },
          transformResponse: (xml) =>
            variant === 'formats'
              ? xml.replace('<saml:Issuer>', `<saml:Issuer Format="${entity}">`)
              : xml,
        }),
        identity = await f.service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        ),
        profile = (identity.claims.saml as Record<string, unknown>).profile;
      assert.deepEqual(profile, {
        ...(variant === 'formats'
          ? { assertionIssuerFormat: entity, responseIssuerFormat: entity }
          : {}),
        conditionsNotBeforePresent: variant !== 'no-before',
        advicePresent: variant === 'advice',
      });
      assert.equal(Object.isFrozen(profile), true);
    }
  } finally {
    await f.close();
  }
});

test('Malformed native profile facts after actual verification fail before claiming the valid request', async (context) => {
  const f = await fixture(),
    emit = Worker.prototype.emit;
  let replacement: unknown,
    intercepted = 0,
    hooks = 0;
  const valid = { conditionsNotBeforePresent: true, advicePresent: false },
    executable = Object.defineProperty({ ...valid }, 'advicePresent', {
      enumerable: true,
      get() {
        hooks++;
        return false;
      },
    }),
    proxy = new Proxy(valid, {
      ownKeys() {
        hooks++;
        throw new Error('Executable native profile');
      },
    }),
    mock = context.mock.method(
      Worker.prototype,
      'emit',
      function (this: Worker, event: string | symbol, ...args: unknown[]) {
        const message = args[0] as {
          ok?: boolean;
          result?: { kind?: string; identity?: Record<string, unknown> };
        };
        if (event === 'message' && message?.ok === true && message.result?.kind === 'identity') {
          assert.deepEqual(message.result.identity!.profile, valid);
          intercepted++;
          return Reflect.apply(emit, this, [
            event,
            {
              ...message,
              result: {
                ...message.result,
                identity: { ...message.result.identity, profile: replacement },
              },
            },
          ]);
        }
        return Reflect.apply(emit, this, [event, ...args]);
      },
    );
  try {
    const login = await f.service.beginLogin({ returnPath: '/' }),
      response = f.response(login.requestId);
    for (replacement of [
      undefined,
      null,
      [],
      { ...valid, conditionsNotBeforePresent: 0 },
      { ...valid, advicePresent: 'false' },
      { ...valid, assertionIssuerFormat: 42 },
      { ...valid, extra: true },
      executable,
      proxy,
    ])
      await assert.rejects(
        () =>
          f.service.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          ),
        { code: 'EK_SAML_ASSERTION' },
      );
    assert.equal(intercepted, 9);
    assert.equal(hooks, 0);
    mock.mock.restore();
    assert.equal(
      (
        await f.service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        )
      ).subject,
      'synthetic-account',
    );
  } finally {
    mock.mock.restore();
    await f.close();
  }
});

test('Optional logout profile metadata stays data-only and cannot be stripped from a newer persisted identity', async () => {
  const f = await fixture();
  let hooks = 0;
  try {
    const login = await f.service.beginLogin({ returnPath: '/' }),
      identity = await f.service.consumeResponse(
        { inResponseTo: login.requestId, relayState: login.requestId },
        f.response(login.requestId),
      ),
      saml = identity.claims.saml as Record<string, unknown>,
      executable = Object.defineProperty({}, 'advicePresent', {
        get() {
          hooks++;
          return false;
        },
      });
    for (const profile of [
      null,
      {},
      { conditionsNotBeforePresent: true, advicePresent: false, responseIssuerFormat: 42 },
      executable,
    ])
      await assert.rejects(() =>
        f.service.beginLogout({ ...identity, claims: { saml: { ...saml, profile } } }),
      );
    const { profile, ...legacy } = saml;
    void profile;
    await assert.rejects(() => f.service.beginLogout({ ...identity, claims: { saml: legacy } }), {
      code: 'EK_SAML_ASSERTION',
    });
    assert.equal(hooks, 0);
    const logout = await f.service.beginLogout(identity);
    await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
  } finally {
    await f.close();
  }
});
