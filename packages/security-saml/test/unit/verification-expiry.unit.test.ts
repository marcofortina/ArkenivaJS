// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { createSamlService } from '../../dist/index.js';
import { parse, NS, one } from '../../dist/xml.js';
import { fixture } from '../fixture.js';

test('Malformed native expiry after actual signature verification fails before claiming the valid request', async (context) => {
  const f = await fixture(),
    emit = Worker.prototype.emit;
  let replacement: unknown,
    changed = 0;
  const intercepted = context.mock.method(
    Worker.prototype,
    'emit',
    function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as {
        ok?: boolean;
        result?: { kind?: string; identity?: Record<string, unknown> };
      };
      if (event === 'message' && message?.ok === true && message.result?.kind === 'identity') {
        assert.ok(Date.parse(String(message.result.identity!.verificationExpiresAt)) > Date.now());
        changed++;
        return Reflect.apply(emit, this, [
          event,
          {
            ...message,
            result: {
              ...message.result,
              identity: { ...message.result.identity, verificationExpiresAt: replacement },
            },
          },
        ]);
      }
      return Reflect.apply(emit, this, [event, ...args]);
    },
  );
  try {
    const service = createSamlService({ ...f.settings, clockSkewSeconds: 0 }),
      login = await service.beginLogin({ returnPath: '/' }),
      response = f.response(login.requestId);
    for (replacement of [
      undefined,
      null,
      'invalid',
      '2030-01-01',
      new Date(Date.now() - 1).toISOString(),
    ])
      await assert.rejects(
        () =>
          service.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          ),
        { code: 'EK_SAML_ASSERTION' },
      );
    assert.equal(changed, 5);
    intercepted.mock.restore();
    const accepted = await service.consumeResponse(
      { inResponseTo: login.requestId, relayState: login.requestId },
      response,
    );
    assert.ok(
      Date.parse(String((accepted.claims.saml as Record<string, unknown>).verificationExpiresAt)) >
        Date.now(),
    );
  } finally {
    intercepted.mock.restore();
    await f.close();
  }
});

test('Malformed optional expiry claims cannot authorize logout or execute claim getters', async () => {
  const f = await fixture();
  let hooks = 0;
  try {
    const login = await f.service.beginLogin({ returnPath: '/' }),
      identity = await f.service.consumeResponse(
        { inResponseTo: login.requestId, relayState: login.requestId },
        f.response(login.requestId),
      ),
      claims = identity.claims.saml as Record<string, unknown>;
    for (const expiry of [null, 1, 'invalid', '2030-01-01'])
      await assert.rejects(() =>
        f.service.beginLogout({
          ...identity,
          claims: { saml: { ...claims, verificationExpiresAt: expiry } },
        }),
      );
    const executable = Object.defineProperty({ ...claims }, 'verificationExpiresAt', {
      get() {
        hooks++;
        throw new Error('Executable protocol claims');
      },
    });
    await assert.rejects(() =>
      f.service.beginLogout({ ...identity, claims: { saml: executable } }),
    );
    assert.equal(hooks, 0);
    const logout = await f.service.beginLogout(identity);
    await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
  } finally {
    await f.close();
  }
});

test('Actual signed assertion conditions, confirmation, session and request lifetime independently cap verification evidence', async () => {
  const f = await fixture();
  try {
    const service = createSamlService({ ...f.settings, clockSkewSeconds: 0 });
    for (const selected of ['conditions', 'confirmation', 'session', 'request'] as const) {
      const login = await service.beginLogin({ returnPath: '/' }),
        deadline = new Date(Date.now() + 45000).toISOString(),
        response = f.response(login.requestId, {
          expiresOffsetMs: 600000,
          transformAssertion(xml) {
            const document = parse(xml),
              root = document.documentElement;
            if (selected === 'conditions')
              one(root, NS.assertion, 'Conditions').setAttribute('NotOnOrAfter', deadline);
            if (selected === 'confirmation')
              one(
                one(one(root, NS.assertion, 'Subject'), NS.assertion, 'SubjectConfirmation'),
                NS.assertion,
                'SubjectConfirmationData',
              ).setAttribute('NotOnOrAfter', deadline);
            if (selected === 'session')
              one(root, NS.assertion, 'AuthnStatement').setAttribute(
                'SessionNotOnOrAfter',
                deadline,
              );
            return document.toString();
          },
        }),
        identity = await service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        );
      assert.equal(
        (identity.claims.saml as Record<string, unknown>).verificationExpiresAt,
        selected === 'request' ? login.expiresAt : deadline,
      );
    }
  } finally {
    await f.close();
  }
});

test('Expiry after an actual session write cannot produce identity or allow a replay retry', async (context) => {
  const f = await fixture();
  let writes = 0;
  const service = createSamlService({
    ...f.settings,
    clockSkewSeconds: 0,
    replayStore: {
      ...f.settings.replayStore,
      async compareAndSet(...args) {
        const receipt = await f.settings.replayStore.compareAndSet(...args);
        if (args[0].endsWith(':sessions') && receipt.committed) {
          writes++;
          context.mock.method(Date, 'now', () => expires + 1);
        }
        return receipt;
      },
    },
  });
  let expires = 0;
  try {
    const login = await service.beginLogin({ returnPath: '/' }),
      response = f.response(login.requestId, { expiresOffsetMs: 60000 }),
      root = parse(Buffer.from(response, 'base64').toString()).documentElement;
    expires = Date.parse(
      one(one(root, NS.assertion, 'Assertion'), NS.assertion, 'Conditions').getAttribute(
        'NotOnOrAfter',
      )!,
    );
    await assert.rejects(
      () =>
        service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        ),
      { code: 'EK_SAML_ASSERTION' },
    );
    assert.equal(writes, 1);
    context.mock.restoreAll();
    await assert.rejects(
      () =>
        service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        ),
      { code: 'EK_SAML_REPLAY' },
    );
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

for (const binding of ['redirect', 'post'] as const)
  test(`Native ${binding} results retain the verified assertion deadline without shortening independently authorized logout`, async (context) => {
    const f = await fixture(binding);
    try {
      const service = createSamlService({ ...f.settings, clockSkewSeconds: 0 }),
        login = await service.beginLogin({ returnPath: '/' }),
        response = f.response(login.requestId, { expiresOffsetMs: 60000 }),
        root = parse(Buffer.from(response, 'base64').toString()).documentElement,
        assertion = one(root, NS.assertion, 'Assertion'),
        confirmation = one(
          one(one(assertion, NS.assertion, 'Subject'), NS.assertion, 'SubjectConfirmation'),
          NS.assertion,
          'SubjectConfirmationData',
        ),
        conditions = one(assertion, NS.assertion, 'Conditions'),
        identity = await service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          response,
        ),
        expiresAt = (identity.claims.saml as Record<string, unknown>).verificationExpiresAt;
      assert.equal(
        expiresAt,
        new Date(
          Math.min(
            Date.parse(confirmation.getAttribute('NotOnOrAfter')!),
            Date.parse(conditions.getAttribute('NotOnOrAfter')!),
            Date.parse(login.expiresAt),
          ),
        ).toISOString(),
      );
      assert.ok(Object.isFrozen(identity.claims.saml));
      assert.ok(Date.parse(String(expiresAt)) > Date.now());
      const clock = context.mock.method(Date, 'now', () => Date.parse(String(expiresAt)) + 1);
      try {
        const logout = await service.beginLogout(identity);
        assert.equal(logout.binding, binding);
        await service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
      } finally {
        clock.mock.restore();
      }
    } finally {
      await f.close();
    }
  });
