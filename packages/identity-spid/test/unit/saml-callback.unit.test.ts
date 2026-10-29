// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { samlResponse } from '../fixtures/saml-response.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { FederationSamlLogin } from '../../dist/saml-login.js';
import { FederationRuntime } from '../../dist/runtime.js';

after(closeRegistryFixture);

test('Callback defaults remain bounded and output limits deny an otherwise valid native identity', async () => {
  const f = await samlLoginFixture();
  try {
    const settings = { ...f.settings, policy: { maxConcurrent: 8, timeoutMs: 3000 } },
      defaults = new FederationSamlLogin(
        settings,
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      ),
      request = await f.runtime.run((call) => defaults.begin(call, f.input)),
      response = samlResponse(f, request);
    assert.equal(
      (await f.runtime.run((call) => defaults.consume(call, response))).assurance,
      'spid-l2',
    );
    const other = await f.runtime.run((call) => f.login.begin(call, f.input)),
      limited = new FederationSamlLogin(
        { ...settings, policy: { ...settings.policy, maxOutputBytes: 1 } },
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      );
    await assert.rejects(
      () => f.runtime.run((call) => limited.consume(call, samlResponse(f, other))),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(
      () => f.runtime.run((call) => f.login.consume(call, samlResponse(f, other))),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});

test('Configured subject attributes must be present and unambiguous after actual native verification', async () => {
  const f = await samlLoginFixture();
  try {
    const profile = { ...f.document.profile, subjectClaim: 'fiscalNumber' },
      login = new FederationSamlLogin(
        { ...f.settings, profiles: [profile] },
        profile.profileId,
        f.transport,
        f.crypto,
      );
    for (const values of [undefined, ['first', 'second'], ['synthetic-account']] as const) {
      const request = await f.runtime.run((call) =>
          login.begin(call, {
            issuer: f.input.issuer,
            assurance: f.input.assurance,
            returnPath: f.input.returnPath,
          }),
        ),
        response = samlResponse(f, request, { attributes: values ? { fiscalNumber: values } : {} });
      if (values?.length === 1) {
        const result = await f.runtime.run((call) => login.consume(call, response));
        assert.equal(result.subject, 'synthetic-account');
        assert.equal(Object.hasOwn(result, 'tenantHint'), false);
      } else
        await assert.rejects(() => f.runtime.run((call) => login.consume(call, response)), {
          code: 'EK_EID_FEDERATION',
        });
    }
  } finally {
    await f.close();
  }
});

test('Expired native evidence cannot survive a mapping delay or manual object reconstruction', async (context) => {
  const f = await samlLoginFixture();
  try {
    const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
      result = await f.runtime.run((call) => f.login.consume(call, samlResponse(f, login)));
    context.mock.method(Date, 'now', () => Date.parse(result.expiresAt));
    assert.throws(() => f.login.result(result), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => f.login.result({ ...result }), { code: 'EK_EID_FEDERATION' });
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

test('Cancellation retains physical callback capacity while an actual secret provider ignores its signal', async () => {
  const f = await samlLoginFixture(),
    owner = new AbortController();
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 3000 });
  try {
    const request = await f.runtime.run((call) => f.login.begin(call, f.input)),
      input = samlResponse(f, request),
      callback = new FederationSamlLogin(
        {
          ...f.settings,
          secretProvider: {
            async get(reference, options) {
              if (reference === f.document.profile.signingKeyRef) {
                entered();
                await pending;
              }
              return f.settings.secretProvider.get(reference, options);
            },
          },
        },
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      ),
      work = runtime.run((call) => callback.consume(call, input), { signal: owner.signal }),
      rejected = assert.rejects(work, { code: 'EK_ABORTED' });
    await began;
    owner.abort();
    await rejected;
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(() => runtime.run(async () => true), { code: 'EK_BACKEND_UNAVAILABLE' });
    release();
    await runtime.close();
    assert.equal(runtime.stats().active, 0);
    await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, input)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    release();
    await runtime.close();
    await f.close();
  }
});

test('Actual native signed SAML acceptance retains encrypted context and only live owner evidence', async () => {
  const f = await samlLoginFixture();
  try {
    const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
      response = samlResponse(f, login),
      result = await f.runtime.run((call) => f.login.consume(call, response));
    assert.equal(result.issuer, f.input.issuer);
    assert.equal(result.subject, 'synthetic-transient-subject');
    assert.equal(result.returnPath, f.input.returnPath);
    assert.equal(result.tenantHint, f.input.tenantHint);
    assert.equal(result.assurance, 'spid-l2');
    assert.deepEqual(result.attributes.tenant_id, ['untrusted-tenant']);
    assert.equal(Object.isFrozen(result.attributes.tenant_id), true);
    assert.equal(f.login.result(result), result);
    assert.throws(() => f.login.result({ ...result }), { code: 'EK_EID_FEDERATION' });
    const other = new FederationSamlLogin(
      f.settings,
      f.document.profile.profileId,
      f.transport,
      f.crypto,
    );
    assert.throws(() => other.result(result), { code: 'EK_EID_FEDERATION' });
    await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.revokedIdp = true;
    await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, f.input)));
    assert.throws(() => f.login.result(result), { code: 'EK_EID_FEDERATION' });
  } finally {
    await f.close();
  }
});

test('Strict callback data rejects executable inputs, unknown fields and malformed encoding before I/O', async () => {
  const f = await samlLoginFixture();
  let hooks = 0;
  try {
    const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
      good = samlResponse(f, login),
      before = f.paths.length,
      getter = Object.defineProperty({}, 'transactionId', {
        enumerable: true,
        get() {
          hooks++;
          return good.transactionId;
        },
      });
    for (const input of [
      null,
      [],
      getter,
      new Proxy(good, {
        get() {
          hooks++;
          throw new Error('Executable callback');
        },
      }),
      { ...good, extra: true },
      { ...good, issuer: 'https://foreign.example.test' },
      { ...good, transactionId: 'a'.repeat(63) },
      { ...good, relayState: '_invalid' },
      { ...good, samlResponse: 'not-base64' },
      { ...good, samlResponse: ' '.repeat(65537) },
      { ...good, samlResponse: good.samlResponse + '=' },
    ])
      await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, input)), {
        code: 'EK_EID_FEDERATION',
      });
    assert.equal(hooks, 0);
    assert.equal(f.paths.length, before);
    assert.equal(
      (await f.runtime.run((call) => f.login.consume(call, good))).subject,
      'synthetic-transient-subject',
    );
  } finally {
    await f.close();
  }
});

test('The protected native request and posted RelayState cannot be interchanged between real logins', async () => {
  const f = await samlLoginFixture();
  try {
    const first = await f.runtime.run((call) => f.login.begin(call, f.input)),
      second = await f.runtime.run((call) => f.login.begin(call, f.input)),
      response = samlResponse(f, first),
      other = samlResponse(f, second),
      paths = f.paths.length;
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          f.login.consume(call, { ...response, relayState: other.relayState }),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.paths.length, paths);
    await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(
      (await f.runtime.run((call) => f.login.consume(call, other))).assurance,
      'spid-l2',
    );
  } finally {
    await f.close();
  }
});

test(
  'Actual native XML signatures and semantic policy reject independent callback attack classes',
  { timeout: 30000 },
  async (context) => {
    const f = await samlLoginFixture();
    try {
      for (const [name, changes] of [
        ['unsigned assertion', { signedAssertion: false }],
        ['unsigned response', { signedResponse: false }],
        ['unregistered signing key', { foreignKey: true }],
        ['wrong issuer', { issuer: 'https://foreign.example.test' }],
        ['wrong audience', { audience: 'https://foreign.example.test' }],
        ['wrong recipient', { recipient: 'https://foreign.example.test/acs' }],
        ['wrong signed request', { inResponseTo: '_' + 'f'.repeat(40) }],
        ['LoA downgrade', { context: 'https://www.spid.gov.it/SpidL1' }],
        ['expired assertion', { expiresAt: new Date(Date.now() - 1000).toISOString() }],
        [
          'wrong NameID format',
          { nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' },
        ],
        ['wrong NameID qualifier', { nameQualifier: 'https://foreign.example.test' }],
        ['missing NameID qualifier', { nameQualifier: null }],
        ['wrong RP qualifier', { spNameQualifier: 'https://foreign.example.test' }],
      ] as const)
        await context.test(name, async () => {
          const login = await f.runtime.run((call) => f.login.begin(call, f.input));
          await assert.rejects(
            () => f.runtime.run((call) => f.login.consume(call, samlResponse(f, login, changes))),
            { code: 'EK_EID_FEDERATION' },
          );
          await assert.rejects(
            () => f.runtime.run((call) => f.login.consume(call, samlResponse(f, login))),
            { code: 'EK_EID_FEDERATION' },
          );
        });
    } finally {
      await f.close();
    }
  },
);

test('Fresh RP and IdP withdrawal, secret outages and uncertain claims never yield native evidence', async () => {
  const f = await samlLoginFixture();
  try {
    for (const selected of [
      'revokedRp',
      'revokedIdp',
      'unavailable',
      'storage',
      'ambiguousClaim',
    ] as const) {
      const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
        response = samlResponse(f, login);
      if (selected === 'storage') f.persistence.storage = false;
      else if (selected === 'ambiguousClaim') f.persistence.ambiguousClaim = true;
      else f.state[selected] = true;
      await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
        code: selected === 'unavailable' ? 'EK_BACKEND_UNAVAILABLE' : 'EK_EID_FEDERATION',
      });
      if (selected === 'storage') f.persistence.storage = true;
      else if (selected === 'ambiguousClaim') f.persistence.ambiguousClaim = false;
      else f.state[selected] = false;
      if (selected !== 'storage')
        await assert.rejects(() => f.runtime.run((call) => f.login.consume(call, response)), {
          code: 'EK_EID_FEDERATION',
        });
    }
  } finally {
    await f.close();
  }
});
