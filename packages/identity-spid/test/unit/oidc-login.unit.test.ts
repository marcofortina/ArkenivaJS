// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify } from 'jose';
import { calculatePKCECodeChallenge } from 'openid-client';
import type { FederationAssurance } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';
import { FederationOidcLogin } from '../../dist/oidc-login.js';
import { FederationTransactions } from '../../dist/transactions.js';
import { configurationEndpoint } from '../../dist/resolver.js';
import { membershipFixture, op } from '../fixtures/membership.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { registration } from '../fixtures/registration.js';

const signing = generateKeyPairSync('rsa', { modulusLength: 2048 });
const metadata = {
  issuer: op,
  authorization_endpoint: op + '/authorize',
  response_types_supported: ['code'],
  scopes_supported: ['openid'],
  code_challenge_methods_supported: ['S256'],
  request_object_signing_alg_values_supported: ['RS256'],
  acr_values_supported: ['https://www.spid.gov.it/SpidL2'],
  client_registration_types_supported: ['automatic'],
  claims_parameter_supported: true,
  request_parameter_supported: true,
};
async function fixture(
  options: { metadata?: Record<string, unknown>; status?: Record<string, unknown> } = {},
) {
  const f = await transactionFixture(),
    graph = await membershipFixture({
      op: { metadata: { openid_provider: { ...metadata, ...options.metadata } } },
      ...(options.status ? { status: options.status } : {}),
    }),
    profile = { ...graph.profile, oidcRegistration: await registration(graph.profile.entityId) },
    raw = { ...f.settings, profiles: [profile] },
    settings = capture(raw, 'test');
  graph.records.set(configurationEndpoint(op), graph.leafConfiguration);
  f.material.set('signing-ref', {
    bytes: Buffer.from(signing.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  return {
    ...f,
    graph,
    profile,
    raw,
    settings,
    flow: () => new FederationOidcLogin(settings, profile.profileId, graph.http, f.crypto),
    input: {
      issuer: op,
      assurance: 'spid-l2' as const,
      returnPath: '/private',
      tenantHint: 'unverified-tenant',
    },
  };
}
test('A real signed JAR binds live federation trust, captured registration, protected nonce and PKCE', async () => {
  const f = await fixture();
  try {
    const result = await f.runtime.run((call) => f.flow().begin(call, f.input)),
      target = new URL(result.redirectUrl),
      verified = await jwtVerify(target.searchParams.get('request')!, signing.publicKey, {
        issuer: f.profile.entityId,
        audience: op,
        algorithms: ['RS256'],
      }),
      transaction = await f.runtime.run((call) =>
        new FederationTransactions(f.settings, f.profile.profileId, f.crypto).consume(
          call,
          result.transactionId,
          op,
        ),
      );
    assert.equal(target.origin + target.pathname, metadata.authorization_endpoint);
    assert.equal(target.searchParams.get('client_id'), f.profile.entityId);
    assert.equal(verified.payload.client_id, f.profile.entityId);
    assert.equal(verified.payload.redirect_uri, f.profile.redirectUri);
    assert.equal(verified.payload.state, result.transactionId);
    assert.equal(verified.payload.nonce, transaction.nonce);
    assert.equal(
      verified.payload.code_challenge,
      await calculatePKCECodeChallenge(transaction.verifier),
    );
    for (const name of ['scope', 'response_type', 'code_challenge', 'code_challenge_method'])
      assert.equal(target.searchParams.get(name), verified.payload[name]);
    assert.equal(verified.payload.acr_values, 'https://www.spid.gov.it/SpidL2');
    assert.deepEqual(verified.payload.claims, {
      userinfo: { name: null, family_name: null },
    });
    assert.equal(verified.payload.prompt, 'consent');
    assert.equal(transaction.returnPath, '/private');
    assert.equal(transaction.tenantHint, 'unverified-tenant');
    assert.ok(verified.payload.exp! <= Date.now() / 1000 + 30);
    assert.equal(Date.parse(result.expiresAt) / 1000, verified.payload.exp);
    for (const sensitive of [transaction.verifier, 'unverified-tenant', '/private', 'signing-ref'])
      assert.ok(!result.redirectUrl.includes(sensitive));
    const persisted = JSON.stringify([...f.rows.values()]);
    assert.ok(!persisted.includes(transaction.verifier));
    assert.ok(!persisted.includes(transaction.nonce));
    assert.equal(f.graph.statuses.length, 2);
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          new FederationTransactions(f.settings, f.profile.profileId, f.crypto).consume(
            call,
            result.transactionId,
            op,
          ),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Independent login instances create distinct protected state and nonce under concurrent requests', async () => {
  const f = await fixture();
  try {
    const logins = await Promise.all(
      Array.from({ length: 8 }, () => f.runtime.run((call) => f.flow().begin(call, f.input))),
    );
    assert.equal(new Set(logins.map((login) => login.transactionId)).size, 8);
    const nonces = await Promise.all(
      logins.map(
        async (login) =>
          (
            await jwtVerify(
              new URL(login.redirectUrl).searchParams.get('request')!,
              signing.publicKey,
            )
          ).payload.nonce,
      ),
    );
    assert.equal(new Set(nonces).size, 8);
    assert.equal(f.rows.size, 8);
    assert.equal(f.graph.statuses.length, 16);
  } finally {
    await f.close();
  }
});
test('Unapproved issuers, assurance, return paths and executable inputs cannot trigger provider work', async () => {
  const f = await fixture();
  let effects = 0;
  try {
    for (const input of [
      { ...f.input, issuer: 'https://foreign.example.test' },
      { ...f.input, assurance: 'spid-l1' as FederationAssurance },
      { ...f.input, returnPath: 'https://foreign.example.test' },
      { ...f.input, returnPath: '//foreign.example.test' },
      {
        ...f.input,
        get issuer(): string {
          effects++;
          throw new Error('Executable issuer');
        },
      },
      new Proxy(f.input, {
        ownKeys() {
          effects++;
          return [];
        },
      }),
    ])
      await assert.rejects(() => f.runtime.run((call) => f.flow().begin(call, input)));
    assert.equal(effects, 0);
    assert.equal(f.graph.reads.length, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    await f.close();
  }
});
test('Revoked membership and unsupported signed protocol metadata never create login state', async () => {
  for (const options of [
    { status: { status: 'revoked' } },
    { metadata: { code_challenge_methods_supported: ['plain'] } },
    { metadata: { response_types_supported: ['token'] } },
    { metadata: { request_object_signing_alg_values_supported: ['none'] } },
    { metadata: { acr_values_supported: ['https://www.spid.gov.it/SpidL1'] } },
    { metadata: { client_registration_types_supported: ['explicit'] } },
    { metadata: { claims_parameter_supported: false } },
    { metadata: { request_parameter_supported: false } },
    { metadata: { authorization_endpoint: 'http://idp.example.test/authorize' } },
  ]) {
    const f = await fixture(options);
    try {
      await assert.rejects(() => f.runtime.run((call) => f.flow().begin(call, f.input)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.rows.size, 0);
    } finally {
      await f.close();
    }
  }
});
test('Storage or secret failure and ambiguous transaction persistence cannot produce a redirect', async () => {
  const f = await fixture();
  try {
    f.state.storage = false;
    await assert.rejects(() => f.runtime.run((call) => f.flow().begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.storage = true;
    f.state.secrets = false;
    await assert.rejects(() => f.runtime.run((call) => f.flow().begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.secrets = true;
    f.state.ambiguousCreate = true;
    await assert.rejects(() => f.runtime.run((call) => f.flow().begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(
      f.rows.size,
      1,
      'An ambiguous committed write cannot be converted into login success',
    );
  } finally {
    await f.close();
  }
});
test('Late live membership work retains actual admission after the login caller times out', async () => {
  const f = await fixture();
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  try {
    const flow = new FederationOidcLogin(
        f.settings,
        f.profile.profileId,
        {
          ...f.graph.http,
          async trustMarkStatus(endpoint, token, options) {
            entered();
            await pending;
            return f.graph.http.trustMarkStatus(endpoint, token, options);
          },
        },
        f.crypto,
      ),
      work = f.runtime.run((call) => flow.begin(call, f.input), { timeoutMs: 100 }),
      rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    await rejected;
    assert.equal(f.runtime.stats().active, 1);
    assert.equal(f.rows.size, 0);
  } finally {
    release();
    await f.close();
  }
});
test('Italian automatic request-object metadata works without requesting unconfigured user claims', async () => {
  const f = await fixture({
    metadata: {
      request_parameter_supported: undefined,
      request_authentication_methods_supported: { ar: ['request_object'] },
      claims_parameter_supported: false,
    },
  });
  try {
    const profile = {
        ...f.profile,
        oidcRegistration: { ...f.profile.oidcRegistration, requestedClaims: [] },
      },
      settings = capture({ ...f.raw, profiles: [profile] }, 'test'),
      flow = new FederationOidcLogin(settings, profile.profileId, f.graph.http, f.crypto),
      result = await f.runtime.run((call) => flow.begin(call, f.input)),
      verified = await jwtVerify(
        new URL(result.redirectUrl).searchParams.get('request')!,
        signing.publicKey,
      );
    assert.equal(verified.payload.claims, undefined);
    assert.equal(verified.payload.scope, 'openid');
  } finally {
    await f.close();
  }
});
test('Expired RP registration marks deny initiation before network I/O even on an existing instance', async (t) => {
  const f = await fixture(),
    flow = f.flow();
  try {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(3601000);
    await assert.rejects(() => f.runtime.run((call) => flow.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(f.graph.reads.length, 0);
    assert.equal(f.rows.size, 0);
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('Finite encoded input and final redirect budgets cannot be bypassed by valid protocol values', async () => {
  const f = await fixture();
  try {
    const inputSettings = capture(
        { ...f.raw, policy: { ...f.raw.policy, maxInputBytes: 1 } },
        'test',
      ),
      inputFlow = new FederationOidcLogin(
        inputSettings,
        f.profile.profileId,
        f.graph.http,
        f.crypto,
      );
    await assert.rejects(() => f.runtime.run((call) => inputFlow.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(f.graph.reads.length, 0);
    assert.equal(f.rows.size, 0);
    const outputSettings = capture(
        { ...f.raw, policy: { ...f.raw.policy, maxOutputBytes: 256 } },
        'test',
      ),
      outputFlow = new FederationOidcLogin(
        outputSettings,
        f.profile.profileId,
        f.graph.http,
        f.crypto,
      );
    await assert.rejects(() => f.runtime.run((call) => outputFlow.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(
      f.rows.size,
      1,
      'A bounded failed response cannot release the protected transaction',
    );
  } finally {
    await f.close();
  }
});
