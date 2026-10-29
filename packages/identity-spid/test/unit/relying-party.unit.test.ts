// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { exportJWK, calculateJwkThumbprint } from 'jose';
import { FederationRelyingParty } from '../../dist/relying-party.js';
import { capture } from '../../dist/settings.js';
import { membershipFixture, root, sa, types, mark, statement } from '../fixtures/membership.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { registration } from '../fixtures/registration.js';

const signing = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  encryption = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  rpType = root + '/openid_relying_party/public/';
async function fixture(
  options: {
    status?: Record<string, unknown>;
    catalog?: Record<string, unknown>;
    statement?: Record<string, unknown>;
    marks?: readonly string[];
  } = {},
) {
  const f = await transactionFixture(),
    graph = await membershipFixture({
      catalog: options.catalog ?? {
        [rpType]: [root],
        [types.op]: [sa],
        [types.sa]: [root],
        [types.aa]: [root],
      },
      ...(options.status ? { status: options.status } : {}),
    }),
    candidate = await registration(f.profile.entityId),
    profile = {
      ...graph.profile,
      oidcRegistration: {
        ...candidate,
        trustMarks: options.marks ?? [await mark(root, f.profile.entityId, 0, rpType)],
      },
    },
    raw = { ...f.settings, profiles: [profile] },
    settings = capture(raw, 'test'),
    jwk = await exportJWK(signing.publicKey),
    signingJwk = { ...jwk, kid: await calculateJwkThumbprint(jwk), use: 'sig', alg: 'RS256' },
    enc = await exportJWK(encryption.publicKey),
    encryptionJwk = { ...enc, kid: await calculateJwkThumbprint(enc), use: 'enc' };
  f.material.set('signing-ref', {
    bytes: Buffer.from(signing.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  f.material.set(candidate.decryptionKeyRef, {
    bytes: Buffer.from(encryption.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  graph.records.set(
    root + '/fetch?' + new URLSearchParams({ sub: profile.entityId }),
    await statement(root, profile.entityId, 0, 0, {
      jwks: { keys: [signingJwk] },
      ...options.statement,
    }),
  );
  return {
    ...f,
    graph,
    raw,
    profile,
    settings,
    signingJwk,
    encryptionJwk,
    rp: new FederationRelyingParty(settings, profile.profileId, graph.http),
  };
}
test('Actual root-delegated RP keys and current authorized role marks produce only owned live participation evidence', async (t) => {
  const f = await fixture();
  try {
    const proof = await f.runtime.run((call) => f.rp.verify(call));
    f.rp.check(proof);
    assert.equal(proof.entityId, f.profile.entityId);
    assert.ok(Date.parse(proof.expiresAt) <= Date.now() + 30000);
    assert.deepEqual(
      f.graph.statuses.map((item) => item.endpoint),
      [root + '/status'],
    );
    assert.equal('trusted' in proof, false);
    assert.throws(() => f.rp.check({ ...proof }), { code: 'EK_EID_FEDERATION' });
    assert.throws(
      () => new FederationRelyingParty(f.settings, f.profile.profileId, f.graph.http).check(proof),
      { code: 'EK_EID_FEDERATION' },
    );
    await f.runtime.run((call) => f.rp.verify(call));
    assert.equal(f.graph.statuses.length, 2);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(40000);
    assert.throws(() => f.rp.check(proof), { code: 'EK_EID_FEDERATION' });
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('Wrong RP signatures, unauthorized mark issuers and OP-only accreditation cannot establish RP membership', async () => {
  const entity = 'https://service.example.test',
    wrong = await mark(root, entity, 4, rpType),
    opMark = await mark(root, entity, 0, root + '/openid_provider/public/');
  for (const options of [
    { marks: [wrong] },
    { marks: [wrong, opMark] },
    { catalog: { [rpType]: [sa] } },
  ]) {
    const f = await fixture(options);
    try {
      await assert.rejects(() => f.runtime.run((call) => f.rp.verify(call)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.graph.statuses.length, 0);
    } finally {
      await f.close();
    }
  }
});
test('Revoked, stale and unknown RP status fail closed despite valid registration signatures', async () => {
  for (const status of [
    { status: 'revoked' },
    { status: 'unknown' },
    { iat: Math.floor(Date.now() / 1000) - 100 },
  ]) {
    const f = await fixture({ status });
    try {
      await assert.rejects(() => f.runtime.run((call) => f.rp.verify(call)), {
        code: 'EK_EID_FEDERATION',
      });
    } finally {
      await f.close();
    }
  }
});
test('Resolved RP security parameters cannot silently replace captured client, redirect, grant or algorithm policy', async () => {
  for (const override of [
    { client_id: 'https://foreign.example.test' },
    { redirect_uris: ['https://foreign.example.test/callback'] },
    { token_endpoint_auth_method: 'client_secret_basic' },
    { request_object_signing_alg: 'none' },
    { id_token_signed_response_alg: 'RS256' },
    { userinfo_encrypted_response_alg: 'RSA1_5' },
    { grant_types: ['refresh_token'] },
  ]) {
    const f = await fixture({ statement: { metadata: { openid_relying_party: override } } });
    try {
      await assert.rejects(() => f.runtime.run((call) => f.rp.verify(call)), {
        code: 'EK_EID_FEDERATION',
      });
    } finally {
      await f.close();
    }
  }
  const f = await fixture({
    statement: {
      metadata_policy: {
        openid_relying_party: {
          redirect_uris: { value: ['https://foreign.example.test/callback'] },
        },
      },
    },
  });
  try {
    await assert.rejects(() => f.runtime.run((call) => f.rp.verify(call)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await f.close();
  }
});
test('Benign informational metadata and JWK order changes preserve the same approved registration', async () => {
  const f = await fixture();
  try {
    f.graph.records.set(
      root + '/fetch?' + new URLSearchParams({ sub: f.profile.entityId }),
      await statement(root, f.profile.entityId, 0, 0, {
        jwks: { keys: [f.signingJwk] },
        metadata: {
          federation_entity: { organization_name: 'Federation Display Name' },
          openid_relying_party: { jwks: { keys: [f.encryptionJwk, f.signingJwk] } },
        },
      }),
    );
    const proof = await f.runtime.run((call) => f.rp.verify(call));
    f.rp.check(proof);
  } finally {
    await f.close();
  }
});
test('Late RP status work retains admission and missing registration never synthesizes accreditation', async () => {
  const f = await fixture();
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  try {
    const rp = new FederationRelyingParty(f.settings, f.profile.profileId, {
        ...f.graph.http,
        async trustMarkStatus(endpoint, token, options) {
          entered();
          await pending;
          return f.graph.http.trustMarkStatus(endpoint, token, options);
        },
      }),
      work = f.runtime.run((call) => rp.verify(call), { timeoutMs: 200 }),
      rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    await rejected;
    assert.equal(f.runtime.stats().active, 1);
    assert.throws(
      () =>
        new FederationRelyingParty(
          capture({ ...f.raw, profiles: [f.graph.profile] }, 'test'),
          f.profile.profileId,
          f.graph.http,
        ),
      { code: 'EK_EID_PROFILE' },
    );
  } finally {
    release();
    await f.close();
  }
});
