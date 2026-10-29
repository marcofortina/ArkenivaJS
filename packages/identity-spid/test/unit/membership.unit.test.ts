// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { exportSPKI } from 'jose';
import { KitError } from '@arkenivajs/core';
import { FederationMembership } from '../../dist/membership.js';
import { FederationRuntime } from '../../dist/runtime.js';
import { configurationEndpoint } from '../../dist/resolver.js';
import { inspectTrustMark } from '../../dist/statements.js';
import {
  membershipFixture as fixture,
  root,
  sa,
  op,
  aa,
  types,
  pairs,
  now,
  statement,
  mark,
  entry,
} from '../fixtures/membership.js';

test('Live participation verifies every intermediary and the provider with exact fresh role-bound status', async () => {
  const f = await fixture(),
    membership = new FederationMembership(f.profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    const proof = await runtime.run((call) => membership.verify(call, f.leafConfiguration));
    assert.equal(proof.subject, op);
    assert.equal(proof.anchor, root);
    assert.equal(membership.nodes(proof).length, 3);
    assert.ok(proof.expiresAt <= now() + 30);
    assert.deepEqual(
      f.statuses.map((request) => request.endpoint),
      [root + '/status', sa + '/status'],
    );
    assert.deepEqual(
      f.statuses.map((request) => request.token),
      [f.saMark, f.opMark],
    );
    assert.throws(() => membership.nodes({ ...proof }), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => new FederationMembership(f.profile, f.http).nodes(proof), {
      code: 'EK_EID_FEDERATION',
    });
    await runtime.run((call) => membership.verify(call, f.leafConfiguration));
    assert.equal(f.statuses.length, 4, 'Every new verification repeats live status checks');
  } finally {
    await runtime.close();
  }
});
test('An authorized external mark issuer requires its own same-anchor chain and live membership', async () => {
  for (const permitted of [[aa], []]) {
    const f = await fixture({
        issuer: aa,
        signer: 3,
        catalog: { [types.sa]: [root], [types.op]: permitted, [types.aa]: [root] },
      }),
      membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      const proof = await runtime.run((call) => membership.verify(call, f.leafConfiguration));
      assert.equal(proof.subject, op);
      assert.ok(f.reads.includes(configurationEndpoint(aa)));
      assert.deepEqual(
        f.statuses.map((request) => request.endpoint),
        [root + '/status', root + '/status', aa + '/status'],
      );
    } finally {
      await runtime.close();
    }
  }
});
test('An AA mark cannot replace the required OP mark or an aggregator accreditation', async () => {
  const foreign = await mark(root, op, 0, types.aa);
  for (const options of [
    { op: { trust_marks: [entry(types.aa, foreign)] } },
    { op: { trust_marks: [] } },
    { sa: { trust_marks: [] } },
    { op: { trust_marks: [entry(types.op, foreign)] } },
    { opMark: { id: types.aa } },
    { opMark: { sub: sa } },
    { opMark: { id: undefined } },
  ]) {
    const f = await fixture(options),
      membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await runtime.close();
    }
  }
});
test('Only the selected signed anchor can authorize the exact issuer/type pair', async () => {
  for (const options of [
    { catalog: { [types.sa]: [root], [types.op]: [root] } },
    { catalog: { [types.sa]: [root] } },
    { signer: 4 },
    { opMark: { crit: ['approval'], approval: true } },
    { opMark: { delegation: 'unverified-extension' } },
    { opMark: { trust_mark_type: types.op } },
    { saMark: { exp: now() - 1 } },
    { root: { trust_mark_issuers: undefined } },
  ]) {
    const f = await fixture(options),
      membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await runtime.close();
    }
  }
});
test('Revoked, unknown, stale, mismatched and boolean status never produce participation evidence', async () => {
  for (const status of [
    { status: 'revoked' },
    { status: 'invalid' },
    { status: 'expired' },
    { status: 'unknown' },
    { status: true },
    { crit: ['custom_status'], custom_status: true },
    { iat: now() - 100 },
    { trust_mark: 'another-public-mark' },
    { iss: aa },
  ]) {
    const f = await fixture({ status }),
      membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await runtime.close();
    }
  }
});
test('Self-referential accreditation and external issuer failures cannot bootstrap trust', async () => {
  const self = await mark(sa, sa, 1, types.sa);
  for (const options of [
    {
      sa: { trust_marks: [entry(types.sa, self)] },
      catalog: { [types.sa]: [sa], [types.op]: [sa] },
    },
    {
      issuer: aa,
      signer: 3,
      catalog: { [types.sa]: [root], [types.op]: [aa], [types.aa]: [root] },
    },
  ]) {
    const f = await fixture(options);
    if (options.issuer) f.records.delete(configurationEndpoint(aa));
    const membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await runtime.close();
    }
  }
});
test('Status endpoints come from authenticated issuer configuration and still require exact endpoint approval', async () => {
  const f = await fixture({
      sa: {
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: sa + '/fetch',
            federation_trust_mark_status_endpoint: sa + '/unapproved',
          },
        },
      },
    }),
    membership = new FederationMembership(f.profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.deepEqual(
      f.statuses.map((request) => request.endpoint),
      [root + '/status'],
    );
  } finally {
    await runtime.close();
  }
});
test('Provider errors, total byte exhaustion and cancellation preserve fail-closed behavior', async () => {
  const f = await fixture();
  for (const code of ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE'] as const) {
    const membership = new FederationMembership(f.profile, {
        ...f.http,
        async trustMarkStatus() {
          throw new KitError({ code, message: 'The fixture status service is unavailable' });
        },
      }),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code },
      );
    } finally {
      await runtime.close();
    }
  }
  const profile = {
      ...f.profile,
      metadata: { ...f.profile.metadata, maxBytes: Buffer.byteLength(f.leafConfiguration) + 1 },
    },
    membership = new FederationMembership(profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await runtime.close();
  }
});
test('Final and Italian mark type names remain unambiguous within role and issuer authorization', async () => {
  const finalMark = await mark(sa, op, 1, types.op, { id: undefined, trust_mark_type: types.op }),
    f = await fixture({
      op: { trust_marks: [{ trust_mark_type: types.op, trust_mark: finalMark }] },
    }),
    membership = new FederationMembership(f.profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    assert.equal(inspectTrustMark(finalMark, 65536).type, types.op);
    assert.equal(
      (await runtime.run((call) => membership.verify(call, f.leafConfiguration))).subject,
      op,
    );
  } finally {
    await runtime.close();
  }
});
test('The Italian role prefix remains exact when the optional mark profile suffix is absent', async () => {
  const type = root + '/openid_provider/',
    token = await mark(sa, op, 1, type),
    f = await fixture({
      catalog: { [types.sa]: [root], [type]: [sa] },
      op: { trust_marks: [entry(type, token)] },
    }),
    membership = new FederationMembership(f.profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    assert.equal(
      (await runtime.run((call) => membership.verify(call, f.leafConfiguration))).subject,
      op,
    );
  } finally {
    await runtime.close();
  }
});
test('Another configured federation cannot authorize an external issuer for the selected anchor', async () => {
  const otherRoot = 'https://other-federation.example.test',
    f = await fixture({
      issuer: aa,
      signer: 3,
      catalog: { [types.sa]: [root], [types.op]: [aa], [types.aa]: [root] },
    });
  f.records.set(
    configurationEndpoint(aa),
    await statement(aa, aa, 3, 3, {
      authority_hints: [otherRoot],
      metadata: {
        oauth_resource: {},
        federation_entity: { federation_trust_mark_status_endpoint: aa + '/status' },
      },
      trust_marks: [entry(types.aa, f.aaMark)],
    }),
  );
  f.records.set(
    configurationEndpoint(otherRoot),
    await statement(otherRoot, otherRoot, 4, 4, {
      constraints: { max_path_length: 0 },
      metadata: { federation_entity: { federation_fetch_endpoint: otherRoot + '/fetch' } },
    }),
  );
  f.records.set(
    otherRoot + '/fetch?' + new URLSearchParams({ sub: aa }),
    await statement(otherRoot, aa, 4, 3),
  );
  const profile = {
      ...f.profile,
      metadata: {
        ...f.profile.metadata,
        trustAnchors: [
          ...f.profile.metadata.trustAnchors,
          {
            ...f.profile.metadata.trustAnchors[0]!,
            issuer: otherRoot,
            kid: 'public-4',
            publicKeyPem: await exportSPKI(pairs[4]!.publicKey),
          },
        ],
        approvedMetadataEndpoints: [
          ...f.profile.metadata.approvedMetadataEndpoints,
          configurationEndpoint(otherRoot),
          otherRoot + '/fetch',
        ],
      },
    },
    membership = new FederationMembership(profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(
      f.statuses.some((request) => request.endpoint === aa + '/status'),
      false,
    );
  } finally {
    await runtime.close();
  }
});
test('Owned participation expires no later than its signed live status freshness', async (t) => {
  const f = await fixture(),
    membership = new FederationMembership(f.profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 25000 });
  try {
    const proof = await runtime.run((call) => membership.verify(call, f.leafConfiguration));
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(40000);
    assert.throws(() => membership.nodes(proof), { code: 'EK_EID_FEDERATION' });
  } finally {
    t.mock.timers.reset();
    await runtime.close();
  }
});
test('A timed-out live status provider retains physical admission until its work settles', async () => {
  const f = await fixture();
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 250 }),
    membership = new FederationMembership(f.profile, {
      ...f.http,
      async trustMarkStatus(endpoint, token, options) {
        await pending;
        return f.http.trustMarkStatus(endpoint, token, options);
      },
    });
  try {
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_TIMEOUT' },
    );
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_BACKEND_UNAVAILABLE' },
    );
  } finally {
    release();
    await runtime.close();
  }
});

test('Malformed signed mark catalogs and missing OP role cannot establish participation', async () => {
  const wrongRole = await mark(sa, op, 1, root + '/not_an_italian_role/public/');
  for (const options of [
    { op: { trust_marks: [{ id: types.op, trust_mark_type: types.op, trust_mark: 'ambiguous' }] } },
    { op: { trust_marks: [{ id: types.op, trust_mark: 17 }] } },
    { op: { trust_marks: [entry(root + '/not_an_italian_role/public/', wrongRole)] } },
    { catalog: { [types.sa]: [root], [types.op]: [sa, sa] } },
    { op: { metadata: { federation_entity: {} } } },
  ]) {
    const f = await fixture(options),
      membership = new FederationMembership(f.profile, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
    try {
      await assert.rejects(
        () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await runtime.close();
    }
  }
});

test('A non-string live status response cannot become trust evidence or evade the cumulative byte budget', async () => {
  const f = await fixture(),
    membership = new FederationMembership(f.profile, {
      ...f.http,
      async trustMarkStatus() {
        return undefined as unknown as string;
      },
    }),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  try {
    await assert.rejects(
      () => runtime.run((call) => membership.verify(call, f.leafConfiguration)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.statuses.length, 0);
  } finally {
    await runtime.close();
  }
});
