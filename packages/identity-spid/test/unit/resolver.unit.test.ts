// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from 'jose';
import { KitError } from '@arkenivajs/core';
import type { FederationProfileV1 } from '../../dist/index.js';
import type { FederationHttp } from '../../dist/metadata-http.js';
import { FederationRuntime } from '../../dist/runtime.js';
import { FederationResolver, configurationEndpoint } from '../../dist/resolver.js';
import { inspectConfiguration } from '../../dist/statements.js';

const root = 'https://anchor.example.test/federation',
  intermediate = 'https://authority.example.test',
  leaf = 'https://idp.example.test';
const pair = await generateKeyPair('ES256'),
  foreign = await generateKeyPair('ES256'),
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'federation-public' }] };
const now = () => Math.floor(Date.now() / 1000);
const sign = (issuer: string, subject: string, claims: Record<string, unknown> = {}) =>
  new SignJWT({ iss: issuer, sub: subject, iat: now() - 1, exp: now() + 300, jwks, ...claims })
    .setProtectedHeader({ alg: 'ES256', kid: 'federation-public', typ: 'entity-statement+jwt' })
    .sign(pair.privateKey);
const profile: FederationProfileV1 = {
  schemaVersion: '1.0.0',
  profileId: 'discovery-profile',
  system: 'spid',
  protocol: 'oidc-federation',
  entityId: 'https://service.example.test',
  clientId: 'https://service.example.test',
  redirectUri: 'https://service.example.test/callback',
  signingKeyRef: 'signing-ref',
  expectedIssuers: [leaf],
  allowedAssurance: ['spid-l2'],
  subjectClaim: 'sub',
  tenantMappingId: 'approved-accounts',
  identityMappingVersion: '1',
  sessionTtlSeconds: 300,
  metadata: {
    trustAnchors: [
      {
        issuer: root,
        kid: 'federation-public',
        publicKeyPem: await exportSPKI(pair.publicKey),
        validFrom: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
    ],
    approvedMetadataEndpoints: [
      configurationEndpoint(root),
      root + '/fetch',
      configurationEndpoint(intermediate),
      intermediate + '/fetch',
    ],
    maxBytes: 65536,
    refreshIntervalSeconds: 60,
    maxChainDepth: 4,
    revocation: 'mandatory',
    stalePolicy: 'reject',
  },
};
async function fixture(
  options: {
    root?: Record<string, unknown>;
    intermediate?: Record<string, unknown>;
    leaf?: Record<string, unknown>;
    lower?: Record<string, unknown>;
    upper?: Record<string, unknown>;
  } = {},
) {
  const leafToken = await sign(leaf, leaf, {
    authority_hints: [intermediate],
    metadata: { openid_provider: { issuer: leaf } },
    ...options.leaf,
  });
  const records = new Map([
    [
      configurationEndpoint(root),
      await sign(root, root, {
        constraints: { max_path_length: 1 },
        metadata: { federation_entity: { federation_fetch_endpoint: root + '/fetch' } },
        ...options.root,
      }),
    ],
    [
      configurationEndpoint(intermediate),
      await sign(intermediate, intermediate, {
        authority_hints: [root],
        metadata: { federation_entity: { federation_fetch_endpoint: intermediate + '/fetch' } },
        ...options.intermediate,
      }),
    ],
    [
      root + '/fetch?' + new URLSearchParams({ sub: intermediate }),
      await sign(root, intermediate, options.upper),
    ],
    [
      intermediate + '/fetch?' + new URLSearchParams({ sub: leaf }),
      await sign(intermediate, leaf, options.lower),
    ],
  ]);
  const calls: string[] = [];
  const http: Pick<FederationHttp, 'statement'> = {
    async statement(endpoint, subject, options) {
      assert.ok(options?.signal instanceof AbortSignal);
      assert.ok(options.timeoutMs! > 0 && options.timeoutMs! <= 5000);
      const key =
        endpoint + (subject === undefined ? '' : '?' + new URLSearchParams({ sub: subject }));
      calls.push(key);
      const result = records.get(key);
      if (!result) throw new Error('The approved fixture document is unavailable');
      return result;
    },
  };
  return { leafToken, records, calls, http };
}
test('Bounded discovery verifies actual signed documents and caches only within one operation', async () => {
  const f = await fixture(),
    resolver = new FederationResolver(profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  try {
    for (let index = 0; index < 2; index++) {
      const proof = await runtime.run((call) => resolver.resolve(call, f.leafToken));
      assert.equal(proof.subject, leaf);
      assert.equal(proof.anchor, root);
      assert.equal(resolver.nodes(proof).length, 3);
      assert.equal('trusted' in proof, false);
      assert.equal((proof.metadata.openid_provider as Record<string, unknown>).issuer, leaf);
    }
    assert.equal(f.calls.length, 8, 'A new call cannot silently reuse old metadata');
    f.records.set(
      intermediate + '/fetch?' + new URLSearchParams({ sub: leaf }),
      await sign(intermediate, leaf, { exp: now() - 1 }),
    );
    await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await runtime.close();
  }
});
test('Unapproved hints and fetch destinations cannot initiate network work', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  try {
    for (const options of [
      { leaf: { authority_hints: ['https://foreign.example.test'] } },
      { leaf: { authority_hints: [leaf] } },
      { leaf: { iss: 'https://foreign.example.test', sub: 'https://foreign.example.test' } },
      { leaf: { authority_hints: [intermediate, intermediate] } },
    ]) {
      const f = await fixture(options),
        resolver = new FederationResolver(profile, f.http);
      await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.calls.length, 0);
    }
    const f = await fixture({
        intermediate: {
          metadata: {
            federation_entity: { federation_fetch_endpoint: intermediate + '/unapproved' },
          },
        },
      }),
      resolver = new FederationResolver(profile, f.http);
    await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.deepEqual(f.calls, [configurationEndpoint(intermediate)]);
  } finally {
    await runtime.close();
  }
});
test('Tampered signatures, swapped configuration subjects, loops and inherited constraint failures yield no evidence', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  try {
    for (const options of [
      { root: { constraints: { max_path_length: 0 } } },
      { intermediate: { authority_hints: [leaf] } },
      { intermediate: { sub: leaf } },
      { lower: { iss: root } },
    ]) {
      const f = await fixture(options),
        resolver = new FederationResolver(profile, f.http);
      await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.ok(f.calls.length <= 4);
    }
    const f = await fixture(),
      resolver = new FederationResolver(profile, f.http);
    const tampered = await new SignJWT({ ...inspectConfiguration(f.leafToken, 65536).claims })
      .setProtectedHeader({ alg: 'ES256', kid: 'federation-public', typ: 'entity-statement+jwt' })
      .sign(foreign.privateKey);
    await assert.rejects(() => runtime.run((call) => resolver.resolve(call, tampered)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await runtime.close();
  }
});
test('Alternative approved paths verify in full while repeated hints do not repeat document fetches', async () => {
  const f = await fixture({
    leaf: { authority_hints: ['https://unapproved.example.test', intermediate, root] },
  });
  f.records.set(root + '/fetch?' + new URLSearchParams({ sub: leaf }), await sign(root, leaf));
  // The intermediary route is invalid; only the separately signed direct route is accepted.
  f.records.set(
    intermediate + '/fetch?' + new URLSearchParams({ sub: leaf }),
    await sign(intermediate, leaf, { exp: now() - 1 }),
  );
  const resolver = new FederationResolver(profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  try {
    const proof = await runtime.run((call) => resolver.resolve(call, f.leafToken));
    assert.equal(resolver.nodes(proof).length, 2);
    assert.equal(f.calls.filter((item) => item === configurationEndpoint(root)).length, 1);
    assert.equal(
      f.calls.some((item) => item.includes('unapproved')),
      false,
    );
  } finally {
    await runtime.close();
  }
});
test('Total document bytes and path depth stop discovery rather than yielding partial evidence', async () => {
  for (const metadata of [
    { ...profile.metadata, maxChainDepth: 1 },
    { ...profile.metadata, maxBytes: 1500 },
  ]) {
    const f = await fixture(),
      resolver = new FederationResolver({ ...profile, metadata }, f.http),
      runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
    try {
      await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.ok(f.calls.length <= 2);
    } finally {
      await runtime.close();
    }
  }
});
test('Timeout and cancellation cannot be hidden by a fallback path or release late provider capacity', async () => {
  const f = await fixture({ leaf: { authority_hints: [intermediate, root] } });
  for (const code of ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE'] as const) {
    let reads = 0;
    const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 1000 }),
      resolver = new FederationResolver(profile, {
        async statement() {
          reads++;
          throw new KitError({ code, message: 'Fixture backend unavailable' });
        },
      });
    try {
      await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
        code,
      });
      assert.equal(reads, 1);
    } finally {
      await runtime.close();
    }
  }
  let release!: () => void, entered!: () => void;
  const pending = new Promise<string>((resolve) => {
      release = () => resolve(f.records.get(configurationEndpoint(intermediate))!);
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 50 }),
    resolver = new FederationResolver(profile, {
      async statement() {
        entered();
        return pending;
      },
    });
  try {
    const work = runtime.run((call) => resolver.resolve(call, f.leafToken));
    await began;
    await assert.rejects(work, { code: 'EK_TIMEOUT' });
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
  } finally {
    release();
    await runtime.close();
  }
});
test('Unverified inspection is bounded data and well-known discovery preserves entity path', async () => {
  const f = await fixture();
  assert.equal(configurationEndpoint(root + '/'), root + '/.well-known/openid-federation');
  assert.throws(() => configurationEndpoint(root + '?caller=unsafe'), {
    code: 'EK_EID_FEDERATION',
  });
  const inspected = inspectConfiguration(f.leafToken, 65536);
  assert.equal(inspected.entity, leaf);
  assert.equal('keys' in inspected, false);
  assert.equal('trusted' in inspected, false);
  assert.ok(Object.isFrozen(inspected.claims));
  assert.throws(() => inspectConfiguration(f.leafToken, 10), { code: 'EK_EID_FEDERATION' });
  assert.throws(() => inspectConfiguration('invalid.jwt.encoding', 65536), {
    code: 'EK_EID_FEDERATION',
  });
});
test('The shared edge budget prevents combinatorial discovery from hiding behind a final fallback', async () => {
  const f = await fixture({
      leaf: { authority_hints: [intermediate, root] },
      intermediate: {
        authority_hints: Array.from(
          { length: 64 },
          (_, index) => `https://candidate-${index}.example.test`,
        ),
      },
    }),
    resolver = new FederationResolver(profile, f.http),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
  f.records.set(root + '/fetch?' + new URLSearchParams({ sub: leaf }), await sign(root, leaf));
  try {
    await assert.rejects(() => runtime.run((call) => resolver.resolve(call, f.leafToken)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(f.calls.length, 2);
    assert.equal(
      f.calls.some((item) => item.startsWith(root)),
      false,
    );
  } finally {
    await runtime.close();
  }
});
