// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from 'jose';
import type { FederationProfileV1 } from '../../dist/index.js';
import type { FederationPath, ChainEvidence } from '../../dist/chain.js';
import { FederationChainVerifier } from '../../dist/chain.js';
import { FederationRuntime } from '../../dist/runtime.js';

const rootId = 'https://anchor.example.test',
  intermediateId = 'https://authority.example.test',
  leafId = 'https://idp.example.test';
const keys = await Promise.all(Array.from({ length: 4 }, () => generateKeyPair('ES256')));
const jwks = await Promise.all(
  keys.map(async (pair, index) => ({
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'public-' + index }],
  })),
);
const now = () => Math.floor(Date.now() / 1000);
async function sign(
  issuer: string,
  subject: string,
  signing: number,
  published: number,
  claims: Record<string, unknown> = {},
) {
  return new SignJWT({
    iss: issuer,
    sub: subject,
    iat: now() - 1,
    exp: now() + 300,
    jwks: jwks[published],
    ...claims,
  })
    .setProtectedHeader({ typ: 'entity-statement+jwt', alg: 'ES256', kid: 'public-' + signing })
    .sign(keys[signing]!.privateKey);
}
const profile: FederationProfileV1 = {
  schemaVersion: '1.0.0',
  profileId: 'chain-profile',
  system: 'spid',
  protocol: 'oidc-federation',
  entityId: 'https://service.example.test',
  clientId: 'https://service.example.test',
  redirectUri: 'https://service.example.test/callback',
  signingKeyRef: 'signing-ref',
  expectedIssuers: [leafId],
  allowedAssurance: ['spid-l2'],
  metadata: {
    trustAnchors: [
      {
        issuer: rootId,
        kid: 'public-0',
        publicKeyPem: await exportSPKI(keys[0]!.publicKey),
        validFrom: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      },
    ],
    approvedMetadataEndpoints: ['https://anchor.example.test/fetch'],
    maxBytes: 65536,
    maxChainDepth: 4,
    refreshIntervalSeconds: 60,
    revocation: 'mandatory',
    stalePolicy: 'reject',
  },
  subjectClaim: 'sub',
  tenantMappingId: 'approved-accounts',
  identityMappingVersion: '1',
  sessionTtlSeconds: 300,
};
async function fixture(
  options: {
    root?: Record<string, unknown>;
    upper?: Record<string, unknown>;
    intermediate?: Record<string, unknown>;
    lower?: Record<string, unknown>;
    leaf?: Record<string, unknown>;
  } = {},
): Promise<FederationPath> {
  return {
    anchor: rootId,
    configuration: await sign(rootId, rootId, 0, 0, {
      constraints: { max_path_length: 4 },
      ...options.root,
    }),
    descendants: [
      {
        entity: intermediateId,
        statement: await sign(rootId, intermediateId, 0, 1, options.upper),
        configuration: await sign(intermediateId, intermediateId, 1, 1, {
          authority_hints: [rootId],
          metadata: { federation_entity: { organization_name: 'Authority' } },
          ...options.intermediate,
        }),
      },
      {
        entity: leafId,
        statement: await sign(intermediateId, leafId, 1, 2, options.lower),
        configuration: await sign(leafId, leafId, 2, 2, {
          authority_hints: [intermediateId],
          metadata: {
            federation_entity: {},
            openid_provider: { issuer: leafId, response_types_supported: ['code', 'token'] },
          },
          ...options.leaf,
        }),
      },
    ],
  };
}
async function using(
  work: (verify: (path: FederationPath) => Promise<ChainEvidence>) => Promise<void>,
  settings = profile,
) {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 }),
    verifier = new FederationChainVerifier(settings);
  try {
    await work((path) => runtime.run((call) => verifier.verify(call, path)));
  } finally {
    await runtime.close();
  }
}
test('Actual JOSE chains enforce inherited policy after direct-superior metadata and retain owned evidence', async () => {
  const path = await fixture({
    upper: {
      constraints: { max_path_length: 1, naming_constraints: { permitted: ['.example.test'] } },
      metadata: { openid_provider: { issuer: 'https://irrelevant.example.test' } },
      metadata_policy: {
        openid_provider: { response_types_supported: { subset_of: ['code'] } },
      },
    },
    lower: { metadata: { openid_provider: { authorization_endpoint: leafId + '/authorize' } } },
  });
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 }),
    verifier = new FederationChainVerifier(profile);
  try {
    const proof = await runtime.run((call) => verifier.verify(call, path));
    assert.equal(proof.subject, leafId);
    assert.equal(proof.anchor, rootId);
    assert.equal('trusted' in proof, false);
    assert.deepEqual(
      { ...(proof.metadata.openid_provider as object) },
      {
        issuer: leafId,
        response_types_supported: ['code'],
        authorization_endpoint: leafId + '/authorize',
      },
    );
    assert.ok(Object.isFrozen(proof.metadata));
    assert.equal(verifier.nodes(proof).length, 3);
    assert.ok(Object.isFrozen(verifier.nodes(proof)[1]));
    assert.throws(() => verifier.nodes({ ...proof }), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => new FederationChainVerifier(profile).nodes(proof), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await runtime.close();
  }
});
test('Pinned roots, parent delegation and current self-published keys are all required', async () => {
  const valid = await fixture();
  const changed = (index: number, value: Partial<FederationPath['descendants'][number]>) => ({
    ...valid,
    descendants: valid.descendants.map((item, current) =>
      current === index ? { ...item, ...value } : item,
    ),
  });
  const attacks = [
    { ...valid, anchor: 'https://unconfigured.example.test' },
    { ...valid, configuration: await sign(rootId, rootId, 3, 3) },
    changed(0, { statement: await sign(rootId, intermediateId, 3, 1) }),
    changed(0, {
      configuration: await sign(intermediateId, intermediateId, 3, 3, {
        authority_hints: [rootId],
      }),
    }),
    // The intermediate can publish another key, but cannot delegate using it without parent approval.
    changed(1, { statement: await sign(intermediateId, leafId, 3, 2) }),
    changed(1, {
      configuration: await sign(leafId, leafId, 3, 3, { authority_hints: [intermediateId] }),
    }),
    changed(0, {
      configuration: await sign(intermediateId, intermediateId, 1, 3, {
        authority_hints: [rootId],
      }),
    }),
  ];
  await using(async (verify) => {
    for (const attack of attacks)
      await assert.rejects(() => verify(attack), { code: 'EK_EID_FEDERATION' });
  });
});
test('Authority hints, path cycles, wrong subjects and profile issuer boundaries fail closed', async () => {
  const valid = await fixture();
  const paths = [
    await fixture({ leaf: { authority_hints: ['https://foreign.example.test'] } }),
    await fixture({ intermediate: { authority_hints: undefined } }),
    await fixture({ lower: { sub: rootId } }),
    await fixture({ upper: { authority_hints: [rootId] } }),
    { ...valid, descendants: [...valid.descendants, valid.descendants[0]!] },
    { ...valid, descendants: [valid.descendants[0]!] },
  ];
  await using(async (verify) => {
    for (const path of paths)
      await assert.rejects(() => verify(path), { code: 'EK_EID_FEDERATION' });
  });
});
test('Path length counts intermediates and every inherited naming constraint is independent', async () => {
  await using(async (verify) => {
    await verify(
      await fixture({
        upper: { constraints: { max_path_length: 1 } },
        lower: { constraints: { max_path_length: 0 } },
      }),
    );
    for (const options of [
      { root: { constraints: undefined } },
      { root: { constraints: {} } },
      { root: { constraints: { max_path_length: 0 } } },
      { upper: { constraints: { max_path_length: 0 } } },
      { upper: { constraints: { max_path_length: -1 } } },
      { lower: { constraints: { max_path_length: 1.5 } } },
      { upper: { constraints: { naming_constraints: { permitted: ['example.test'] } } } },
      {
        upper: {
          constraints: {
            naming_constraints: { permitted: ['.example.test'], excluded: ['idp.example.test'] },
          },
        },
      },
      { upper: { constraints: { naming_constraints: { permitted: ['.ample.test'] } } } },
      { lower: { constraints: { naming_constraints: { permitted: ['.idp.example.test'] } } } },
      { lower: { constraints: { naming_constraints: { permitted: [] } } } },
      {
        lower: { constraints: { naming_constraints: { excluded: ['https://idp.example.test'] } } },
      },
    ])
      await assert.rejects(() => fixture(options).then(verify), { code: 'EK_EID_FEDERATION' });
    await verify(
      await fixture({
        lower: { constraints: { naming_constraints: { permitted: ['IDP.EXAMPLE.TEST'] } } },
      }),
    );
  });
});
test('Approved root and intermediate rotations work while self-published key escalation fails', async () => {
  const valid = await fixture(),
    both = { keys: [...jwks[0]!.keys, ...jwks[3]!.keys] },
    rotatedProfile: FederationProfileV1 = {
      ...profile,
      metadata: {
        ...profile.metadata,
        trustAnchors: [
          ...profile.metadata.trustAnchors,
          {
            ...profile.metadata.trustAnchors[0]!,
            kid: 'public-3',
            publicKeyPem: await exportSPKI(keys[3]!.publicKey),
          },
        ],
      },
    },
    rotated: FederationPath = {
      ...valid,
      configuration: await sign(rootId, rootId, 0, 0, {
        jwks: both,
        constraints: { max_path_length: 4 },
      }),
      descendants: [
        {
          entity: intermediateId,
          statement: await sign(rootId, intermediateId, 3, 3),
          configuration: await sign(intermediateId, intermediateId, 3, 3, {
            authority_hints: [rootId],
          }),
        },
        { ...valid.descendants[1]!, statement: await sign(intermediateId, leafId, 3, 2) },
      ],
    };
  await using(async (verify) => {
    await verify(rotated);
  }, rotatedProfile);
  await using(async (verify) => {
    await assert.rejects(() => verify(rotated), { code: 'EK_EID_FEDERATION' });
  });
  const escalation: FederationPath = {
    ...valid,
    descendants: [
      {
        ...valid.descendants[0]!,
        configuration: await sign(intermediateId, intermediateId, 1, 1, {
          jwks: { keys: [...jwks[1]!.keys, ...jwks[3]!.keys] },
          authority_hints: [rootId],
        }),
      },
      { ...valid.descendants[1]!, statement: await sign(intermediateId, leafId, 3, 2) },
    ],
  };
  await using(async (verify) => {
    await assert.rejects(() => verify(escalation), { code: 'EK_EID_FEDERATION' });
  });
});
test('Italian leaf-role constraints do not constrain intermediary roles and cannot be weakened below', async () => {
  await using(async (verify) => {
    await verify(
      await fixture({
        root: {
          constraints: { max_path_length: 1, allowed_leaf_entity_types: ['openid_provider'] },
        },
      }),
    );
    await assert.rejects(
      () =>
        fixture({
          upper: { constraints: { allowed_leaf_entity_types: ['openid_relying_party'] } },
          lower: {
            constraints: { allowed_leaf_entity_types: ['openid_provider', 'openid_relying_party'] },
          },
        }).then(verify),
      { code: 'EK_EID_FEDERATION' },
    );
    await verify(await fixture({ upper: { constraints: { extension_not_critical: true } } }));
  });
});
test('Direct root-to-leaf delegation accepts a zero intermediary limit', async () => {
  const path: FederationPath = {
    anchor: rootId,
    configuration: await sign(rootId, rootId, 0, 0, { constraints: { max_path_length: 0 } }),
    descendants: [
      {
        entity: leafId,
        statement: await sign(rootId, leafId, 0, 2, { constraints: { max_path_length: 0 } }),
        configuration: await sign(leafId, leafId, 2, 2, { authority_hints: [rootId] }),
      },
    ],
  };
  await using(async (verify) => {
    assert.equal((await verify(path)).subject, leafId);
  });
});
test('Entity type constraints filter roles before policies and cannot create absent roles', async () => {
  const path = await fixture({
    upper: {
      constraints: { allowed_entity_types: [] },
      metadata_policy: {
        openid_provider: { issuer: { default: leafId }, required: { essential: true } },
      },
    },
    lower: { metadata: { openid_relying_party: { client_name: 'Unpublished role' } } },
  });
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 }),
    verifier = new FederationChainVerifier(profile);
  try {
    const proof = await runtime.run((call) => verifier.verify(call, path));
    assert.deepEqual(Object.keys(proof.metadata), ['federation_entity']);
    await assert.rejects(
      () =>
        runtime.run(async (call) =>
          verifier.verify(
            call,
            await fixture({
              upper: { constraints: { allowed_entity_types: ['federation_entity'] } },
            }),
          ),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await runtime.close();
  }
});
test('Chain expiry, bounds, critical extensions and inherited policy conflicts invalidate evidence', async () => {
  await using(async (verify) => {
    for (const options of [
      { lower: { exp: now() - 1 } },
      { leaf: { iat: now() + 100 } },
      { upper: { crit: ['custom'], custom: true } },
      { leaf: { crit: [] } },
      { upper: { metadata_policy_crit: ['regexp'] } },
      {
        upper: { metadata_policy: { openid_provider: { issuer: { value: 'one' } } } },
        lower: { metadata_policy: { openid_provider: { issuer: { value: 'two' } } } },
      },
    ])
      await assert.rejects(() => fixture(options).then(verify), { code: 'EK_EID_FEDERATION' });
  });
  for (const metadata of [
    { ...profile.metadata, maxChainDepth: 1 },
    { ...profile.metadata, maxBytes: 100 },
  ])
    await using(
      async (verify) => {
        await assert.rejects(() => fixture().then(verify), { code: 'EK_EID_FEDERATION' });
      },
      { ...profile, metadata },
    );
});
test('Inherited expiry bounds the entire proof and canceled calls produce no evidence', async () => {
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 }),
    verifier = new FederationChainVerifier(profile),
    expiry = now() + 120,
    path = await fixture({ upper: { exp: expiry } });
  try {
    const proof = await runtime.run((call) => verifier.verify(call, path));
    assert.equal(proof.expiresAt, expiry);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      () => runtime.run((call) => verifier.verify(call, path), { signal: controller.signal }),
      { code: 'EK_ABORTED' },
    );
    let effects = 0;
    await assert.rejects(
      () =>
        runtime.run((call) =>
          verifier.verify(call, {
            ...path,
            get descendants() {
              effects++;
              return path.descendants;
            },
          }),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(effects, 0);
  } finally {
    await runtime.close();
  }
});
