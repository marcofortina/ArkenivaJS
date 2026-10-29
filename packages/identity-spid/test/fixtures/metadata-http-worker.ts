// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import type { OperationOptions } from '@arkenivajs/core';
import type { FederationTrustAnchor, FederationProfileV1 } from '../../dist/index.js';
import { FederationHttp } from '../../dist/metadata-http.js';
import { anchorKeys, verifyStatement } from '../../dist/statements.js';
import { TrustMarkVerifier } from '../../dist/trust-marks.js';
import { FederationResolver } from '../../dist/resolver.js';
import { FederationRuntime } from '../../dist/runtime.js';
import { FederationMembership } from '../../dist/membership.js';
import { verifySamlMetadataSignature } from '../../dist/saml-metadata-signature.js';
import { FederationSamlSignatures } from '../../dist/saml-signatures.js';
import { FederationSamlRegistry } from '../../dist/saml-registry.js';

interface Input {
  origin: string;
  issuer: string;
  subject: string;
  trustMark: string;
  anchor: FederationTrustAnchor;
  leafConfiguration: string;
  deniedConfiguration: string;
  membershipConfiguration: string;
  samlMetadata: string;
  registryStatus: string;
}
process.once('message', (input: Input) => {
  void run(input).then(
    () => {
      process.send?.({ ok: true });
      process.disconnect();
    },
    (error: unknown) => {
      process.send?.({
        ok: false,
        message: error instanceof Error ? error.message : 'Metadata fixture failed',
      });
      process.disconnect();
    },
  );
});
async function run(input: Input) {
  const paths = [
    '/statement',
    '/fetch',
    '/status',
    '/redirect',
    '/wrong-type',
    '/missing-type',
    '/empty',
    '/utf8',
    '/oversized',
    '/slow',
    '/cancel',
    '/saml/metadata',
    '/saml/application-xml',
    '/saml/text-xml',
    '/saml/withdrawn',
    '/saml/empty',
    '/saml/utf8',
    '/saml/oversized',
    '/saml/tampered',
    '/saml/slow',
    '/saml/cancel',
    '/saml/cache',
    '/registry/status',
    '/registry/disabled',
    '/registry/withdrawn',
    '/registry/empty',
    '/registry/utf8',
    '/registry/oversized',
    '/registry/slow',
    '/registry/cancel',
    '/registry/cache',
    '/registry/wrong-type',
    '/registry/missing-type',
    '/registry/application-status',
    '/saml/application-metadata',
  ];
  const metadata = {
    approvedMetadataEndpoints: paths.map((path) => input.origin + path),
    maxBytes: 4096,
  };
  const policy = { maxConcurrent: 2, timeoutMs: 1000, maxInputBytes: 4096, maxOutputBytes: 4096 };
  const source = new FederationHttp(metadata, policy, 'test');
  try {
    assert.equal(
      await source.samlRegistryStatus(input.origin + '/registry/status'),
      input.registryStatus,
    );
    const disabled = await source.samlRegistryStatus(input.origin + '/registry/disabled');
    assert.equal(JSON.parse(disabled)._disabled, 'Y');
    assert.equal('trusted' in JSON.parse(disabled), false);
    for (const path of [
      '/registry/withdrawn',
      '/registry/empty',
      '/registry/utf8',
      '/registry/oversized',
      '/redirect',
      '/registry/wrong-type',
      '/registry/missing-type',
      '/not-approved',
      '/registry/status?unapproved=yes',
    ])
      await assert.rejects(() => source.samlRegistryStatus(input.origin + path), {
        code: 'EK_EID_FEDERATION',
      });
    assert.equal(
      await source.samlRegistryStatus(input.origin + '/registry/cache'),
      input.registryStatus,
    );
    await assert.rejects(() => source.samlRegistryStatus(input.origin + '/registry/cache'), {
      code: 'EK_EID_FEDERATION',
    });
    await assert.rejects(
      () => source.samlRegistryStatus(input.origin + '/registry/slow', { timeoutMs: 40 }),
      { code: 'EK_TIMEOUT' },
    );
    await assert.rejects(
      () =>
        source.samlRegistryStatus(input.origin + '/registry/cancel', {
          signal: AbortSignal.abort(),
        }),
      { code: 'EK_ABORTED' },
    );
    const registryCapacity = new FederationHttp(metadata, { ...policy, maxConcurrent: 1 }, 'test');
    try {
      const active = registryCapacity.samlRegistryStatus(input.origin + '/registry/slow');
      await assert.rejects(() => registryCapacity.samlMetadata(input.origin + '/saml/metadata'), {
        code: 'EK_BACKEND_UNAVAILABLE',
      });
      assert.equal(await active, input.registryStatus);
      assert.equal(registryCapacity.stats().active, 0);
    } finally {
      await registryCapacity.close();
    }
    await assert.rejects(
      () => registryCapacity.samlRegistryStatus(input.origin + '/registry/status'),
      {
        code: 'EK_RESOURCE_CLOSED',
      },
    );
    const samlProfile: FederationProfileV1 = {
      schemaVersion: '1.0.0',
      profileId: 'native-saml-transport',
      system: 'spid',
      protocol: 'saml2',
      entityId: input.origin + '/application',
      redirectUri: input.origin + '/application/acs',
      signingKeyRef: 'signing-ref',
      expectedIssuers: [input.subject],
      allowedAssurance: ['spid-l2'],
      subjectClaim: 'NameID',
      tenantMappingId: 'approved-accounts',
      identityMappingVersion: '1',
      sessionTtlSeconds: 300,
      metadata: {
        ...metadata,
        trustAnchors: [input.anchor],
        refreshIntervalSeconds: 60,
        maxChainDepth: 2,
        revocation: 'mandatory',
        stalePolicy: 'reject',
      },
    };
    const signatures = new FederationSamlSignatures(samlProfile),
      signatureRuntime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
    try {
      for (const path of ['/saml/metadata', '/saml/application-xml', '/saml/text-xml']) {
        const evidence = await signatureRuntime.run(async (call) => {
          const xml = await call.step((options) =>
            source.samlMetadata(input.origin + path, options),
          );
          assert.equal(xml, input.samlMetadata);
          return signatures.verify(call, xml, 'idp');
        });
        assert.equal(signatures.result(evidence).issuer, input.subject);
        assert.equal('trusted' in evidence, false);
      }
    } finally {
      await signatureRuntime.close();
    }
    const registryProfile: FederationProfileV1 = {
        ...samlProfile,
        samlRegistration: {
          signingCertificateRef: 'application-certificate',
          registrySources: {
            [samlProfile.entityId]: {
              metadataEndpoint: input.origin + '/saml/application-metadata',
              statusEndpoint: input.origin + '/registry/application-status',
            },
            [input.subject]: {
              metadataEndpoint: input.origin + '/saml/metadata',
              statusEndpoint: input.origin + '/registry/status',
            },
          },
        },
        metadata: {
          ...samlProfile.metadata,
          maxBytes: 8192,
          trustAnchors: [{ ...input.anchor, issuer: input.origin }],
        },
      },
      registry = new FederationSamlRegistry(registryProfile, source),
      registryRuntime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 5000 });
    try {
      const evidence = await registryRuntime.run((call) =>
        registry.verify(call, input.subject, 'idp'),
      );
      assert.equal(registry.result(evidence).issuer, input.subject);
      assert.equal(evidence.certificates.length, 1);
      assert.equal('trusted' in evidence, false);
    } finally {
      await registryRuntime.close();
    }
    for (const path of [
      '/saml/withdrawn',
      '/saml/empty',
      '/saml/utf8',
      '/saml/oversized',
      '/redirect',
      '/wrong-type',
      '/missing-type',
      '/statement',
    ])
      await assert.rejects(() => source.samlMetadata(input.origin + path), {
        code: 'EK_EID_FEDERATION',
      });
    const tampered = await source.samlMetadata(input.origin + '/saml/tampered');
    assert.throws(() => verifySamlMetadataSignature(tampered, samlProfile, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(await source.samlMetadata(input.origin + '/saml/cache'), input.samlMetadata);
    await assert.rejects(() => source.samlMetadata(input.origin + '/saml/cache'), {
      code: 'EK_EID_FEDERATION',
    });
    for (const path of ['/not-approved', '/saml/metadata?unapproved=yes'])
      await assert.rejects(() => source.samlMetadata(input.origin + path), {
        code: 'EK_EID_FEDERATION',
      });
    await assert.rejects(
      () => source.samlMetadata(input.origin + '/saml/slow', { timeoutMs: 40 }),
      { code: 'EK_TIMEOUT' },
    );
    await assert.rejects(
      () => source.samlMetadata(input.origin + '/saml/cancel', { signal: AbortSignal.abort() }),
      { code: 'EK_ABORTED' },
    );
    const shared = new FederationHttp(metadata, { ...policy, maxConcurrent: 1 }, 'test');
    try {
      const active = shared.samlMetadata(input.origin + '/saml/slow');
      await assert.rejects(() => shared.statement(input.origin + '/statement'), {
        code: 'EK_BACKEND_UNAVAILABLE',
      });
      assert.equal(await active, input.samlMetadata);
      assert.equal(shared.stats().active, 0);
    } finally {
      await shared.close();
    }
    const keys = anchorKeys([input.anchor], input.issuer);
    const encoded = await source.statement(input.origin + '/statement');
    assert.equal(
      (
        await verifyStatement(encoded, {
          issuer: input.issuer,
          subject: input.subject,
          keys,
          maxBytes: 4096,
        })
      ).subject,
      input.subject,
    );
    assert.equal(await source.statement(input.origin + '/fetch', input.subject), encoded);
    const marks = new TrustMarkVerifier();
    const owned = await marks.verify(input.trustMark, {
      issuer: input.issuer,
      subject: input.subject,
      type: input.issuer + '/openid_provider',
      keys,
      maxBytes: 4096,
    });
    const status = await source.trustMarkStatus(input.origin + '/status', marks.request(owned));
    await marks.verifyStatus(status, owned, 30);
    await assert.rejects(() => source.trustMarkStatus(input.origin + '/status', encoded), {
      code: 'EK_EID_FEDERATION',
    });
    await assert.rejects(
      () => source.trustMarkStatus(input.origin + '/wrong-type', input.trustMark),
      { code: 'EK_EID_FEDERATION' },
    );
    for (const path of [
      '/redirect',
      '/wrong-type',
      '/missing-type',
      '/empty',
      '/utf8',
      '/oversized',
    ])
      await assert.rejects(() => source.statement(input.origin + path), {
        code: 'EK_EID_FEDERATION',
      });
    const tiny = new FederationHttp(metadata, { ...policy, maxInputBytes: 1 }, 'test'),
      formBound = new FederationHttp(
        metadata,
        { ...policy, maxInputBytes: Buffer.byteLength(input.trustMark) + 1 },
        'test',
      ),
      fixedSubject = new FederationHttp(
        { ...metadata, approvedMetadataEndpoints: [input.origin + '/fetch?sub=approved'] },
        policy,
        'test',
      );
    try {
      await assert.rejects(() => tiny.statement(input.origin + '/statement'), {
        code: 'EK_EID_FEDERATION',
      });
      await assert.rejects(
        () => formBound.trustMarkStatus(input.origin + '/status', input.trustMark),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () => fixedSubject.statement(input.origin + '/fetch?sub=approved', input.subject),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await tiny.close();
      await formBound.close();
      await fixedSubject.close();
    }
    await assert.rejects(() => source.statement(input.origin + '/not-approved'), {
      code: 'EK_EID_FEDERATION',
    });
    await assert.rejects(
      () =>
        source.statement(input.origin + '/statement', undefined, {
          method: 'DELETE',
        } as OperationOptions),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(
      () => source.statement(input.origin + '/slow', undefined, { timeoutMs: 40 }),
      { code: 'EK_TIMEOUT' },
    );
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      () => source.statement(input.origin + '/cancel', undefined, { signal: controller.signal }),
      { code: 'EK_ABORTED' },
    );
    for (const environment of ['production', 'development'] as const) {
      const denied = new FederationHttp(metadata, policy, environment);
      try {
        await assert.rejects(() => denied.statement(input.origin + '/statement'), {
          code: 'EK_EID_FEDERATION',
        });
      } finally {
        await denied.close();
      }
    }
    assert.equal(source.stats().active, 0);
    const bounded = new FederationHttp(metadata, { ...policy, maxConcurrent: 1 }, 'test');
    try {
      const first = bounded.statement(input.origin + '/slow');
      assert.equal(bounded.stats().active, 1);
      await assert.rejects(() => bounded.statement(input.origin + '/statement'), {
        code: 'EK_BACKEND_UNAVAILABLE',
      });
      assert.equal(await first, encoded);
      assert.equal(bounded.stats().active, 0);
    } finally {
      await bounded.close();
    }
    const federationRoot = input.origin + '/federation-root',
      federationLeaf = input.origin + '/federation-leaf';
    const profile: FederationProfileV1 = {
      schemaVersion: '1.0.0',
      profileId: 'native-discovery',
      system: 'spid',
      protocol: 'oidc-federation',
      entityId: input.origin + '/service',
      clientId: input.origin + '/service',
      redirectUri: input.origin + '/service/callback',
      signingKeyRef: 'signing-ref',
      expectedIssuers: [federationLeaf],
      allowedAssurance: ['spid-l2'],
      subjectClaim: 'sub',
      tenantMappingId: 'approved-accounts',
      identityMappingVersion: '1',
      sessionTtlSeconds: 300,
      metadata: {
        trustAnchors: [{ ...input.anchor, issuer: federationRoot }],
        approvedMetadataEndpoints: [
          federationRoot + '/.well-known/openid-federation',
          federationRoot + '/fetch',
          federationRoot + '/status',
        ],
        maxBytes: 16384,
        maxChainDepth: 2,
        refreshIntervalSeconds: 60,
        revocation: 'mandatory',
        stalePolicy: 'reject',
      },
    };
    const transport = new FederationHttp(
        profile.metadata,
        { ...policy, maxInputBytes: 16384, maxOutputBytes: 16384 },
        'test',
      ),
      runtime = new FederationRuntime(policy),
      resolver = new FederationResolver(profile, transport);
    try {
      const proof = await runtime.run((call) => resolver.resolve(call, input.leafConfiguration));
      assert.equal(proof.anchor, federationRoot);
      assert.equal(proof.subject, federationLeaf);
      assert.equal(resolver.nodes(proof).length, 2);
      assert.equal('trusted' in proof, false);
      await assert.rejects(
        () => runtime.run((call) => resolver.resolve(call, input.deniedConfiguration)),
        { code: 'EK_EID_FEDERATION' },
      );
      const membership = new FederationMembership(profile, transport),
        accepted = await runtime.run((call) =>
          membership.verify(call, input.membershipConfiguration),
        );
      assert.equal(accepted.subject, federationLeaf);
      assert.equal(membership.nodes(accepted).length, 2);
      assert.ok(accepted.expiresAt <= Date.now() / 1000 + 60);
    } finally {
      await runtime.close();
      await transport.close();
    }
    await source.close();
    await assert.rejects(() => source.samlMetadata(input.origin + '/saml/metadata'), {
      code: 'EK_RESOURCE_CLOSED',
    });
    await assert.rejects(() => source.statement(input.origin + '/statement'), {
      code: 'EK_RESOURCE_CLOSED',
    });
    assert.equal(source.stats().active, 0);
  } finally {
    await source.close();
    await source.close();
  }
}
