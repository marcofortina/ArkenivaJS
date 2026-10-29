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

interface Input {
  origin: string;
  issuer: string;
  subject: string;
  trustMark: string;
  anchor: FederationTrustAnchor;
  leafConfiguration: string;
  deniedConfiguration: string;
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
    '/utf8',
    '/oversized',
    '/slow',
    '/cancel',
  ];
  const metadata = {
    approvedMetadataEndpoints: paths.map((path) => input.origin + path),
    maxBytes: 4096,
  };
  const policy = { maxConcurrent: 2, timeoutMs: 1000, maxInputBytes: 4096, maxOutputBytes: 4096 };
  const source = new FederationHttp(metadata, policy, 'test');
  try {
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
    for (const path of ['/redirect', '/wrong-type', '/utf8', '/oversized'])
      await assert.rejects(() => source.statement(input.origin + path), {
        code: 'EK_EID_FEDERATION',
      });
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
    } finally {
      await runtime.close();
      await transport.close();
    }
  } finally {
    await source.close();
    await source.close();
  }
}
