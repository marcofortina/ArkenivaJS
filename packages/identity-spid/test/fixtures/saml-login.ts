// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { SecurityStoreSettings } from '@arkenivajs/security-apikey';
import { capture } from '../../dist/settings.js';
import { FederationSamlLogin } from '../../dist/saml-login.js';
import { FederationTransactions } from '../../dist/transactions.js';
import { transactionFixture } from './transactions.js';
import { registry, root, foreign } from './saml-metadata.js';

export async function samlLoginFixture(external?: SecurityStoreSettings) {
  const federation = await transactionFixture(external),
    document = await registry(),
    material = new Set<Buffer>(),
    paths: string[] = [],
    references: string[] = [];
  const state = {
    revokedRp: false,
    revokedIdp: false,
    key: 'first' as 'first' | 'second',
    registeredBoth: false,
    rotateAfterBootstrap: false,
    unavailable: false,
    certificateReads: 0,
  };
  const input = { ...federation.input, issuer: document.issuer },
    settings = capture(
      {
        ...federation.settings,
        profiles: [document.profile],
        policy: {
          ...federation.settings.policy,
          timeoutMs: 10000,
          maxInputBytes: 65536,
          maxOutputBytes: 65536,
        },
        secretProvider: {
          ...{ usage: 'test-only' as const },
          async get(reference, options) {
            references.push(reference);
            if (state.unavailable)
              throw new Error('The native fixture secret provider is unavailable');
            const selected =
              state.rotateAfterBootstrap && state.certificateReads > 0 ? 'second' : state.key;
            let bytes: Buffer;
            if (reference === document.profile.signingKeyRef)
              bytes = Buffer.from(
                (selected === 'first' ? foreign : root).privateKey.export({
                  format: 'pem',
                  type: 'pkcs8',
                }),
              );
            else if (reference === document.profile.samlRegistration!.signingCertificateRef) {
              state.certificateReads++;
              bytes = Buffer.from(selected === 'first' ? document.first.pem : document.second.pem);
            } else return federation.settings.secretProvider.get(reference, options);
            material.add(bytes);
            return { bytes, keyVersion: 'fixture' };
          },
        },
      },
      'test',
    ),
    transport = {
      async samlMetadata(endpoint: string) {
        paths.push(endpoint);
        const role = endpoint.endsWith('/sp') ? 'sp' : 'idp';
        return role === 'sp' && state.registeredBoth
          ? document.xml(role, {
              descriptorContent:
                document.descriptor() +
                document.descriptor(document.second.encoded) +
                document.consumer,
            })
          : document.xml(role);
      },
      async samlRegistryStatus(endpoint: string) {
        paths.push(endpoint);
        const role = endpoint.endsWith('/sp-status') ? 'sp' : 'idp';
        return document.status(role, {
          ...((role === 'sp' ? state.revokedRp : state.revokedIdp) ? { _disabled: 'Y' } : {}),
          ...(role === 'sp' && state.registeredBoth
            ? { signing_certificate_x509: [document.first.encoded, document.second.encoded] }
            : {}),
        });
      },
    };
  return {
    ...federation,
    settings,
    document,
    state,
    persistence: federation.state,
    input,
    transport,
    paths,
    references,
    login: new FederationSamlLogin(
      settings,
      document.profile.profileId,
      transport,
      federation.crypto,
    ),
    transactions: new FederationTransactions(
      settings,
      document.profile.profileId,
      federation.crypto,
    ),
    async close() {
      await federation.close();
      for (const bytes of material) bytes.fill(0);
    },
  };
}
