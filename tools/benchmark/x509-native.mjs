// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { X509Certificate } from 'node:crypto';

/** Direct native utility calls and the same independent TLS/CRL authority used by the adapter. */
export function nativeCertificateOperations(provider, fixture) {
  const certificate = new X509Certificate(fixture.leafDer);
  return {
    parse: () => new X509Certificate(fixture.leafDer),
    daysUntilExpiry: () => Math.floor((certificate.validToDate.getTime() - Date.now()) / 86400000),
    getFingerprints: () => ({
      sha256: certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
      sha512: certificate.fingerprint512.replaceAll(':', '').toLowerCase(),
    }),
    async inspectChain() {
      await provider.verifyChainAndRevocation({
        peerDer: fixture.leafDer,
        policy: {
          trustRootsRef: 'demonstration',
          allowedIdentities: ['localhost'],
          hostname: 'localhost',
          revocation: 'approved-online-checker',
        },
        now: new Date().toISOString(),
      });
      return { status: 'trusted' };
    },
  };
}
