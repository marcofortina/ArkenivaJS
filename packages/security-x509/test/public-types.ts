// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { x509Plugin, X509_CAPABILITY } from '@arkenivajs/security-x509';
import type {
  CertificateFingerprints,
  CertificateValidation,
  OperationOptions,
  X509Info,
  X509PluginSettings,
  X509Service,
} from '@arkenivajs/security-x509';
import type { Application, Plugin } from '@arkenivajs/core';

/** Compile-only positive and negative calls; never execute invalid runtime inputs. */
export function publicTypes(
  app: Application,
  settings: X509PluginSettings,
  input: Uint8Array,
  options: OperationOptions,
) {
  const plugin: Plugin = x509Plugin(settings),
    x509 = app.resolve<X509Service>(X509_CAPABILITY);
  const certificate: X509Info = x509.parse(input),
    pem: X509Info = x509.parse('certificate');
  const validation: Promise<CertificateValidation> = x509.inspectChain(
    [input],
    { trustRoots: [input], expectedHostname: 'localhost', requireRevocationCheck: true },
    options,
  );
  const fingerprints: CertificateFingerprints = x509.getFingerprints(certificate),
    days: number = x509.daysUntilExpiry(certificate);
  // @ts-expect-error Explicit revocation policy is mandatory.
  x509.inspectChain([input], { trustRoots: [input] });
  // @ts-expect-error Chain bytes cannot silently accept arbitrary strings.
  x509.inspectChain(['certificate'], { trustRoots: [input], requireRevocationCheck: true });
  // @ts-expect-error A root catalogue cannot replace the required trusted provider.
  x509Plugin({ trustRoots: settings.trustRoots, policy: settings.policy });
  // @ts-expect-error Metadata is immutable and is not an authentication claim.
  certificate.fingerprintSha256 = 'forged';
  return { plugin, certificate, pem, validation, fingerprints, days };
}
