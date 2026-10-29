// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  FederationProfileV1,
  FederationOidcRegistration,
  FederationEncryptionPolicy,
  FederationSamlRegistration,
} from '../../dist/index.js';

declare const profile: FederationProfileV1;
declare const registration: FederationOidcRegistration;
const configured: FederationProfileV1 = { ...profile, oidcRegistration: registration };
const saml: FederationSamlRegistration = { signingCertificateRef: 'approved-saml-certificate' };
const sources: FederationSamlRegistration = {
  ...saml,
  registrySources: {
    'https://service.example.test': {
      metadataEndpoint: 'https://registry.example.test/sp',
      statusEndpoint: 'https://registry.example.test/sp?output=json',
    },
  },
};
const invalidSource: FederationSamlRegistration = {
  ...saml,
  registrySources: {
    // @ts-expect-error Both metadata and current-status locations must be explicit typed configuration.
    'https://service.example.test': { metadataEndpoint: 'https://registry.example.test/sp' },
  },
};
const samlProfile: FederationProfileV1 = { ...profile, protocol: 'saml2', samlRegistration: saml };
const invalidCertificate: FederationSamlRegistration = {
  // @ts-expect-error Certificates are explicit external references, not inline configuration objects.
  signingCertificateRef: { pem: 'untrusted-inline-material' },
};
const encrypted: FederationEncryptionPolicy = {
  algorithm: 'RSA-OAEP-256',
  encryption: 'A256CBC-HS512',
};
const invalid: FederationEncryptionPolicy = {
  // @ts-expect-error Legacy RSA key transport is forbidden in the Italian profile.
  algorithm: 'RSA_1_5',
  encryption: 'A128CBC-HS256',
};
const wrong: FederationOidcRegistration = {
  ...registration,
  // @ts-expect-error Requested claim catalogs contain names, not arbitrary application objects.
  requestedClaims: [123],
};
const network: FederationOidcRegistration = {
  ...registration,
  approvedProtocolEndpoints: ['https://idp.example.test/token'],
};
const invalidNetwork: FederationOidcRegistration = {
  ...registration,
  // @ts-expect-error Protocol destination catalogs contain explicit HTTPS URL strings.
  approvedProtocolEndpoints: [123],
};
void [
  configured,
  encrypted,
  invalid,
  wrong,
  network,
  invalidNetwork,
  samlProfile,
  invalidCertificate,
  sources,
  invalidSource,
];
