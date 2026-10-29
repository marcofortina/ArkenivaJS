// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  FederationProfileV1,
  FederationOidcRegistration,
  FederationEncryptionPolicy,
} from '../../dist/index.js';

declare const profile: FederationProfileV1;
declare const registration: FederationOidcRegistration;
const configured: FederationProfileV1 = { ...profile, oidcRegistration: registration };
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
void [configured, encrypted, invalid, wrong];
