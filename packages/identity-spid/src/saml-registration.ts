// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FederationSamlRegistration } from './contracts.js';
import { fields, text, failure } from './validation.js';

/** Capture only deployment-owned references; certificate parsing belongs to the native SAML backend. */
export function captureSamlRegistration(
  input: unknown,
  signingKeyRef: string,
): FederationSamlRegistration {
  const value = fields(input, ['signingCertificateRef']),
    signingCertificateRef = text(value.signingCertificateRef);
  if (signingCertificateRef === signingKeyRef) throw failure();
  return Object.freeze({ signingCertificateRef });
}
