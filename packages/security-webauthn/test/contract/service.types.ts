// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import type {
  WebAuthnServiceOptions,
  WebAuthnService,
  MfaSubjectContext,
  MfaManagementAuthorization,
} from '@arkenivajs/security-webauthn';

function publicSurface(
  options: WebAuthnServiceOptions,
  subject: MfaSubjectContext,
  authorization: MfaManagementAuthorization,
) {
  const service: WebAuthnService = createWebAuthnService(options);
  void service.beginRegistration(subject);
  void service.finishRegistration(subject, 'ceremony', {});
  void service.beginAuthentication(subject);
  void service.finishAuthentication(subject, 'ceremony', {});
  void service.beginPasswordless();
  void service.finishPasswordless('ceremony', {});
  void service.listCredentials(subject);
  void service.revokeCredential(subject, 'credential', authorization);
  // @ts-expect-error Trusted runtime authority is mandatory at construction.
  createWebAuthnService({
    rpId: 'example.test',
    rpName: 'Example',
    expectedOrigins: ['https://example.test'],
  });
  // @ts-expect-error Revocation always requires an independent management authorization.
  void service.revokeCredential(subject, 'credential');
  // @ts-expect-error Listing has no request-controlled configuration or time override.
  void service.listCredentials(subject, { environment: 'test' });
}
void publicSurface;
