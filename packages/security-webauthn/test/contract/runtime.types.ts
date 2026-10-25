// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { MfaSubjectContext } from '@arkenivajs/core';
import type {
  WebAuthnStateStore,
  WebAuthnServiceOptions,
  WebAuthnTrustedSubjectAuthority,
} from '../../dist/contracts.js';

function verifyContracts(
  state: WebAuthnStateStore,
  authority: WebAuthnTrustedSubjectAuthority,
  subject: MfaSubjectContext,
) {
  void state.getOrCreateUserHandle(subject, 'example.test');
  void state.advanceCounter({
    rpId: 'example.test',
    credentialId: 'credential',
    issuer: subject.issuer,
    subject: subject.subject,
    userHandle: 'opaque-handle',
    expectedVersion: 'backend-version',
    previousCounter: 0,
    newCounter: 0,
    backedUp: true,
  });
  // @ts-expect-error A counter-only comparison cannot guard zero-to-zero authentication.
  void state.advanceCounter({
    credentialId: 'credential',
    rpId: 'example.test',
    previousCounter: 0,
    newCounter: 0,
  });
  // @ts-expect-error Revocation must contend on the same backend revision as authentication.
  void state.revokeCredential(subject, 'example.test', 'credential');
  // @ts-expect-error Passwordless identity resolution remains a required authority method.
  const incomplete: WebAuthnTrustedSubjectAuthority = {
    resolveSubject: authority.resolveSubject,
    authorize: authority.authorize,
  };
  const invalid: Pick<WebAuthnServiceOptions, 'userVerification'> = {
    // @ts-expect-error Optional configuration never permits relaxing user verification.
    userVerification: 'preferred',
  };
  void [incomplete, invalid];
}
void verifyContracts;
